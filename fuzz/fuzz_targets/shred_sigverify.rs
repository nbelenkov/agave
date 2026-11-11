//! `verify_shred_cpu`:
//! 1 never panics on raw bytes (it runs before any other check);
//! 2 a genuine leader-signed shred verifies;
//! 3 a tampered signature or signed Merkle root does not;
//! 4 the raw accessors it trusts (`get_slot`, `get_merkle_root`) match the parsed shred;
//!   otherwise a shred is verified as one identity and processed as another.

#![no_main]

use {
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_hash::Hash,
    solana_keypair::{Keypair, Signer},
    solana_ledger::{
        shred::{ProcessShredsStats, Shred, Shredder, layout},
        sigverify_shreds::{LruCache, SlotPubkeys, verify_shred_cpu},
    },
    solana_packet::PACKET_DATA_SIZE,
    solana_perf::packet::BytesPacket,
    std::sync::RwLock,
};

const LEADER_SEED: [u8; 32] = [7u8; 32];
const SHRED_VERSION: u16 = 0;

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    slot: u64,
    parent_off: u16,
    raw: Vec<u8>,
    tamper: Tamper,
}

#[derive(Arbitrary, Debug)]
enum Tamper {
    None,
    Signature { off: u8, xor: u8 },
    SignedRegion { off: u16, xor: u8 },
}

fuzz_target!(|input: Input| {
    verify_raw(&input.raw);
    check_accessor_consistency(&input.raw);

    let leader = Keypair::new_from_array(LEADER_SEED);
    let Some(shred) = build_first_shred(&input, &leader) else {
        return;
    };
    let slot = shred.slot();
    let mut bytes = shred.payload().to_vec();
    check_accessor_consistency(&bytes);

    let leader_slots: SlotPubkeys = [(slot, leader.pubkey())].into_iter().collect();
    let cache = RwLock::new(LruCache::new(128));

    match &input.tamper {
        Tamper::None => {
            assert!(
                verify_bytes(&bytes, &leader_slots, &cache),
                "verify_shred_cpu rejected a genuine leader-signed shred"
            );
        }
        Tamper::Signature { off, xor } => {
            if *xor == 0 {
                return;
            }
            bytes[usize::from(*off) % 64] ^= *xor;
            assert!(
                !verify_bytes(&bytes, &leader_slots, &cache),
                "verify_shred_cpu accepted a shred with a tampered signature"
            );
        }
        Tamper::SignedRegion { off, xor } => {
            let root_before = layout::get_merkle_root(&bytes);
            let start = 64; // past the signature
            if bytes.len() > start {
                let pos = start + usize::from(*off) % (bytes.len() - start);
                bytes[pos] ^= *xor;
            }
            // A byte outside the signed tree leaves the root, and acceptance, unchanged.
            if root_before.is_some() && layout::get_merkle_root(&bytes) != root_before {
                assert!(
                    !verify_bytes(&bytes, &leader_slots, &cache),
                    "verify_shred_cpu accepted a shred whose signed Merkle root was tampered"
                );
            }
        }
    }
});

/// Maps whatever slot the bytes claim to the leader, so the full verify path runs.
fn verify_raw(raw: &[u8]) {
    if raw.is_empty() {
        return;
    }
    let n = raw.len().min(PACKET_DATA_SIZE);
    let packet = BytesPacket::from_bytes(None, raw[..n].to_vec());
    let mut leader_slots = SlotPubkeys::default();
    if let Some(slot) = layout::get_slot(&raw[..n]) {
        leader_slots.insert(slot, Keypair::new_from_array(LEADER_SEED).pubkey());
    }
    let cache = RwLock::new(LruCache::new(16));
    let _ = verify_shred_cpu(&packet, &leader_slots, &cache);
}

fn verify_bytes(bytes: &[u8], leader_slots: &SlotPubkeys, cache: &RwLock<LruCache>) -> bool {
    if bytes.len() > PACKET_DATA_SIZE {
        return false;
    }
    let packet = BytesPacket::from_bytes(None, bytes.to_vec());
    verify_shred_cpu(&packet, leader_slots, cache)
}

fn check_accessor_consistency(bytes: &[u8]) {
    let Ok(shred) = Shred::new_from_serialized_shred(bytes.to_vec()) else {
        return;
    };
    if let Some(raw_slot) = layout::get_slot(bytes) {
        assert_eq!(
            raw_slot,
            shred.slot(),
            "get_slot (sigverify's) diverges from the parsed slot"
        );
    }
    if let (Some(raw_root), Ok(parsed_root)) = (layout::get_merkle_root(bytes), shred.merkle_root())
    {
        assert_eq!(
            raw_root, parsed_root,
            "get_merkle_root (sigverify's signed data) diverges from the parsed merkle_root"
        );
    }
}

fn build_first_shred(input: &Input, leader: &Keypair) -> Option<Shred> {
    let parent = if input.slot == 0 {
        0
    } else {
        input
            .slot
            .saturating_sub(u64::from(input.parent_off).max(1))
    };
    let shredder = Shredder::new(input.slot, parent, 0, SHRED_VERSION).ok()?;
    let mut stats = ProcessShredsStats::default();
    let cap = 30_000.min(input.data.len());
    shredder
        .make_shreds_from_data_slice(
            leader,
            &input.data[..cap],
            false,
            Hash::default(),
            0,
            0,
            &mut stats,
        )
        .ok()?
        .into_iter()
        .next()
}
