//! `ShredRecoveryContext::recover`:
//! 1 shreds rebuilt from an honest set are byte-identical to the erased ones;
//! 2 with a malformed data shred re-encoded into the coding shreds and withheld, every rebuilt
//!   shred passes the filter and DATA_COMPLETE sits on the set's last data index;
//! 3 with corrupted parity re-signed into the set, every rebuilt data shred verifies.

#![no_main]

use {
    agave_shred_fuzz::{
        FLAGS_OFFSET, Gates, LEADER_SEED, PARENT_OFFSET_OFFSET, POSITION_OFFSET, SHRED_VERSION,
        bank_for, build_fec_set, chained_root_range, recovery_context,
    },
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_hash::Hash,
    solana_keypair::{Keypair, Signer},
    solana_ledger::shred::{
        DATA_SHREDS_PER_FEC_BLOCK, Payload, Shred, ShredFlags,
        filter::ShredFilterContext,
        layout,
        merkle::{finish_erasure_batch_for_tests, reseal_erasure_batch_for_tests},
    },
    solana_runtime::bank::Bank,
    std::sync::Arc,
};

#[derive(Arbitrary, Debug)]
struct Input {
    // Fixed-size fields before the Vec, so a short input still sets every knob.
    gates: Gates,
    slot_offset: u16,
    drop_mask: u64,
    victim: u8,
    victim_flags: VictimFlags,
    /// 0 leaves the victim's parent offset unchanged.
    parent_offset: u16,
    coding_victim: u8,
    coding_off: u16,
    coding_xor: u8,
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum VictimFlags {
    Clear,
    DataComplete,
    LastInSlot,
}

impl VictimFlags {
    fn bits(self) -> u8 {
        match self {
            VictimFlags::Clear => 0,
            VictimFlags::DataComplete => ShredFlags::DATA_COMPLETE_SHRED.bits(),
            VictimFlags::LastInSlot => ShredFlags::LAST_SHRED_IN_SLOT.bits(),
        }
    }
}

fuzz_target!(|input: Input| {
    let bank = bank_for(input.gates);
    let shred_slot = bank.slot() + 1 + u64::from(input.slot_offset % 64);
    let leader = Keypair::new_from_array(LEADER_SEED);
    let Some(base) = build_fec_set(&input.data, shred_slot, shred_slot - 1, &leader) else {
        return;
    };
    check_fidelity(&bank, &base, input.drop_mask);
    check_filter_parity(&bank, &base, &input, &leader);
    check_integrity(&bank, base, &input, &leader);
});

fn recover_without(
    bank: &Arc<Bank>,
    shreds: &[Shred],
    skip: Option<usize>,
    drop_mask: u64,
) -> Option<(Vec<Payload>, Vec<Shred>)> {
    let kept: Vec<Shred> = shreds
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != skip && drop_mask & (1u64 << (i % 64)) == 0)
        .map(|(_, s)| s.clone())
        .collect();
    if kept.is_empty() || kept.len() == shreds.len() {
        return None;
    }
    let mut recovered = Vec::new();
    let mut recovered_data = Vec::new();
    recovery_context(bank)
        .recover(kept, &mut recovered, &mut recovered_data)
        .ok()?;
    Some((recovered, recovered_data))
}

/// 1
fn check_fidelity(bank: &Arc<Bank>, base: &[Shred], drop_mask: u64) {
    let Some((recovered, _)) = recover_without(bank, base, None, drop_mask) else {
        return;
    };
    for payload in &recovered {
        let id = layout::get_shred_id(payload.as_ref());
        let original = base.iter().find(|o| Some(o.id()) == id);
        assert!(
            original.is_some_and(|o| o.payload().as_ref() == payload.as_ref()),
            "recovery reconstructed {id:?}, which is not byte-identical to an erased shred",
        );
    }
}

/// 2
fn check_filter_parity(bank: &Arc<Bank>, base: &[Shred], input: &Input, leader: &Keypair) {
    let Some((shreds, victim)) = malformed_set(base, input, leader) else {
        return;
    };
    let Some((recovered, _)) = recover_without(bank, &shreds, Some(victim), input.drop_mask) else {
        return;
    };
    let mut network = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    for payload in &recovered {
        assert!(
            !network.should_discard_shred(payload.as_ref()),
            "recover emitted a shred the network filter rejects"
        );
        assert_canonical_data_complete(payload.as_ref());
    }
}

/// None if the victim no longer sanitizes, since `finish` debug-asserts that.
fn malformed_set(base: &[Shred], input: &Input, leader: &Keypair) -> Option<(Vec<Shred>, usize)> {
    let mut shreds = base.to_vec();
    let victim = usize::from(input.victim) % DATA_SHREDS_PER_FEC_BLOCK;
    if !shreds.get(victim)?.is_data() {
        return None;
    }
    let mut bytes = shreds[victim].payload().to_vec();
    *bytes.get_mut(FLAGS_OFFSET)? |= input.victim_flags.bits();
    if input.parent_offset != 0 {
        bytes
            .get_mut(PARENT_OFFSET_OFFSET..PARENT_OFFSET_OFFSET + 2)?
            .copy_from_slice(&input.parent_offset.to_le_bytes());
    }
    shreds[victim] = Shred::new_from_serialized_shred(bytes).ok()?;
    shreds[victim].sanitize().ok()?;
    finish_erasure_batch_for_tests(leader, &mut shreds, Hash::default()).ok()?;
    Some((shreds, victim))
}

fn assert_canonical_data_complete(payload: &[u8]) {
    let Ok(flags) = layout::get_flags(payload) else {
        return;
    };
    if !flags.contains(ShredFlags::DATA_COMPLETE_SHRED) {
        return;
    }
    let (Some(index), Some(fec)) = (
        layout::get_index(payload),
        layout::get_fec_set_index(payload),
    ) else {
        return;
    };
    assert_eq!(
        fec.checked_add(DATA_SHREDS_PER_FEC_BLOCK as u32 - 1),
        Some(index),
        "recover emitted DATA_COMPLETE off the set's last data index (fec_set {fec})",
    );
}

/// 3
fn check_integrity(bank: &Arc<Bank>, mut shreds: Vec<Shred>, input: &Input, leader: &Keypair) {
    let coding =
        DATA_SHREDS_PER_FEC_BLOCK + usize::from(input.coding_victim) % DATA_SHREDS_PER_FEC_BLOCK;
    let Some(target) = shreds.get(coding).filter(|s| s.is_code()) else {
        return;
    };
    let mut bytes = target.payload().to_vec();
    let Some(root) = chained_root_range(&bytes) else {
        return;
    };
    let shard = (POSITION_OFFSET + 2)..root.start;
    bytes[shard.start + usize::from(input.coding_off) % shard.len()] ^= input.coding_xor;
    let Ok(corrupted) = Shred::new_from_serialized_shred(bytes) else {
        return;
    };
    shreds[coding] = corrupted;
    if reseal_erasure_batch_for_tests(leader, &mut shreds).is_err() {
        return;
    }
    let victim = usize::from(input.victim) % DATA_SHREDS_PER_FEC_BLOCK;
    let Some((_, recovered_data)) = recover_without(bank, &shreds, Some(victim), 0) else {
        return;
    };
    let pubkey = leader.pubkey();
    for shred in &recovered_data {
        assert!(
            shred.verify(&pubkey),
            "recover emitted a data shred that fails signature verification"
        );
    }
}
