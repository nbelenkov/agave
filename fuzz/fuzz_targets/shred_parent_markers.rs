//! Alpenglow parent markers (BlockHeader, UpdateParent) at blockstore insert, which is live
//! and ungated. Each block is delivered twice at the same leader-window position; the second
//! delivery withholds data shreds so markers can arrive recovered.
//!
//! P1 dead iff the harness's restatement of the marker rules (`marker_violation`) is broken.
//! P2 a live slot records the effective parent: the UpdateParent's (its FEC set as replay
//!    start), else the header's, else the shred header's.
//! P3 both deliveries reach the same outcome.
//! P4 a complete slot's double Merkle root equals a recomputation over its FEC-set roots and
//!    the effective parent.
//! P5 the markers replay decodes match the parent blockstore recorded.
//! P6 a complete live slot forwards exactly the finalization certificates of the footer in its
//!    second-to-last FEC set (where a leader puts it), tagged with the slot; a dead slot forwards
//!    those or nothing, an incomplete one nothing.

#![no_main]

use {
    agave_shred_fuzz::{
        Gates, LEADER_SEED, SHRED_VERSION, bank_for, recovery_context, take_forwarded_certificates,
        with_blockstore,
    },
    agave_votor_messages::{
        certificate::CertificateType,
        consensus_message::{Block as CertifiedBlock, BlockId},
        unverified_vote_message::UnverifiedCertificate,
    },
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_bls_signatures::{
        Keypair as BlsKeypair, SignatureCompressed, signature::points::SignatureAffine,
    },
    solana_entry::{
        block_component::{
            BlockComponent, BlockFinalizationCert, BlockFooterV1, ParsedBlockComponent,
            UpdateParentV1, VersionedBlockHeader, VersionedBlockMarker, VotesAggregate,
        },
        entry::Entry,
    },
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_meta::BlockLocation,
        blockstore_metrics::BlockstoreInsertionMetrics,
        shred::{
            ProcessShredsStats, Shred, Shredder, filter::ShredFilterContext,
            merkle_tree::MerkleTree,
        },
    },
    solana_runtime::{bank::Bank, leader_schedule_utils::leader_slot_index},
    solana_sha256_hasher::hashv,
    std::sync::{Arc, OnceLock},
};

/// The two delivery slots sit one leader window (4 slots) apart.
const SLOTS: u64 = 16;
const MAX_UPDATES: usize = 2;

#[derive(Arbitrary, Debug)]
struct Input {
    // Fixed-size fields before the Vec, so a short input still sets every knob.
    gates: Gates,
    footer: Option<Footer>,
    window_pos: u8,
    shred_parent_back: u8,
    header: Option<Marker>,
    entries_before: u8,
    schedules: [Schedule; 2],
    withhold: u64,
    updates: Vec<Marker>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct Footer {
    placement: Placement,
    cert: Option<Cert>,
    bank_hash: u8,
    user_agent_len: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Placement {
    /// Second-to-last, before the final entry batch, as a leader places it.
    Honest,
    Last,
    /// Followed by two entry batches.
    Early,
    /// Two footers, the second one placed honestly.
    Twice,
    BeforeUpdateParent,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct Cert {
    block: Marker,
    /// With a notarization aggregate (Notarize and Finalize), else FinalizeFast.
    notar: bool,
    final_sig: Sig,
    notar_sig: Sig,
    bitmap_len: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Sig {
    Valid(u8),
    /// Rarely a point on the curve, so the footer usually forwards nothing.
    Junk(u8),
}

/// `id` is a one-byte seed, so markers naming the same block are common.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct Marker {
    back: u8,
    id: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct Schedule {
    reversed: bool,
    rotate: u8,
    /// Shreds per insert call; 0 means all at once.
    batch: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parent {
    slot: u64,
    id: Hash,
}

struct Block {
    slot: u64,
    shred_parent: u64,
    header: Option<Parent>,
    /// With the first data index of each one's FEC set.
    updates: Vec<(Parent, u32)>,
    /// The certificate of a footer in the second-to-last component, if any.
    forwardable: Option<BlockFinalizationCert>,
    shreds: Vec<Shred>,
}

/// Relative to the slot, so the two deliveries compare.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Dead,
    Live {
        parent_back: Option<u64>,
        parent_block_id: Hash,
        replay_fec_set_index: u32,
    },
}

fuzz_target!(|input: Input| {
    let bank = bank_for(input.gates);
    with_blockstore(&bank, SLOTS, |blockstore, base| {
        run(&bank, blockstore, base, &input)
    });
});

fn run(bank: &Arc<Bank>, blockstore: &Blockstore, base: u64, input: &Input) {
    let leader = Keypair::new_from_array(LEADER_SEED);
    let start = base + 4;
    let pos = u64::from(input.window_pos % 4);
    let slot_a = start + (4 + pos - start % 4) % 4;
    let mut outcomes = Vec::with_capacity(2);
    take_forwarded_certificates();
    for (k, schedule) in input.schedules.iter().enumerate() {
        let slot = slot_a + 4 * k as u64;
        let Some(block) = build_block(slot, input, &leader) else {
            return;
        };
        let withhold = if k == 0 { 0 } else { input.withhold };
        deliver(bank, blockstore, &block.shreds, *schedule, withhold);
        let outcome = outcome(blockstore, slot);
        check_reference(blockstore, &block, &outcome);
        check_complete_block(blockstore, &block);
        check_forwarded(blockstore, &block);
        outcomes.push(outcome);
    }
    assert_eq!(
        outcomes[0], outcomes[1],
        "P3: the parent-marker outcome depends on arrival order or recovery ({:?})",
        input.schedules,
    );
}

fn build_block(slot: u64, input: &Input, leader: &Keypair) -> Option<Block> {
    let back = |marker: &Marker| u64::from(marker.back % 16);
    let resolve = |marker: &Marker| -> Option<Parent> {
        Some(Parent {
            slot: slot.checked_sub(1 + back(marker))?,
            id: Hash::new_from_array([marker.id.max(1); 32]),
        })
    };
    let shred_parent = slot - 1 - u64::from(input.shred_parent_back % 4);
    let header = match &input.header {
        Some(marker) => Some(resolve(marker)?),
        None => None,
    };
    let updates: Vec<Parent> = input
        .updates
        .iter()
        .take(MAX_UPDATES)
        .map(resolve)
        .collect::<Option<_>>()?;
    let mut components = Vec::new();
    if let Some(h) = header {
        components.push(BlockComponent::new_block_header(
            h.slot,
            BlockId::from(h.id),
        ));
    }
    // An UpdateParent at index 0 is never parsed as one.
    let entries_before = usize::from(input.entries_before % 3) + usize::from(header.is_none());
    for i in 0..entries_before {
        components.push(entry_batch(i));
    }
    let mut update_at = Vec::with_capacity(updates.len());
    if let Some(footer) = input
        .footer
        .filter(|f| matches!(f.placement, Placement::BeforeUpdateParent))
    {
        components.push(block_footer(slot, &footer));
    }
    for (i, u) in updates.iter().enumerate() {
        update_at.push(components.len());
        components.push(update_parent(*u));
        components.push(entry_batch(entries_before + i));
    }
    if let Some(footer) = &input.footer {
        push_footer(&mut components, slot, footer);
    }
    let forwardable = components
        .len()
        .checked_sub(2)
        .and_then(|i| footer_cert(&components[i]));
    let (shreds, starts) = shred_components(slot, shred_parent, &components, leader)?;
    let updates = updates
        .iter()
        .zip(update_at)
        .map(|(u, at)| (*u, starts[at]))
        .collect();
    Some(Block {
        slot,
        shred_parent,
        header,
        updates,
        forwardable,
        shreds,
    })
}

fn entry_batch(seed: usize) -> BlockComponent {
    let entry = Entry {
        num_hashes: seed as u64 + 1,
        hash: Hash::new_from_array([seed as u8; 32]),
        transactions: vec![],
    };
    BlockComponent::EntryBatch(vec![entry])
}

fn update_parent(parent: Parent) -> BlockComponent {
    let marker = UpdateParentV1 {
        new_parent_slot: parent.slot,
        new_parent_block_id: BlockId::from(parent.id),
    };
    BlockComponent::BlockMarker(VersionedBlockMarker::from_update_parent(marker))
}

/// Appends the footer, and the entry batches its placement calls for, after the last component.
fn push_footer(components: &mut Vec<BlockComponent>, slot: u64, footer: &Footer) {
    const FINAL: usize = 200;
    match footer.placement {
        Placement::Honest | Placement::BeforeUpdateParent => {
            if matches!(footer.placement, Placement::Honest) {
                components.push(block_footer(slot, footer));
            }
            components.push(entry_batch(FINAL));
        }
        Placement::Last => components.push(block_footer(slot, footer)),
        Placement::Early => {
            components.push(block_footer(slot, footer));
            components.push(entry_batch(FINAL + 1));
            components.push(entry_batch(FINAL));
        }
        Placement::Twice => {
            components.push(block_footer(slot, footer));
            components.push(block_footer(slot, footer));
            components.push(entry_batch(FINAL));
        }
    }
}

fn block_footer(slot: u64, footer: &Footer) -> BlockComponent {
    let block_final_cert = footer.cert.and_then(|cert| finalization_cert(slot, &cert));
    let footer = BlockFooterV1 {
        bank_hash: Hash::new_from_array([footer.bank_hash; 32]),
        block_producer_time_nanos: u64::from(footer.bank_hash),
        block_user_agent: vec![b'a'; usize::from(footer.user_agent_len)],
        block_final_cert,
        skip_reward_cert: None,
        notar_reward_cert: None,
    };
    BlockComponent::BlockMarker(VersionedBlockMarker::from_block_footer(footer))
}

fn finalization_cert(slot: u64, cert: &Cert) -> Option<BlockFinalizationCert> {
    // Distinct bitmaps, so forwarding one aggregate's bitmap with the other's signature shows.
    let len = usize::from(cert.bitmap_len % 32);
    Some(BlockFinalizationCert {
        slot: slot.checked_sub(1 + u64::from(cert.block.back % 16))?,
        block_id: BlockId::from(Hash::new_from_array([cert.block.id; 32])),
        final_aggregate: VotesAggregate::new(compressed(cert.final_sig), vec![0xa5; len]),
        notar_aggregate: cert
            .notar
            .then(|| VotesAggregate::new(compressed(cert.notar_sig), vec![0x5a; len + 1])),
    })
}

fn compressed(sig: Sig) -> SignatureCompressed {
    static VALID: OnceLock<Vec<SignatureCompressed>> = OnceLock::new();
    match sig {
        Sig::Valid(i) => {
            let valid = VALID.get_or_init(|| {
                (0..4u8)
                    .map(|seed| {
                        let keypair = BlsKeypair::derive(&[seed + 1; 32]).expect("valid ikm");
                        SignatureCompressed::from(&SignatureAffine::from(keypair.sign(b"footer")))
                    })
                    .collect()
            });
            valid[usize::from(i) % valid.len()]
        }
        Sig::Junk(byte) => SignatureCompressed([byte; 96]),
    }
}

fn footer_cert(component: &BlockComponent) -> Option<BlockFinalizationCert> {
    let BlockComponent::BlockMarker(VersionedBlockMarker::V1(marker)) = component else {
        return None;
    };
    let solana_entry::block_component::VersionedBlockFooter::V1(footer) =
        marker.as_block_footer()?;
    footer.block_final_cert.clone()
}

/// P6
fn check_forwarded(blockstore: &Blockstore, block: &Block) {
    let slot = block.slot;
    let forwarded = take_forwarded_certificates();
    let full = blockstore
        .meta(slot)
        .ok()
        .flatten()
        .is_some_and(|meta| meta.is_full());
    let expected = match (&block.forwardable, full) {
        (Some(cert), true) => expected_certificates(cert),
        _ => vec![],
    };
    let mut got: Vec<CertKey> = forwarded
        .iter()
        .map(|(carrier, cert)| {
            assert_eq!(
                *carrier, slot,
                "P6: a certificate was forwarded with carrier slot {carrier}, delivering {slot}"
            );
            cert_key(cert)
        })
        .collect();
    got.sort();
    if blockstore.is_dead(slot) && got.is_empty() {
        return;
    }
    assert_eq!(
        got, expected,
        "P6: slot {slot} (full {full}) forwarded the wrong footer certificates"
    );
}

type CertKey = (CertificateType, Vec<u8>, Vec<u8>, u16);

fn cert_key(cert: &UnverifiedCertificate) -> CertKey {
    (
        cert.cert_type,
        cert.signature.0.to_vec(),
        cert.bitmap.clone(),
        cert.shred_version,
    )
}

/// What a footer certificate stands for: Notarize and Finalize with a notarization aggregate,
/// FinalizeFast without; nothing if a signature is not a curve point.
fn expected_certificates(cert: &BlockFinalizationCert) -> Vec<CertKey> {
    let block = CertifiedBlock {
        slot: cert.slot,
        block_id: cert.block_id,
    };
    let key = |cert_type, aggregate: &VotesAggregate| -> Option<CertKey> {
        let signature = aggregate.uncompress_signature().ok()?;
        Some((
            cert_type,
            signature.0.to_vec(),
            aggregate.bitmap().to_vec(),
            SHRED_VERSION,
        ))
    };
    let keys = match &cert.notar_aggregate {
        Some(notar) => vec![
            key(CertificateType::Notarize(block), notar),
            key(CertificateType::Finalize(cert.slot), &cert.final_aggregate),
        ],
        None => vec![key(
            CertificateType::FinalizeFast(block),
            &cert.final_aggregate,
        )],
    };
    let mut keys: Vec<CertKey> = keys.into_iter().collect::<Option<_>>().unwrap_or_default();
    keys.sort();
    keys
}

/// Each component in its own FEC sets, chained as a leader does, with each one's first data
/// index.
fn shred_components(
    slot: u64,
    shred_parent: u64,
    components: &[BlockComponent],
    leader: &Keypair,
) -> Option<(Vec<Shred>, Vec<u32>)> {
    let shredder = Shredder::new(slot, shred_parent, 0, SHRED_VERSION).ok()?;
    let mut stats = ProcessShredsStats::default();
    let mut next = 0u32;
    let mut chained = Hash::default();
    let mut shreds = Vec::new();
    let mut starts = Vec::with_capacity(components.len());
    for (i, component) in components.iter().enumerate() {
        let is_last = i + 1 == components.len();
        let batch = shredder.make_merkle_shreds_from_component(
            leader, component, is_last, chained, next, next, &mut stats,
        );
        let last_data = batch
            .iter()
            .filter(|s| s.is_data())
            .max_by_key(|s| s.index())?;
        chained = last_data.merkle_root().ok()?;
        starts.push(next);
        next = last_data.index() + 1;
        shreds.extend(batch);
    }
    Some((shreds, starts))
}

fn deliver(
    bank: &Arc<Bank>,
    blockstore: &Blockstore,
    shreds: &[Shred],
    schedule: Schedule,
    withhold: u64,
) {
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    let mut kept: Vec<Shred> = shreds
        .iter()
        .filter(|s| !(s.is_data() && withhold & (1 << (s.index() % 64)) != 0))
        .filter(|s| s.sanitize().is_ok() && !filter.should_discard_shred(s.payload()))
        .cloned()
        .collect();
    if schedule.reversed {
        kept.reverse();
    }
    if !kept.is_empty() {
        let by = usize::from(schedule.rotate) % kept.len();
        kept.rotate_left(by);
    }
    let batch = match usize::from(schedule.batch) {
        0 => kept.len().max(1),
        n => n,
    };
    for chunk in kept.chunks(batch) {
        let mut recovery_ctx = recovery_context(bank);
        let mut metrics = BlockstoreInsertionMetrics::default();
        let chunk: Vec<(Shred, bool)> = chunk.iter().cloned().map(|s| (s, false)).collect();
        let _ = blockstore.insert_shreds_handle_duplicate(
            chunk,
            /*is_trusted:*/ false,
            &mut recovery_ctx,
            &|_| {},
            &mut metrics,
        );
    }
}

fn outcome(blockstore: &Blockstore, slot: u64) -> Outcome {
    if blockstore.is_dead(slot) {
        return Outcome::Dead;
    }
    let meta = blockstore.meta(slot).ok().flatten();
    Outcome::Live {
        parent_back: meta.as_ref().and_then(|m| m.parent_slot).map(|p| slot - p),
        parent_block_id: meta
            .as_ref()
            .map_or_else(Hash::default, |m| m.parent_block_id),
        replay_fec_set_index: meta.as_ref().map_or(0, |m| m.replay_fec_set_index),
    }
}

/// P1 and P2.
fn check_reference(blockstore: &Blockstore, block: &Block, outcome: &Outcome) {
    let slot = block.slot;
    let violation = marker_violation(blockstore.max_root(), block);
    match (violation, outcome) {
        (Some(rule), Outcome::Live { .. }) => {
            panic!("P1: inconsistent parent markers ({rule}) left slot {slot} alive: {outcome:?}")
        }
        (None, Outcome::Dead) => {
            panic!(
                "P1: consistent parent markers killed slot {slot} (header {:?}, updates {:?})",
                block.header, block.updates
            )
        }
        (Some(_), Outcome::Dead) => {}
        (None, Outcome::Live { .. }) => {
            let (parent, start) = effective_parent(block);
            let expected = (slot - parent.slot, parent.id, start);
            let Outcome::Live {
                parent_back: Some(back),
                parent_block_id,
                replay_fec_set_index,
            } = outcome
            else {
                return; // nothing inserted
            };
            let recorded = (*back, *parent_block_id, *replay_fec_set_index);
            assert_eq!(
                recorded, expected,
                "P2: slot {slot} records the wrong effective parent"
            );
        }
    }
}

fn effective_parent(block: &Block) -> (Parent, u32) {
    match (block.updates.first(), block.header) {
        (Some((u, start)), _) => (*u, *start),
        (None, Some(h)) => (h, 0),
        (None, None) => (
            Parent {
                slot: block.shred_parent,
                id: Hash::default(),
            },
            0,
        ),
    }
}

/// P4 and P5.
fn check_complete_block(blockstore: &Blockstore, block: &Block) {
    let slot = block.slot;
    let Ok(Some(meta)) = blockstore.meta(slot) else {
        return;
    };
    if !meta.is_full() || blockstore.is_dead(slot) {
        return;
    }
    let (parent, start) = effective_parent(block);
    let stored = blockstore
        .get_double_merkle_root(slot, BlockLocation::Original)
        .ok()
        .flatten();
    assert_eq!(
        stored,
        double_merkle_root(block, parent),
        "P4: slot {slot}'s stored block id differs from the recomputed one"
    );
    let Ok((components, _, _)) =
        blockstore.get_slot_component_views_with_shred_info(slot, 0, false)
    else {
        return;
    };
    let markers = || {
        components.iter().filter_map(|component| match component {
            ParsedBlockComponent::BlockMarker(marker) => Some(marker),
            ParsedBlockComponent::EntryBatch(_) => None,
        })
    };
    let replay_update = markers()
        .find_map(|marker| marker.as_update_parent())
        .map(|u| Parent {
            slot: u.new_parent_slot,
            id: u.new_parent_block_id.to_hash(),
        });
    let replay_header = markers().find_map(header_parent);
    let recorded = (meta.replay_fec_set_index > 0).then_some(parent);
    assert_eq!(
        replay_update, recorded,
        "P5: replay reads UpdateParent {replay_update:?} but slot {slot} recorded {recorded:?} \
         (replay start {start})"
    );
    if replay_update.is_none() {
        assert!(
            replay_header.is_none_or(|h| h == parent),
            "P5: replay reads header {replay_header:?} but slot {slot} recorded parent {parent:?}"
        );
    }
}

fn header_parent(marker: &VersionedBlockMarker) -> Option<Parent> {
    let VersionedBlockMarker::V1(marker) = marker;
    let VersionedBlockHeader::V1(header) = marker.as_block_header()?;
    Some(Parent {
        slot: header.parent_slot,
        id: header.parent_block_id.to_hash(),
    })
}

/// A tree over the FEC-set roots in order, plus a leaf binding the parent and the set count.
fn double_merkle_root(block: &Block, parent: Parent) -> Option<Hash> {
    let mut roots = std::collections::BTreeMap::new();
    for shred in &block.shreds {
        roots
            .entry(shred.fec_set_index())
            .or_insert(shred.merkle_root().ok()?);
    }
    let count = u32::try_from(roots.len()).ok()?;
    let parent_leaf = hashv(&[
        &parent.slot.to_le_bytes(),
        parent.id.as_ref(),
        &count.to_le_bytes(),
    ]);
    let leaves = roots
        .into_values()
        .chain(std::iter::once(parent_leaf))
        .map(Ok);
    let tree = MerkleTree::try_new_with_len(leaves, count as usize + 1).ok()?;
    Some(*tree.root())
}

/// `root` is blockstore's max root, which it validates parents against.
fn marker_violation(root: u64, block: &Block) -> Option<&'static str> {
    let in_range = |p: u64| root <= p && p < block.slot;
    if let Some(h) = block.header {
        if !in_range(h.slot) {
            return Some("header parent out of range");
        }
        if h.slot != block.shred_parent {
            return Some("header parent differs from the shred-header parent");
        }
    }
    if block.updates.is_empty() {
        return None;
    }
    if leader_slot_index(block.slot) != 0 {
        return Some("UpdateParent outside the first slot of a leader window");
    }
    // Blockstore compares the whole ParentInfo, FEC-set index included.
    if block.updates.len() > 1 {
        return Some("more than one UpdateParent");
    }
    for (u, _) in &block.updates {
        if !in_range(u.slot) {
            return Some("UpdateParent parent out of range");
        }
        if u.slot > block.shred_parent {
            return Some("UpdateParent newer than the shred-header parent");
        }
        if let Some(h) = block.header {
            if *u == h {
                return Some("UpdateParent names the header's block");
            }
            if u.slot > h.slot {
                return Some("UpdateParent newer than the header parent");
            }
        }
    }
    None
}
