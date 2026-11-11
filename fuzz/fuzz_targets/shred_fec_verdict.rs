//! SIMD-0504 per-FEC-set ("Family 2") verdicts through the blockstore, read from the
//! `num_fec_set_checks_*` counters and `is_dead` (`check_fec_set` is `pub(crate)`). The checks
//! run once, in the insert batch that brings a set to 32 shreds.
//!
//! V1 an honest set never fails the checks or kills its slot.
//! V2 a set the harness's restatement of Family 2 calls non-canonical fails the checks. Sound
//!    because the Merkle root binds all 64 leaves, so no 32 of them rebuild a canonical set.
//! V3 with SIMD-0504 effective, V2's slot is dead.
//! V4 the verdict ignores order, batching and which 32+ shreds arrive. Compared only under one
//!    gate state: without SIMD-0504, per-shred insert rejections make death depend on which
//!    shreds arrived.
//! V5 with SIMD-0504 effective, mixed signatures change nothing and a re-delivery with another
//!    signature raises no duplicate proof; without it they fail the rebuild and the re-delivery
//!    raises `PayloadConflict`.
//! Whole block: in a block with one faulted set, exactly that set fails.
//!
//! Every built set must derive one Merkle root (one a leader can sign), so a fault that builds
//! an undeliverable set fails loudly.

#![no_main]

use {
    agave_shred_fuzz::{
        DATA_SIZE_OFFSET, FLAGS_OFFSET, Gates, LEADER_SEED, NUM_CODING_OFFSET, NUM_DATA_OFFSET,
        PARENT_OFFSET_OFFSET, POSITION_OFFSET, PROOF_ENTRIES, SHRED_VERSION, SLOT_OFFSET,
        VARIANT_OFFSET, bank_for, chained_root_range, is_resigned_variant, pick_fec_set,
        read_u16_le, recovery_context, stricter_active, with_blockstore,
    },
    agave_shred_wire_format::{
        constants as wire,
        kind::{Code, Data},
    },
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    reed_solomon_erasure::galois_8::ReedSolomon,
    solana_entry::entry::Entry,
    solana_hash::Hash,
    solana_keypair::{Keypair, Signer},
    solana_ledger::{
        blockstore::{Blockstore, PossibleDuplicateShred},
        blockstore_metrics::BlockstoreInsertionMetrics,
        shred::{
            DATA_SHREDS_PER_FEC_BLOCK, ProcessShredsStats, SHREDS_PER_FEC_BLOCK, Shred, ShredData,
            ShredFlags, Shredder,
            filter::ShredFilterContext,
            layout,
            merkle::{finish_erasure_batch_for_tests, reseal_erasure_batch_for_tests},
            merkle_tree::MerkleTree,
        },
    },
    solana_runtime::bank::Bank,
    solana_sha256_hasher::hashv,
    std::{cell::Cell, sync::Arc},
};

/// Gap before the delivery slots, so a parent up to `FIRST_SLOT` back stays above the root.
const FIRST_SLOT: u64 = 4;
const SLOTS: u64 = FIRST_SLOT + 4;
/// Restated from ledger's private `MERKLE_HASH_PREFIX_LEAF`; the one-root check catches drift.
const MERKLE_LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const LONG_PROOF_ENTRIES: usize = PROOF_ENTRIES + 1;
const MAX_ENTRIES: usize = 512;
/// A data shred's headers, which its declared size includes.
const DATA_HEADERS: u16 = 88;

#[derive(Arbitrary, Debug)]
struct Input {
    // Fixed-size fields before the Vec, so a short input still sets every knob.
    gates: Gates,
    fault: Fault,
    schedules: [Schedule; 2],
    mixed_mask: u64,
    redeliver: u8,
    is_last: bool,
    chained_root: u8,
    /// Synthetic entries, so a short input still spans several FEC sets.
    extra_entries: u16,
    set_pick: u8,
    /// Older leaders' layout: with `is_last`, the trailing set(s) are resigned.
    legacy_resigned: bool,
    whole_block: bool,
    entries: Vec<(u64, [u8; 32])>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Fault {
    None,
    /// A data shred names a parent 2..=FIRST_SLOT back, which still passes the filter.
    ParentOffset {
        shred: u8,
        back: u8,
    },
    /// A data shred's declared size changes within its capacity.
    DataSize {
        shred: u8,
        size: u16,
    },
    DataComplete {
        shred: u8,
    },
    ChainedRoot {
        shred: u8,
        xor: u8,
    },
    Parity {
        shred: u8,
        off: u16,
        xor: u8,
    },
    /// Two coding shreds swap positions, re-signed over a tree in the claimed order.
    SwapPositions {
        a: u8,
        b: u8,
    },
    /// One data shred flipped between the resigned and plain layouts, set re-signed.
    MixVariant {
        shred: u8,
    },
    /// Re-laid out with a 7-entry proof over a 65-leaf tree: every shred verifies, but no
    /// 64-leaf rebuild matches. With SIMD-0317 off, only SIMD-0504's check stops it.
    LongProof,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct Schedule {
    order: Order,
    /// Shreds per insert call; 0 means the whole set at once.
    batch: u8,
    /// Positions never delivered; withholding all coding makes a data-only set.
    withhold: u64,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Order {
    AsBuilt,
    Reversed,
    CodingFirst,
    Rotated(u8),
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Verdict {
    inserted: u64,
    checks_failed: usize,
    rebuild_failed: usize,
    checks_passed: usize,
    dead: bool,
}

impl Verdict {
    fn reached_threshold(&self) -> bool {
        self.inserted >= DATA_SHREDS_PER_FEC_BLOCK as u64
    }
}

fuzz_target!(|input: Input| {
    let bank = bank_for(input.gates);
    with_blockstore(&bank, SLOTS, |blockstore, base| {
        run(&bank, blockstore, base, &input)
    });
});

fn run(bank: &Arc<Bank>, blockstore: &Blockstore, base: u64, input: &Input) {
    let entries = honest_entries(&input.entries, input.extra_entries);
    if entries.is_empty() {
        return; // an empty entry batch is an aborted block, not honest content
    }
    let leader = Keypair::new_from_array(LEADER_SEED);
    let chained_root = Hash::new_from_array([input.chained_root; 32]);
    let build = |slot: u64| -> Option<(Vec<Shred>, bool)> {
        let set = honest_set(&entries, slot, input, chained_root, &leader)?;
        apply_fault(set, input.fault, &leader)
    };
    let mut verdicts = Vec::with_capacity(2);
    for (k, schedule) in input.schedules.iter().enumerate() {
        let slot = base + FIRST_SLOT + k as u64;
        let Some((set, parity_corrupted)) = build(slot) else {
            return;
        };
        let roots: Vec<_> = set
            .iter()
            .map(|s| layout::get_merkle_root(s.payload()))
            .collect();
        assert!(
            roots.windows(2).all(|pair| pair[0] == pair[1]),
            "harness: fault {:?} built a set that does not derive one Merkle root",
            input.fault,
        );
        let canonical = !non_canonical(bank, &set, parity_corrupted);
        let verdict = deliver(bank, blockstore, slot, &set, *schedule);
        check_verdict(bank, slot, canonical, &verdict, input.fault);
        verdicts.push(verdict);
    }
    let (a, b) = (&verdicts[0], &verdicts[1]);
    let (slot_a, slot_b) = (base + FIRST_SLOT, base + FIRST_SLOT + 1);
    let comparable = a.reached_threshold()
        && b.reached_threshold()
        && stricter_active(bank, slot_a) == stricter_active(bank, slot_b);
    let gated = stricter_active(bank, slot_a);
    let key = |v: &Verdict| (gated && v.dead, v.checks_failed > 0, v.checks_passed > 0);
    if comparable {
        assert_eq!(
            key(a),
            key(b),
            "V4: the FEC verdict depends on the delivery schedule: {a:?} vs {b:?} ({:?})",
            input.schedules,
        );
    }
    if input.whole_block {
        whole_block(
            bank,
            blockstore,
            base + FIRST_SLOT + 3,
            input,
            &entries,
            chained_root,
        );
    }
    if matches!(input.fault, Fault::None) {
        mixed_signatures(bank, blockstore, base, input, &build);
    }
}

/// V1, V2, V3 for one delivery.
fn check_verdict(bank: &Bank, slot: u64, canonical: bool, verdict: &Verdict, fault: Fault) {
    if canonical {
        assert!(
            !verdict.dead && verdict.checks_failed == 0,
            "V1: a canonical FEC set (fault {fault:?}) failed the checks or killed slot {slot}: \
             {verdict:?}"
        );
        return;
    }
    if !verdict.reached_threshold() {
        return;
    }
    assert!(
        verdict.checks_failed > 0,
        "V2: a non-canonical FEC set (fault {fault:?}) passed the checks at slot {slot}: \
         {verdict:?}"
    );
    if stricter_active(bank, slot) {
        assert!(
            verdict.dead,
            "V3: SIMD-0504 is effective but a non-canonical FEC set (fault {fault:?}) left slot \
             {slot} alive: {verdict:?}"
        );
    }
}

fn honest_entries(specs: &[(u64, [u8; 32])], extra: u16) -> Vec<Entry> {
    let fuzzed = specs.iter().take(MAX_ENTRIES).copied();
    // 48 serialized bytes each: up to ~1400 of them spans two to three FEC sets.
    let synthetic = (0..extra % 1400).map(|i| (u64::from(i), [i as u8; 32]));
    fuzzed
        .chain(synthetic)
        .map(|(num_hashes, hash)| Entry {
            num_hashes,
            hash: Hash::new_from_array(hash),
            transactions: vec![],
        })
        .collect()
}

fn honest_set(
    entries: &[Entry],
    slot: u64,
    input: &Input,
    chained_root: Hash,
    leader: &Keypair,
) -> Option<Vec<Shred>> {
    let set = pick_fec_set(
        honest_block(entries, slot, input, chained_root, leader)?,
        input.set_pick,
    )?;
    (set.len() == SHREDS_PER_FEC_BLOCK).then_some(set)
}

fn honest_block(
    entries: &[Entry],
    slot: u64,
    input: &Input,
    chained_root: Hash,
    leader: &Keypair,
) -> Option<Vec<Shred>> {
    let shredder = Shredder::new(slot, slot - 1, 0, SHRED_VERSION).ok()?;
    let mut stats = ProcessShredsStats::default();
    let shreds = if input.legacy_resigned {
        let (data, coding) = shredder.entries_to_resigned_merkle_shreds_for_tests(
            leader,
            entries,
            input.is_last,
            chained_root,
            0,
            0,
        );
        data.into_iter().chain(coding).collect()
    } else {
        shredder.make_merkle_shreds_from_entries(
            leader,
            entries,
            input.is_last,
            chained_root,
            0,
            0,
            &mut stats,
        )
    };
    Some(shreds)
}

/// Data-header faults are re-encoded so only the targeted rule breaks; the rest are resealed
/// over the faulted bytes. The bool reports corrupted parity, which the reference cannot
/// recompute. None when `finish` would get a shred that does not sanitize (it debug-asserts).
fn apply_fault(mut set: Vec<Shred>, fault: Fault, leader: &Keypair) -> Option<(Vec<Shred>, bool)> {
    let chained_root = set[0].chained_merkle_root().ok()?;
    let data = |shred: u8| usize::from(shred) % DATA_SHREDS_PER_FEC_BLOCK;
    let code = |shred: u8| DATA_SHREDS_PER_FEC_BLOCK + data(shred);
    let (pos, off, bytes, reencode) = match fault {
        Fault::None => return Some((set, false)),
        Fault::ParentOffset { shred, back } => {
            let offset = 2 + u16::from(back) % (FIRST_SLOT as u16 - 1);
            (
                data(shred),
                PARENT_OFFSET_OFFSET,
                offset.to_le_bytes().to_vec(),
                true,
            )
        }
        Fault::DataSize { shred, size } => {
            let variant = *set[data(shred)].payload().get(VARIANT_OFFSET)?;
            let capacity = ShredData::capacity(PROOF_ENTRIES as u8, is_resigned_variant(variant));
            let capacity = u16::try_from(capacity.ok()?).ok()?;
            let size = DATA_HEADERS + size % (capacity + 1);
            (
                data(shred),
                DATA_SIZE_OFFSET,
                size.to_le_bytes().to_vec(),
                true,
            )
        }
        Fault::DataComplete { shred } => {
            let flags = *set[data(shred)].payload().get(FLAGS_OFFSET)?;
            let flipped = flags ^ ShredFlags::DATA_COMPLETE_SHRED.bits();
            (data(shred), FLAGS_OFFSET, vec![flipped], true)
        }
        Fault::ChainedRoot { shred, xor } => {
            let pos = usize::from(shred) % SHREDS_PER_FEC_BLOCK;
            let range = chained_root_range(set[pos].payload())?;
            let mut root = set[pos].payload().get(range.clone())?.to_vec();
            root[0] ^= xor;
            (pos, range.start, root, false)
        }
        Fault::Parity { shred, off, xor } => {
            let shard =
                (POSITION_OFFSET + 2)..chained_root_range(set[code(shred)].payload())?.start;
            let at = shard.start + usize::from(off) % shard.len();
            let byte = *set[code(shred)].payload().get(at)? ^ xor;
            (code(shred), at, vec![byte], false)
        }
        Fault::SwapPositions { a, b } => return swap_positions(set, code(a), code(b), leader),
        Fault::LongProof => return Some((relayout_long_proof(&set, leader)?, false)),
        Fault::MixVariant { shred } => {
            let pos = data(shred);
            set[pos] = flip_resigned(&set[pos])?;
            reseal_erasure_batch_for_tests(leader, &mut set).ok()?;
            return Some((set, false));
        }
    };
    if !poke(&mut set, pos, off, &bytes) {
        return Some((set, false)); // not applicable: the set stays canonical
    }
    if reencode {
        set[pos].sanitize().ok()?;
        finish_erasure_batch_for_tests(leader, &mut set, chained_root).ok()?;
    } else {
        reseal_erasure_batch_for_tests(leader, &mut set).ok()?;
    }
    let parity_corrupted = matches!(fault, Fault::Parity { xor, .. } if xor != 0);
    Some((set, parity_corrupted))
}

fn flip_resigned(shred: &Shred) -> Option<Shred> {
    let payload = shred.payload();
    let variant = *payload.get(VARIANT_OFFSET)?;
    let resigned = is_resigned_variant(variant);
    let flipped = (if resigned { 0x90 } else { 0xb0 }) | (variant & 0x0f);
    let data = shred.data().ok()?;
    if data.len() > ShredData::capacity(variant & 0x0f, !resigned).ok()? {
        return None;
    }
    let headers = usize::from(DATA_HEADERS);
    let mut out = vec![0u8; payload.len()];
    out[..headers].copy_from_slice(payload.get(..headers)?);
    out[VARIANT_OFFSET] = flipped;
    out.get_mut(headers..headers + data.len())?
        .copy_from_slice(data);
    let root = chained_root_range(&out)?;
    out.get_mut(root)?
        .copy_from_slice(shred.chained_merkle_root().ok()?.as_ref());
    Shred::new_from_serialized_shred(out).ok()
}

/// Coding leaves are ordered by position, so the shreds also swap list slots before resealing.
fn swap_positions(
    mut set: Vec<Shred>,
    i: usize,
    j: usize,
    leader: &Keypair,
) -> Option<(Vec<Shred>, bool)> {
    if i == j {
        return Some((set, false));
    }
    let pos_i = read_u16_le(set[i].payload(), POSITION_OFFSET)?;
    let pos_j = read_u16_le(set[j].payload(), POSITION_OFFSET)?;
    if !poke(&mut set, i, POSITION_OFFSET, &pos_j.to_le_bytes())
        || !poke(&mut set, j, POSITION_OFFSET, &pos_i.to_le_bytes())
    {
        return None;
    }
    set.swap(i, j);
    reseal_erasure_batch_for_tests(leader, &mut set).ok()?;
    Some((set, false))
}

/// Reparses after writing, so the typed headers `finish` writes back carry the change.
fn poke(set: &mut [Shred], pos: usize, off: usize, bytes: &[u8]) -> bool {
    let mut payload = set[pos].payload().to_vec();
    let Some(dst) = payload.get_mut(off..off + bytes.len()) else {
        return false;
    };
    dst.copy_from_slice(bytes);
    match Shred::new_from_serialized_shred(payload) {
        Ok(shred) => {
            set[pos] = shred;
            true
        }
        Err(_) => false,
    }
}

/// A shred the filter rejects counts: blockstore rejects it once reconstructed.
fn non_canonical(bank: &Arc<Bank>, set: &[Shred], parity_corrupted: bool) -> bool {
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    set.iter().any(|s| filter.should_discard_shred(s.payload()))
        || violates_family2(set, parity_corrupted)
}

/// Family 2, restated from the bytes; `parity_corrupted` stands in for the codeword rule.
fn violates_family2(set: &[Shred], parity_corrupted: bool) -> bool {
    if parity_corrupted || set.len() != SHREDS_PER_FEC_BLOCK {
        return true;
    }
    let mut data: Vec<&Shred> = set.iter().filter(|s| s.is_data()).collect();
    let mut code: Vec<&Shred> = set.iter().filter(|s| s.is_code()).collect();
    if data.len() != DATA_SHREDS_PER_FEC_BLOCK || code.len() != DATA_SHREDS_PER_FEC_BLOCK {
        return true;
    }
    data.sort_by_key(|s| s.index());
    code.sort_by_key(|s| s.index());
    let fec = set[0].fec_set_index();
    let chained = set[0].chained_merkle_root().ok();
    let block = DATA_SHREDS_PER_FEC_BLOCK as u16;
    let header_mismatch = set.iter().any(|s| {
        s.slot() != set[0].slot()
            || s.version() != set[0].version()
            || s.fec_set_index() != fec
            || s.chained_merkle_root().ok() != chained
    });
    let variant = |s: &Shred| {
        s.payload()
            .get(VARIANT_OFFSET)
            .map(|v| (v & 0x0f, is_resigned_variant(*v)))
    };
    let variant_mismatch = set.iter().any(|s| variant(s) != variant(&set[0]));
    let wrong_proof_size =
        variant(&set[0]).map(|(entries, _)| usize::from(entries)) != Some(PROOF_ENTRIES);
    let index_mismatch = |group: &[&Shred]| {
        group
            .iter()
            .enumerate()
            .any(|(i, s)| Some(s.index()) != fec.checked_add(i as u32))
    };
    let coding_header = code.iter().enumerate().any(|(j, s)| {
        let p = s.payload();
        read_u16_le(p, NUM_DATA_OFFSET) != Some(block)
            || read_u16_le(p, NUM_CODING_OFFSET) != Some(block)
            || read_u16_le(p, POSITION_OFFSET) != Some(j as u16)
    });
    header_mismatch
        || variant_mismatch
        || wrong_proof_size
        || index_mismatch(&data)
        || index_mismatch(&code)
        || coding_header
        || violates_data_layout(&data)
}

/// One parent_offset; after the first short data shred, every later one is empty and the
/// last carries DATA_COMPLETE.
fn violates_data_layout(data: &[&Shred]) -> bool {
    let parent = |s: &Shred| read_u16_le(s.payload(), PARENT_OFFSET_OFFSET);
    if data.iter().any(|s| parent(s) != parent(data[0])) {
        return true;
    }
    let variant = data[0].payload().get(VARIANT_OFFSET).copied().unwrap_or(0);
    let Ok(capacity) = ShredData::capacity(variant & 0x0f, is_resigned_variant(variant)) else {
        return true;
    };
    let full = DATA_HEADERS as usize + capacity;
    let size = |s: &Shred| read_u16_le(s.payload(), DATA_SIZE_OFFSET).map_or(0, usize::from);
    let Some(partial) = data.iter().position(|s| size(s) != full) else {
        return false;
    };
    let padded = data[partial + 1..]
        .iter()
        .all(|s| size(s) == DATA_HEADERS as usize);
    let flags = data[data.len() - 1]
        .payload()
        .get(FLAGS_OFFSET)
        .copied()
        .unwrap_or(0);
    !padded || flags & ShredFlags::DATA_COMPLETE_SHRED.bits() == 0
}

/// Pre-filters like the fetch stage (insert debug-asserts `sanitize`), then inserts.
fn deliver(
    bank: &Arc<Bank>,
    blockstore: &Blockstore,
    slot: u64,
    set: &[Shred],
    schedule: Schedule,
) -> Verdict {
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    let mut kept: Vec<Shred> = set
        .iter()
        .enumerate()
        .filter(|(i, _)| schedule.withhold & (1u64 << (i % 64)) == 0)
        .map(|(_, s)| s)
        .filter(|s| s.sanitize().is_ok() && !filter.should_discard_shred(s.payload()))
        .cloned()
        .collect();
    reorder(&mut kept, schedule.order);
    let batch = match usize::from(schedule.batch) {
        0 => kept.len().max(1),
        n => n,
    };
    let mut verdict = Verdict::default();
    for chunk in kept.chunks(batch) {
        let metrics = insert(bank, blockstore, chunk.to_vec(), &|_| {});
        verdict.inserted += metrics.num_inserted;
        verdict.checks_failed += metrics.num_fec_set_checks_failed;
        verdict.rebuild_failed += metrics.num_fec_set_checks_rebuild_failed;
        verdict.checks_passed += metrics.num_fec_set_checks_passed;
    }
    verdict.dead = blockstore.is_dead(slot);
    verdict
}

fn reorder(shreds: &mut [Shred], order: Order) {
    match order {
        Order::AsBuilt => {}
        Order::Reversed => shreds.reverse(),
        Order::CodingFirst => shreds.sort_by_key(|s| s.is_data()),
        Order::Rotated(by) => {
            if !shreds.is_empty() {
                let by = usize::from(by) % shreds.len();
                shreds.rotate_left(by);
            }
        }
    }
}

fn insert<F: Fn(PossibleDuplicateShred)>(
    bank: &Arc<Bank>,
    blockstore: &Blockstore,
    shreds: Vec<Shred>,
    handle: &F,
) -> BlockstoreInsertionMetrics {
    let mut recovery_ctx = recovery_context(bank);
    let mut metrics = BlockstoreInsertionMetrics::default();
    let shreds: Vec<(Shred, bool)> = shreds.into_iter().map(|s| (s, false)).collect();
    let _ = blockstore.insert_shreds_handle_duplicate(
        shreds,
        /*is_trusted:*/ false,
        &mut recovery_ctx,
        handle,
        &mut metrics,
    );
    metrics
}

/// V5, on the honest set in a third slot.
fn mixed_signatures(
    bank: &Arc<Bank>,
    blockstore: &Blockstore,
    base: u64,
    input: &Input,
    build: &dyn Fn(u64) -> Option<(Vec<Shred>, bool)>,
) {
    let slot = base + FIRST_SLOT + 2;
    let Some((mut set, _)) = build(slot) else {
        return;
    };
    let mut altered = 0usize;
    for (i, shred) in set.iter_mut().enumerate() {
        if input.mixed_mask & (1 << (i % 64)) != 0 && resign_other(shred) {
            altered += 1;
        }
    }
    let one_batch = Schedule {
        order: Order::AsBuilt,
        batch: 0,
        withhold: 0,
    };
    let verdict = deliver(bank, blockstore, slot, &set, one_batch);
    let mixed = altered > 0 && altered < set.len();
    if stricter_active(bank, slot) {
        assert!(
            !verdict.dead && verdict.checks_failed == 0,
            "V5: SIMD-0504 is effective but mixed leader signatures over one Merkle root failed \
             the checks or killed slot {slot}: {verdict:?}"
        );
    } else if mixed && verdict.inserted == set.len() as u64 {
        assert!(
            verdict.rebuild_failed > 0 && !verdict.dead,
            "V5: SIMD-0504 is off but mixed signatures did not fail the rebuild, or killed slot \
             {slot}: {verdict:?}"
        );
    }
    let index = u64::from(set[0].fec_set_index())
        + u64::from(input.redeliver) % DATA_SHREDS_PER_FEC_BLOCK as u64;
    redeliver_other_signature(bank, blockstore, slot, index);
}

/// Insert never verifies signatures (sigverify runs first), so any other 64 bytes stand in
/// for a second valid leader signature over the same root.
fn resign_other(shred: &mut Shred) -> bool {
    let mut payload = shred.payload().to_vec();
    payload[0] ^= 0x01;
    match Shred::new_from_serialized_shred(payload) {
        Ok(other) => {
            *shred = other;
            true
        }
        Err(_) => false,
    }
}

fn redeliver_other_signature(bank: &Arc<Bank>, blockstore: &Blockstore, slot: u64, index: u64) {
    if blockstore.has_duplicate_shreds_in_slot(slot) {
        return;
    }
    let Some(mut shred) = blockstore
        .get_data_shred(slot, index)
        .ok()
        .flatten()
        .and_then(|payload| Shred::new_from_serialized_shred(payload).ok())
    else {
        return;
    };
    if !resign_other(&mut shred) {
        return;
    }
    let conflicts = Cell::new(0usize);
    let handle = |dup: PossibleDuplicateShred| {
        if matches!(dup, PossibleDuplicateShred::PayloadConflict(..)) {
            conflicts.set(conflicts.get() + 1);
        }
    };
    insert(bank, blockstore, vec![shred], &handle);
    if stricter_active(bank, slot) {
        assert_eq!(
            conflicts.get(),
            0,
            "V5: SIMD-0504 is effective but a stored shred re-delivered with another signature \
             raised a PayloadConflict at slot {slot} index {index}"
        );
    } else {
        assert_eq!(
            conflicts.get(),
            1,
            "V5: SIMD-0504 is off but a stored shred re-delivered with another signature raised \
             no PayloadConflict at slot {slot} index {index}"
        );
    }
}

/// `Fault::LongProof`: the 64 shreds in erasure order plus a filler leaf, parity re-encoded
/// for the smaller shards.
fn relayout_long_proof(set: &[Shred], leader: &Keypair) -> Option<Vec<Shred>> {
    let data_sections = wire::sections_with_proof_entries::<Data>(LONG_PROOF_ENTRIES, false)?;
    let code_sections = wire::sections_with_proof_entries::<Code>(LONG_PROOF_ENTRIES, false)?;
    let sections = |i: usize| {
        if i < DATA_SHREDS_PER_FEC_BLOCK {
            data_sections
        } else {
            code_sections
        }
    };
    if set.len() != SHREDS_PER_FEC_BLOCK || set[DATA_SHREDS_PER_FEC_BLOCK - 1].is_code() {
        return None;
    }
    let mut payloads = Vec::with_capacity(set.len());
    for (i, shred) in set.iter().enumerate() {
        let old = shred.payload();
        let variant = *old.get(VARIANT_OFFSET)?;
        if is_resigned_variant(variant) {
            return None;
        }
        let layout = sections(i);
        let mut out = vec![0u8; old.len()];
        out[VARIANT_OFFSET] = (variant & 0xf0) | LONG_PROOF_ENTRIES as u8;
        let headers = SLOT_OFFSET..layout.headers.end;
        out[headers.clone()].copy_from_slice(old.get(headers)?);
        if shred.is_data() {
            let data = shred.data().ok()?;
            if data.len() > layout.body.len() {
                return None;
            }
            out[layout.body.start..layout.body.start + data.len()].copy_from_slice(data);
        }
        out[layout.chained_merkle_root.as_range()]
            .copy_from_slice(shred.chained_merkle_root().ok()?.as_ref());
        payloads.push(out);
    }
    let (data, code) = payloads.split_at_mut(DATA_SHREDS_PER_FEC_BLOCK);
    let mut shards: Vec<&mut [u8]> = data
        .iter_mut()
        .map(|p| &mut p[data_sections.erasure_shard.as_range()])
        .chain(
            code.iter_mut()
                .map(|p| &mut p[code_sections.erasure_shard.as_range()]),
        )
        .collect();
    ReedSolomon::new(DATA_SHREDS_PER_FEC_BLOCK, DATA_SHREDS_PER_FEC_BLOCK)
        .ok()?
        .encode(&mut shards)
        .ok()?;
    let leaves = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            Ok(hashv(&[
                MERKLE_LEAF_PREFIX,
                &p[sections(i).merkle_leaf.as_range()],
            ]))
        })
        .chain(std::iter::once(Ok(Hash::default())));
    let len = SHREDS_PER_FEC_BLOCK + 1;
    let tree = MerkleTree::try_new_with_len(leaves, len).ok()?;
    let signature = leader.sign_message(tree.root().as_ref());
    for (i, payload) in payloads.iter_mut().enumerate() {
        let mut at = sections(i).merkle_proof.start;
        for entry in tree.make_merkle_proof(i, len) {
            let entry = entry.ok()?;
            payload[at..at + entry.len()].copy_from_slice(entry);
            at += entry.len();
        }
        payload[..signature.as_ref().len()].copy_from_slice(signature.as_ref());
    }
    payloads
        .into_iter()
        .map(|p| Shred::new_from_serialized_shred(p).ok())
        .collect()
}

/// Every FEC set of the block, with the fault in set `set_pick` only.
fn whole_block(
    bank: &Arc<Bank>,
    blockstore: &Blockstore,
    slot: u64,
    input: &Input,
    entries: &[Entry],
    chained_root: Hash,
) {
    let leader = Keypair::new_from_array(LEADER_SEED);
    let Some(block) = honest_block(entries, slot, input, chained_root, &leader) else {
        return;
    };
    let mut sets: Vec<Vec<Shred>> = Vec::new();
    for shred in block {
        match sets.last_mut() {
            Some(set) if set[0].fec_set_index() == shred.fec_set_index() => set.push(shred),
            _ => sets.push(vec![shred]),
        }
    }
    if sets.is_empty() || sets.iter().any(|set| set.len() != SHREDS_PER_FEC_BLOCK) {
        return;
    }
    let k = usize::from(input.set_pick) % sets.len();
    let Some((faulted, parity_corrupted)) = apply_fault(sets[k].clone(), input.fault, &leader)
    else {
        return;
    };
    let canonical = !non_canonical(bank, &faulted, parity_corrupted);
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    let admitted = faulted
        .iter()
        .filter(|s| s.sanitize().is_ok() && !filter.should_discard_shred(s.payload()))
        .count();
    sets[k] = faulted;
    let n = sets.len();
    let all: Vec<Shred> = sets.into_iter().flatten().collect();
    let schedule = Schedule {
        withhold: 0,
        ..input.schedules[0]
    };
    let verdict = deliver(bank, blockstore, slot, &all, schedule);
    if canonical {
        assert!(
            !verdict.dead && verdict.checks_failed == 0 && verdict.checks_passed == n,
            "whole block: {n} canonical FEC sets did not all pass, or slot {slot} died: \
             {verdict:?}"
        );
        return;
    }
    // One faulted shred may be rejected at insert; 33 admitted still crosses 32.
    if admitted <= DATA_SHREDS_PER_FEC_BLOCK {
        return;
    }
    assert!(
        verdict.checks_failed == 1 && verdict.checks_passed == n - 1,
        "whole block: set {k} of {n} faulted ({:?}) should fail alone at slot {slot}: {verdict:?}",
        input.fault,
    );
    if stricter_active(bank, slot) {
        assert!(
            verdict.dead,
            "whole block: SIMD-0504 is effective but faulted set {k} of {n} ({:?}) left slot \
             {slot} alive: {verdict:?}",
            input.fault,
        );
    }
}
