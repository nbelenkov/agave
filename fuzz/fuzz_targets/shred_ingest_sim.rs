//! A byzantine delivery script over one blockstore and several slots: chaining, recovery,
//! duplicate detection and completion as state accumulates.
//!
//! I1 insert never panics.
//! I2 `consumed <= received`.
//! I3 re-delivering stored data shreds byte-identical counts each as existing and raises no
//!    duplicate proof (that would be false equivocation evidence).
//! I4 every stored data shred passes the filter.
//! I5 a completed data set ends at or below `received`, with all its shreds stored.
//! I6 a slot's `next_slots` children name it as their parent.
//! I7 a Merkle root conflict, or a LAST shred below `received`, is flagged, and the slot is
//!    then dead unless full.
//! I8 replay's and RPC's decoders agree wherever both accept the slot.
//! I10 stored-shred growth is bounded by the action count.
//! I11 reconstructed shreds are bounded by the insert-call count (failed rebuilds and other
//!     time or memory blowups are left to libFuzzer's limits).

#![no_main]

use {
    agave_shred_fuzz::{
        FLAGS_OFFSET, Gates, LEADER_SEED, MAX_BLOCK_DATA, SHRED_VERSION, bank_for,
        build_block_fec_set, build_fec_set, recovery_context, resign, summarize_entries,
        summarize_views, with_blockstore,
    },
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore::{Blockstore, CompletedDataSetInfo, PossibleDuplicateShred},
        blockstore_metrics::BlockstoreInsertionMetrics,
        shred::{
            Shred, ShredFlags, filter::ShredFilterContext, layout,
            merkle::finish_erasure_batch_for_tests,
        },
    },
    solana_runtime::bank::Bank,
    std::{cell::Cell, sync::Arc},
};

const SLOTS_PER_INPUT: u64 = 16;
const MAX_ACTIONS: usize = 16;
// Each action inserts at most one FEC set of a two-set block (data indices below 64).
const MAX_DATA_PER_ACTION: u64 = 64;
const GROWTH_SLACK: u64 = 64;
// Each insert call feeds at most one FEC set: 32 data + 32 coding shreds to rebuild.
const MAX_RECOVERED_PER_INSERT: u64 = 64;

thread_local! {
    // I11: (reconstructed shreds, insert calls) for this input.
    static WORK: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

#[derive(Arbitrary, Debug)]
struct Input {
    gates: Gates,
    data_pool: Vec<u8>,
    actions: Vec<Action>,
}

#[derive(Arbitrary, Debug)]
enum Action {
    Deliver {
        slot: u8,
        parent: u8,
        len: u16,
        set: u8,
        drop_mask: u64,
        reversed: bool,
    },
    DeliverMalformed {
        slot: u8,
        parent: u8,
        len: u16,
        victim: u8,
        victim_flags: VictimFlags,
    },
    Conflict {
        slot: u8,
    },
    Equivocate {
        slot: u8,
        len_a: u16,
        len_b: u16,
        pick: u8,
    },
    LastIndexConflict {
        slot: u8,
        len: u16,
    },
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
    with_blockstore(&bank, SLOTS_PER_INPUT, |blockstore, base| {
        run_sequence(&bank, blockstore, base, &input);
    });
});

fn run_sequence(bank: &Arc<Bank>, blockstore: &Blockstore, base: u64, input: &Input) {
    let leader = Keypair::new_from_array(LEADER_SEED);
    let mut pool_off = 0usize;

    // I10 bounds the delta, so a stale window in a reused blockstore cannot false-positive.
    let received_before = window_received(blockstore, base);
    WORK.with(|w| w.set((0, 0)));

    for action in input.actions.iter().take(MAX_ACTIONS) {
        match action {
            Action::Deliver {
                slot,
                parent,
                len,
                set,
                drop_mask,
                reversed,
            } => {
                let (s, p) = map_slots(base, *slot, *parent);
                let data = take_slice(&input.data_pool, &mut pool_off, *len);
                let Some(batch) = build_block_fec_set(&data, s, p, &leader, false, *set) else {
                    continue;
                };
                let kept: Vec<Shred> = batch
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| drop_mask & (1u64 << (i % 64)) == 0)
                    .map(|(_, sh)| sh)
                    .collect();
                deliver(blockstore, bank, s, kept, *reversed);
            }
            Action::DeliverMalformed {
                slot,
                parent,
                len,
                victim,
                victim_flags,
            } => {
                let (s, p) = map_slots(base, *slot, *parent);
                let data = take_slice(&input.data_pool, &mut pool_off, *len);
                if let Some(kept) =
                    malformed_minus_victim(&data, s, p, *victim, *victim_flags, &leader)
                {
                    deliver(blockstore, bank, s, kept, false);
                }
            }
            Action::Conflict { slot } => {
                let s = base + u64::from(*slot) % SLOTS_PER_INPUT;
                conflict(blockstore, bank, s);
            }
            Action::Equivocate {
                slot,
                len_a,
                len_b,
                pick,
            } => {
                let s = base + 1 + u64::from(*slot) % (SLOTS_PER_INPUT - 1);
                let data_a = take_slice(&input.data_pool, &mut pool_off, *len_a);
                let data_b = take_slice(&input.data_pool, &mut pool_off, *len_b);
                equivocate(blockstore, bank, s, &data_a, &data_b, *pick, &leader);
            }
            Action::LastIndexConflict { slot, len } => {
                let s = base + 1 + u64::from(*slot) % (SLOTS_PER_INPUT - 1);
                let data = take_slice(&input.data_pool, &mut pool_off, *len);
                last_index_conflict(blockstore, bank, s, &data, &leader);
            }
        }
    }

    // I6
    for off in 0..SLOTS_PER_INPUT {
        let s = base + off;
        let Ok(Some(meta)) = blockstore.meta(s) else {
            continue;
        };
        for &child in &meta.next_slots {
            if child < base || child >= base + SLOTS_PER_INPUT {
                continue;
            }
            if let Ok(Some(cmeta)) = blockstore.meta(child) {
                assert_eq!(
                    cmeta.parent_slot,
                    Some(s),
                    "chaining inconsistency: slot {s} lists child {child} but its parent_slot is \
                     {:?}",
                    cmeta.parent_slot,
                );
            }
        }
    }

    // I10
    let actions = input.actions.len().min(MAX_ACTIONS) as u64;
    let growth = window_received(blockstore, base).saturating_sub(received_before);
    let bound = MAX_DATA_PER_ACTION
        .saturating_mul(actions)
        .saturating_add(GROWTH_SLACK);
    assert!(
        growth <= bound,
        "asymmetric state growth: {actions} actions added {growth} stored data shreds across the \
         window (bound {bound})",
    );

    // I11
    let (recovered, insert_calls) = WORK.with(Cell::get);
    let recover_bound = MAX_RECOVERED_PER_INSERT
        .saturating_mul(insert_calls)
        .saturating_add(GROWTH_SLACK);
    assert!(
        recovered <= recover_bound,
        "asymmetric recovery work: {insert_calls} insert calls reconstructed {recovered} shreds \
         (bound {recover_bound})",
    );
}

fn window_received(blockstore: &Blockstore, base: u64) -> u64 {
    (0..SLOTS_PER_INPUT)
        .filter_map(|off| blockstore.meta(base + off).ok().flatten())
        .map(|meta| meta.received)
        .sum()
}

fn map_slots(base: u64, slot: u8, parent: u8) -> (u64, u64) {
    let slot_off = 1 + u64::from(slot) % (SLOTS_PER_INPUT - 1);
    (base + slot_off, base + u64::from(parent) % slot_off)
}

/// Cycles the pool, so a short input can still fill a FEC set.
fn take_slice(pool: &[u8], off: &mut usize, len: u16) -> Vec<u8> {
    let take = usize::from(len).min(MAX_BLOCK_DATA);
    let out = if pool.is_empty() {
        Vec::new()
    } else {
        (0..take).map(|i| pool[(*off + i) % pool.len()]).collect()
    };
    *off = off.wrapping_add(take.max(1));
    out
}

/// Pre-filters (insert debug-asserts `sanitize`), inserts, and checks I2, I4, I5 and I8.
fn deliver(
    blockstore: &Blockstore,
    bank: &Arc<Bank>,
    slot: u64,
    mut shreds: Vec<Shred>,
    reversed: bool,
) {
    if reversed {
        shreds.reverse();
    }
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    let kept: Vec<(Shred, bool)> = shreds
        .into_iter()
        .filter(|sh| sh.sanitize().is_ok() && !filter.should_discard_shred(sh.payload()))
        .map(|sh| (sh, false))
        .collect();
    if kept.is_empty() {
        return;
    }
    let (completed, _) = insert(blockstore, bank, kept, &|_| {});

    if let Ok(Some(meta)) = blockstore.meta(slot) {
        assert!(
            meta.consumed <= meta.received,
            "SlotMeta consumed {} > received {} at slot {slot}",
            meta.consumed,
            meta.received,
        );
        for info in &completed {
            assert!(
                info.slot >= slot.saturating_sub(SLOTS_PER_INPUT)
                    && info.indices.start <= info.indices.end,
                "CompletedDataSetInfo {info:?} malformed",
            );
            if let Ok(Some(m)) = blockstore.meta(info.slot) {
                assert!(
                    u64::from(info.indices.end) <= m.received,
                    "completed set end {} > received {} at slot {}",
                    info.indices.end,
                    m.received,
                    info.slot,
                );
            }
            let missing = info.indices.clone().find(|index| {
                !matches!(
                    blockstore.get_data_shred(info.slot, u64::from(*index)),
                    Ok(Some(_))
                )
            });
            assert!(
                missing.is_none(),
                "completed set {info:?} reported with data shred {missing:?} not stored",
            );
        }
        assert_stored_canonical(blockstore, bank, slot, meta.received);

        check_decoders_agree(blockstore, slot);
    }
}

/// I8
fn check_decoders_agree(blockstore: &Blockstore, slot: u64) {
    let replayed = blockstore.get_slot_component_views_with_shred_info(slot, 0, false);
    let rpc = blockstore.get_slot_entries(slot, 0);
    if let (Ok((components, _, _)), Ok(entries)) = (replayed, rpc) {
        assert_eq!(
            summarize_views(&components),
            summarize_entries(&entries),
            "replay and RPC decode slot {slot} to different entries",
        );
    }
}

/// I4: holds for recovered shreds only because recovery re-filters them.
fn assert_stored_canonical(blockstore: &Blockstore, bank: &Arc<Bank>, slot: u64, received: u64) {
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    for index in 0..received {
        if let Ok(Some(payload)) = blockstore.get_data_shred(slot, index) {
            assert!(
                !filter.should_discard_shred(&payload),
                "blockstore stored a data shred the network filter rejects: slot {slot} index \
                 {index}"
            );
        }
    }
}

/// A set with a completion flag baked into one data shred (re-encoded), minus that shred, so
/// recovery must rebuild it.
fn malformed_minus_victim(
    data: &[u8],
    slot: u64,
    parent: u64,
    victim: u8,
    victim_flags: VictimFlags,
    leader: &Keypair,
) -> Option<Vec<Shred>> {
    let mut shreds = build_fec_set(data, slot, parent, leader)?;
    let data_positions: Vec<usize> = shreds
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_data())
        .map(|(i, _)| i)
        .collect();
    if data_positions.len() < 2 {
        return None;
    }
    let vpos = data_positions[usize::from(victim) % data_positions.len()];
    let mut bytes = shreds[vpos].payload().to_vec();
    *bytes.get_mut(FLAGS_OFFSET)? |= victim_flags.bits();
    shreds[vpos] = Shred::new_from_serialized_shred(bytes).ok()?;
    finish_erasure_batch_for_tests(leader, &mut shreds, Hash::default()).ok()?;
    Some(
        shreds
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != vpos)
            .map(|(_, s)| s)
            .collect(),
    )
}

/// I3. Presence comes from `get_data_shred`, not from the detector under test.
fn conflict(blockstore: &Blockstore, bank: &Arc<Bank>, slot: u64) {
    let Ok(Some(meta)) = blockstore.meta(slot) else {
        return;
    };
    let present: Vec<Shred> = (0..meta.received)
        .filter_map(|index| blockstore.get_data_shred(slot, index).ok().flatten())
        .filter_map(|payload| Shred::new_from_serialized_shred(payload).ok())
        .collect();
    if present.is_empty() {
        return;
    }
    let n = present.len();
    let duplicates = Cell::new(0usize);
    let handle = |_: PossibleDuplicateShred| duplicates.set(duplicates.get() + 1);
    let reinsert: Vec<(Shred, bool)> = present.into_iter().map(|s| (s, false)).collect();
    let (_, metrics) = insert(blockstore, bank, reinsert, &handle);
    assert_eq!(
        metrics.num_turbine_data_shreds_exists, n,
        "re-delivering {n} present data shreds at slot {slot} (untrusted) counted only {} as \
         existing",
        metrics.num_turbine_data_shreds_exists,
    );
    assert_eq!(
        duplicates.get(),
        0,
        "re-delivering {n} byte-identical present data shreds at slot {slot} raised {} duplicate \
         proofs",
        duplicates.get(),
    );
}

/// I7: a stored anchor, then a same-set shred under another Merkle root. `pick` chooses data
/// or coding, so both insert paths' checks run.
fn equivocate(
    blockstore: &Blockstore,
    bank: &Arc<Bank>,
    slot: u64,
    data_a: &[u8],
    data_b: &[u8],
    pick: u8,
    leader: &Keypair,
) {
    let parent = recorded_parent(blockstore, slot);
    let (Some(set_a), Some(set_b)) = (
        build_fec_set(data_a, slot, parent, leader),
        build_fec_set(data_b, slot, parent, leader),
    ) else {
        return;
    };
    let Some(anchor) = set_a.into_iter().next() else {
        return;
    };
    let fec = anchor.fec_set_index();
    // A different index avoids the exists path.
    let candidates: Vec<Shred> = set_b
        .into_iter()
        .filter(|s| s.fec_set_index() == fec && s.index() != anchor.index())
        .collect();
    if candidates.is_empty() {
        return;
    }
    let other = candidates[usize::from(pick) % candidates.len()].clone();
    if layout::get_merkle_root(anchor.payload()) == layout::get_merkle_root(other.payload()) {
        return;
    }
    let noop = |_: PossibleDuplicateShred| {};
    let anchor_index = u64::from(anchor.index());
    let anchor_payload = anchor.payload().to_vec();
    insert(blockstore, bank, vec![(anchor, false)], &noop);
    // Blockstore may reject the anchor, e.g. after a marker changed the expected parent.
    let stored = blockstore.get_data_shred(slot, anchor_index).ok().flatten();
    if stored.as_deref() != Some(anchor_payload.as_slice())
        && !blockstore.has_duplicate_shreds_in_slot(slot)
    {
        return;
    }
    let flagged = Cell::new(false);
    let handle = |_: PossibleDuplicateShred| flagged.set(true);
    insert(blockstore, bank, vec![(other, false)], &handle);
    assert!(
        flagged.get() || blockstore.has_duplicate_shreds_in_slot(slot),
        "equivocation undetected at slot {slot} erasure set {fec}: two leader-signed shreds with \
         different merkle roots were not flagged as a conflict",
    );
    assert_dead_unless_full(blockstore, slot, "a Merkle root conflict");
}

/// I7 for slot length: set 1's data shreds (no coding, so set 0 stays missing), then set 0's
/// last data shred flagged LAST. It passes the filter yet ends the slot below `received`.
fn last_index_conflict(
    blockstore: &Blockstore,
    bank: &Arc<Bank>,
    slot: u64,
    data: &[u8],
    leader: &Keypair,
) {
    let parent = recorded_parent(blockstore, slot);
    let filler = [0xa5u8];
    let source = if data.is_empty() { &filler[..] } else { data };
    let block: Vec<u8> = source
        .iter()
        .cycle()
        .take(MAX_BLOCK_DATA)
        .copied()
        .collect();
    let (Some(first), Some(second)) = (
        build_block_fec_set(&block, slot, parent, leader, false, 0),
        build_block_fec_set(&block, slot, parent, leader, false, 1),
    ) else {
        return;
    };
    let Some(victim) = first
        .iter()
        .filter(|s| s.is_data())
        .max_by_key(|s| s.index())
    else {
        return;
    };
    if second[0].fec_set_index() == first[0].fec_set_index() {
        return; // a one-set block
    }
    let delivered: Vec<(Shred, bool)> = second
        .iter()
        .filter(|s| s.is_data())
        .map(|s| (s.clone(), false))
        .collect();
    let noop = |_: PossibleDuplicateShred| {};
    insert(blockstore, bank, delivered, &noop);

    let Ok(Some(meta)) = blockstore.meta(slot) else {
        return;
    };
    let index = u64::from(victim.index());
    if index >= meta.received || matches!(blockstore.get_data_shred(slot, index), Ok(Some(_))) {
        return;
    }
    let mut bytes = victim.payload().to_vec();
    let Some(flags) = bytes.get_mut(FLAGS_OFFSET) else {
        return;
    };
    *flags |= ShredFlags::LAST_SHRED_IN_SLOT.bits();
    resign(&mut bytes, leader);
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    if filter.should_discard_shred(&bytes) {
        return; // production would drop it before blockstore
    }
    let Ok(forced) = Shred::new_from_serialized_shred(bytes) else {
        return;
    };
    let flagged = Cell::new(false);
    let handle = |_: PossibleDuplicateShred| flagged.set(true);
    insert(blockstore, bank, vec![(forced, false)], &handle);
    assert!(
        flagged.get() || blockstore.has_duplicate_shreds_in_slot(slot),
        "last-index equivocation undetected at slot {slot}: a LAST shred at index {index} below \
         received {} was not flagged as a conflict",
        meta.received,
    );
    assert_dead_unless_full(blockstore, slot, "a last-index conflict");
}

/// I7: blockstore leaves a full slot to replay.
fn assert_dead_unless_full(blockstore: &Blockstore, slot: u64, conflict: &str) {
    let full = blockstore
        .meta(slot)
        .ok()
        .flatten()
        .is_some_and(|meta| meta.is_full());
    assert!(
        blockstore.is_dead(slot) || full,
        "{conflict} was flagged at slot {slot} but the slot is neither dead nor full",
    );
}

/// So new shreds for `slot` are not rejected for a parent mismatch.
fn recorded_parent(blockstore: &Blockstore, slot: u64) -> u64 {
    blockstore
        .meta(slot)
        .ok()
        .flatten()
        .and_then(|meta| meta.parent_slot)
        .filter(|parent| *parent < slot)
        .unwrap_or(slot - 1)
}

fn insert<F: Fn(PossibleDuplicateShred)>(
    blockstore: &Blockstore,
    bank: &Arc<Bank>,
    shreds: Vec<(Shred, bool)>,
    handle: &F,
) -> (Vec<CompletedDataSetInfo>, BlockstoreInsertionMetrics) {
    let mut recovery_ctx = recovery_context(bank);
    let mut metrics = BlockstoreInsertionMetrics::default();
    let completed = blockstore
        .insert_shreds_handle_duplicate(
            shreds,
            /*is_trusted:*/ false,
            &mut recovery_ctx,
            handle,
            &mut metrics,
        )
        .unwrap_or_default();
    // I11
    let reconstructed = metrics
        .num_recovered_data_shreds
        .saturating_add(metrics.num_recovered_coding_shreds) as u64;
    WORK.with(|w| {
        let (recovered, calls) = w.get();
        w.set((
            recovered.saturating_add(reconstructed),
            calls.saturating_add(1),
        ));
    });
    (completed, metrics)
}
