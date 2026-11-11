//! Shared helpers for the shred fuzz targets.

use {
    agave_shred_wire_format::{
        constants as wire,
        kind::{Code, Data},
    },
    arbitrary::Arbitrary,
    solana_clock::DEFAULT_NS_PER_TICK_400_MS,
    solana_entry::{block_component::ParsedBlockComponent, entry::Entry},
    solana_hash::Hash,
    solana_keypair::{Keypair, Signer},
    solana_leader_schedule::SlotLeader,
    solana_ledger::{
        blockstore::Blockstore,
        genesis_utils::create_genesis_config,
        shred::{
            ProcessShredsStats, Shred, Shredder,
            filter::{RetransmitSender, ShredRecoveryContext, new_dummy_retransmit_sender},
            layout,
        },
    },
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_signature::Signature,
    std::{
        cell::{Cell, RefCell},
        ops::Range,
        sync::{Arc, OnceLock},
        time::Duration,
    },
    tempfile::TempDir,
};

pub const LEADER_SEED: [u8; 32] = [7u8; 32];
pub const SHRED_VERSION: u16 = 0;

pub const VARIANT_OFFSET: usize = wire::OFFSET_OF_VARIANT;
pub const SLOT_OFFSET: usize = wire::OFFSET_OF_SLOT;
pub const INDEX_OFFSET: usize = wire::OFFSET_OF_INDEX;
pub const VERSION_OFFSET: usize = wire::OFFSET_OF_VERSION;
pub const FEC_SET_INDEX_OFFSET: usize = wire::OFFSET_OF_FEC_SET_INDEX;
pub const PARENT_OFFSET_OFFSET: usize = wire::OFFSET_OF_PARENT_OFFSET;
pub const FLAGS_OFFSET: usize = wire::OFFSET_OF_FLAGS;
pub const DATA_SIZE_OFFSET: usize = wire::OFFSET_OF_DATA_SIZE;
pub const NUM_DATA_OFFSET: usize = wire::OFFSET_OF_NUM_DATA_SHREDS;
pub const NUM_CODING_OFFSET: usize = wire::OFFSET_OF_NUM_CODE_SHREDS;
pub const POSITION_OFFSET: usize = wire::OFFSET_OF_POSITION;
/// Proof length of a 32:32 erasure set (a 64-leaf tree).
pub const PROOF_ENTRIES: usize = 6;

pub fn is_resigned_variant(variant: u8) -> bool {
    matches!(variant & 0xf0, 0x70 | 0xb0)
}

pub fn chained_root_range(payload: &[u8]) -> Option<Range<usize>> {
    let variant = *payload.get(VARIANT_OFFSET)?;
    let resigned = is_resigned_variant(variant);
    let sections = match variant & 0xf0 {
        0x60 | 0x70 => wire::sections_with_proof_entries::<Code>(PROOF_ENTRIES, resigned),
        0x90 | 0xb0 => wire::sections_with_proof_entries::<Data>(PROOF_ENTRIES, resigned),
        _ => None,
    }?;
    Some(sections.chained_merkle_root.as_range())
}

thread_local! {
    static BANKS: RefCell<[Option<Arc<Bank>>; 8]> = const { RefCell::new([const { None }; 8]) };
    // `new_dummy_retransmit_sender` spawns a worker thread, so share one.
    static RETRANSMIT: RetransmitSender = new_dummy_retransmit_sender();
    static STORE: RefCell<Option<(Blockstore, TempDir)>> = const { RefCell::new(None) };
    static NEXT_SLOT: Cell<u64> = const { Cell::new(0) };
    static INPUTS: Cell<u64> = const { Cell::new(0) };
}

/// Reopening bounds RSS: RocksDB only reclaims deleted ranges on compaction.
const REOPEN_EVERY: u64 = 2000;

#[derive(Arbitrary, Clone, Copy, Debug)]
pub struct Gates {
    pub proof_size: bool,
    pub stricter: bool,
    /// Root at the activation slot, so shred slots straddle the first effective slot.
    pub at_activation: bool,
}

impl Gates {
    fn index(self) -> usize {
        usize::from(self.proof_size)
            | usize::from(self.stricter) << 1
            | usize::from(self.at_activation) << 2
    }
}

pub fn proof_size_gate() -> Pubkey {
    agave_feature_set::enforce_correct_proof_size::id()
}

pub fn stricter_gate() -> Pubkey {
    agave_feature_set::stricter_shred_validation::id()
}

pub fn bank_for(gates: Gates) -> Arc<Bank> {
    BANKS.with(|cell| {
        let idx = gates.index();
        if let Some(bank) = &cell.borrow()[idx] {
            return bank.clone();
        }
        let bank = build_bank(gates);
        cell.borrow_mut()[idx] = Some(bank.clone());
        bank
    })
}

fn build_bank(gates: Gates) -> Arc<Bank> {
    let mut genesis = create_genesis_config(1).genesis_config;
    // 400ms ticks as on the live clusters; otherwise the SIMD-0525 shred caps do not apply.
    genesis.poh_config.target_tick_duration = Duration::from_nanos(DEFAULT_NS_PER_TICK_400_MS);
    // `Bank::deactivate_feature` does not survive advancing across epochs, so a gate-off
    // bank drops the feature account from genesis instead.
    for (on, gate) in [
        (gates.proof_size, proof_size_gate()),
        (gates.stricter, stricter_gate()),
    ] {
        if !on {
            genesis.accounts.remove(&gate);
        }
    }
    let bank = Bank::new_for_tests(&genesis);
    let (bank, forks) = bank.wrap_with_bank_forks_for_tests();
    if gates.at_activation {
        return bank;
    }
    // Shred gates take effect one epoch after activation.
    let target = bank
        .epoch_schedule()
        .slots_per_epoch
        .saturating_mul(2)
        .saturating_add(1);
    Bank::new_from_parent_with_bank_forks(&forks, bank, SlotLeader::default(), target)
}

pub fn stricter_active(bank: &Bank, shred_slot: u64) -> bool {
    first_effective_slot(bank, &stricter_gate()).is_some_and(|first| shred_slot >= first)
}

pub fn proof_size_active(bank: &Bank, shred_slot: u64) -> bool {
    first_effective_slot(bank, &proof_size_gate()).is_some_and(|first| shred_slot >= first)
}

/// Restated from the SIMD rule rather than taken from the filter, so an off-by-one there shows.
pub fn first_effective_slot(bank: &Bank, feature: &Pubkey) -> Option<u64> {
    let activated = bank.feature_set.activated_slot(feature)?;
    let schedule = bank.epoch_schedule();
    Some(schedule.get_first_slot_in_epoch(schedule.get_epoch(activated).saturating_add(1)))
}

/// One full FEC set (32 data shreds of ~963 bytes) and part of a second.
pub const MAX_BLOCK_DATA: usize = 61_000;

pub fn build_fec_set(data: &[u8], slot: u64, parent: u64, leader: &Keypair) -> Option<Vec<Shred>> {
    let data = &data[..data.len().min(30_000)];
    pick_fec_set(shred_block(data, slot, parent, leader, false)?, 0)
}

pub fn build_block_fec_set(
    data: &[u8],
    slot: u64,
    parent: u64,
    leader: &Keypair,
    is_last_in_slot: bool,
    pick: u8,
) -> Option<Vec<Shred>> {
    let data = &data[..data.len().min(MAX_BLOCK_DATA)];
    pick_fec_set(
        shred_block(data, slot, parent, leader, is_last_in_slot)?,
        pick,
    )
}

pub fn pick_fec_set(block: Vec<Shred>, pick: u8) -> Option<Vec<Shred>> {
    let mut sets: Vec<u32> = block.iter().map(Shred::fec_set_index).collect();
    sets.dedup();
    let chosen = *sets.get(usize::from(pick) % sets.len().max(1))?;
    Some(
        block
            .into_iter()
            .filter(|s| s.fec_set_index() == chosen)
            .collect(),
    )
}

fn shred_block(
    data: &[u8],
    slot: u64,
    parent: u64,
    leader: &Keypair,
    is_last_in_slot: bool,
) -> Option<Vec<Shred>> {
    let shredder = Shredder::new(slot, parent, 0, SHRED_VERSION).ok()?;
    let mut stats = ProcessShredsStats::default();
    shredder
        .make_shreds_from_data_slice(
            leader,
            data,
            is_last_in_slot,
            Hash::default(),
            0,
            0,
            &mut stats,
        )
        .ok()
}

pub fn read_u16_le(payload: &[u8], off: usize) -> Option<u16> {
    payload
        .get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub fn resign(payload: &mut [u8], leader: &Keypair) {
    let Some(root) = layout::get_merkle_root(payload) else {
        return;
    };
    let signature = leader.sign_message(root.as_ref());
    if payload.len() >= 64 {
        payload[..64].copy_from_slice(signature.as_ref());
    }
}

pub fn recovery_context(bank: &Arc<Bank>) -> ShredRecoveryContext {
    let sender = RETRANSMIT.with(Arc::clone);
    ShredRecoveryContext::new(sender, bank.clone(), SHRED_VERSION)
}

/// Runs `run(blockstore, base)` with slots `[base, base + slots)` unused, above the root and
/// inside the filter's slot window. `SHRED_FUZZ_FRESH=1` opens a blockstore per input so a
/// crash replays deterministically.
pub fn with_blockstore<R>(
    bank: &Bank,
    slots: u64,
    run: impl FnOnce(&Blockstore, u64) -> R,
) -> Option<R> {
    let root = bank.slot();
    if fresh_mode() {
        let dir = TempDir::new().ok()?;
        let blockstore = Blockstore::open(dir.path()).ok()?;
        return Some(run(&blockstore, root + 1));
    }
    // Mirrors the filter's private `max_shred_slot`.
    let max_slot = root.saturating_add(500.max(bank.get_slots_in_epoch(bank.epoch()) / 2));
    let inputs = INPUTS.with(|c| {
        c.set(c.get().wrapping_add(1));
        c.get()
    });
    let exhausted = NEXT_SLOT.with(|n| n.get() < root + 1 || n.get() + slots > max_slot);
    let stale = STORE.with(|c| c.borrow().is_none()) || inputs.is_multiple_of(REOPEN_EVERY);
    if exhausted || stale {
        let dir = TempDir::new().ok()?;
        let blockstore = Blockstore::open(dir.path()).ok()?;
        STORE.with(|c| c.replace(Some((blockstore, dir))));
        NEXT_SLOT.with(|n| n.set(root + 1));
    }
    let base = NEXT_SLOT.with(|n| {
        let base = n.get();
        n.set(base + slots);
        base
    });
    STORE.with(|c| {
        c.borrow()
            .as_ref()
            .map(|(blockstore, _)| run(blockstore, base))
    })
}

fn fresh_mode() -> bool {
    static FRESH: OnceLock<bool> = OnceLock::new();
    *FRESH.get_or_init(|| std::env::var_os("SHRED_FUZZ_FRESH").is_some())
}

pub type EntrySummary = (u64, Hash, Vec<Signature>);

/// As RPC decodes a slot (`get_slot_entries`).
pub fn summarize_entries(entries: &[Entry]) -> Vec<EntrySummary> {
    entries
        .iter()
        .map(|entry| {
            let signatures = entry
                .transactions
                .iter()
                .flat_map(|tx| tx.signatures.iter().copied())
                .collect();
            (entry.num_hashes, entry.hash, signatures)
        })
        .collect()
}

/// As replay decodes a slot (`get_slot_component_views_with_shred_info`), markers skipped.
pub fn summarize_views(components: &[ParsedBlockComponent]) -> Vec<EntrySummary> {
    components
        .iter()
        .filter_map(|component| match component {
            ParsedBlockComponent::EntryBatch(views) => Some(views),
            ParsedBlockComponent::BlockMarker(_) => None,
        })
        .flatten()
        .map(|view| {
            let signatures = view
                .transactions
                .iter()
                .flat_map(|tx| tx.signatures().iter().copied())
                .collect();
            (view.num_hashes, view.hash, signatures)
        })
        .collect()
}
