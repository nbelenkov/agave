//! Entries with signed transfers, shredded into a complete slot in a fresh blockstore: replay's
//! and RPC's decoders must each return exactly those entries.

#![no_main]

use {
    agave_shred_fuzz::{LEADER_SEED, summarize_entries, summarize_views},
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_entry::entry::Entry,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore::Blockstore,
        shred::{ProcessShredsStats, Shred, Shredder},
    },
    solana_pubkey::Pubkey,
    solana_transaction::versioned::VersionedTransaction,
    tempfile::TempDir,
};

const MAX_ENTRIES: usize = 64;
const MAX_TXS_PER_ENTRY: usize = 4;
const MAX_TXS_TOTAL: usize = 64;

#[derive(Arbitrary, Debug)]
struct Input {
    slot_offset: u16,
    version: u16,
    entries: Vec<EntrySpec>,
}

#[derive(Arbitrary, Debug)]
struct EntrySpec {
    num_hashes: u64,
    hash: [u8; 32],
    txs: Vec<TxSpec>,
}

#[derive(Arbitrary, Debug)]
struct TxSpec {
    from_seed: u8,
    to: [u8; 32],
    lamports: u64,
}

fuzz_target!(|input: Input| {
    if input.entries.is_empty() {
        return;
    }
    let mut tx_budget = MAX_TXS_TOTAL;
    let mut entries: Vec<Entry> = Vec::new();
    for e in input.entries.iter().take(MAX_ENTRIES) {
        let mut transactions: Vec<VersionedTransaction> = Vec::new();
        for t in e.txs.iter().take(MAX_TXS_PER_ENTRY) {
            if tx_budget == 0 {
                break;
            }
            tx_budget -= 1;
            let from = Keypair::new_from_array([t.from_seed; 32]);
            let to = Pubkey::new_from_array(t.to);
            let tx = solana_system_transaction::transfer(&from, &to, t.lamports, Hash::default());
            transactions.push(VersionedTransaction::from(tx));
        }
        entries.push(Entry {
            num_hashes: e.num_hashes,
            hash: Hash::new_from_array(e.hash),
            transactions,
        });
    }

    let slot = u64::from(input.slot_offset) + 1;
    let Ok(shredder) = Shredder::new(slot, slot - 1, 0, input.version) else {
        return;
    };
    let leader = Keypair::new_from_array(LEADER_SEED);
    let mut stats = ProcessShredsStats::default();

    let shreds: Vec<Shred> = shredder.make_merkle_shreds_from_entries(
        &leader,
        &entries,
        true, // is_last_in_slot
        Hash::default(),
        0, // next_shred_index
        0, // next_code_index
        &mut stats,
    );
    if shreds.is_empty() {
        return;
    }

    let Ok(dir) = TempDir::new() else { return };
    let Ok(blockstore) = Blockstore::open(dir.path()) else {
        return;
    };
    // Trusted, so every shred is stored and the slot completes.
    if blockstore
        .insert_shreds(shreds, /*is_trusted:*/ true)
        .is_err()
    {
        return;
    }

    let expected = summarize_entries(&entries);
    let (components, _, _) = blockstore
        .get_slot_component_views_with_shred_info(slot, 0, /*allow_dead_slots:*/ false)
        .unwrap_or_default();
    let replayed = summarize_views(&components);
    assert_eq!(
        replayed,
        expected,
        "replay decoder mismatch at slot {slot}: {} entries read back, {} shredded",
        replayed.len(),
        expected.len(),
    );
    let rpc = blockstore.get_slot_entries(slot, 0).unwrap_or_default();
    assert_eq!(
        rpc,
        entries,
        "RPC decoder mismatch at slot {slot}: {} entries read back, {} shredded",
        rpc.len(),
        entries.len(),
    );
});
