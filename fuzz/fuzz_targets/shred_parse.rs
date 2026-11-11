//! Parse, accessors and `sanitize` on untrusted bytes: never panic.

#![no_main]

use {libfuzzer_sys::fuzz_target, solana_ledger::shred::Shred};

fuzz_target!(|data: &[u8]| {
    let Ok(shred) = Shred::new_from_serialized_shred(data.to_vec()) else {
        return;
    };

    let _ = shred.id();
    let _ = shred.slot();
    let _ = shred.index();
    let _ = shred.fec_set_index();
    let _ = shred.shred_type();
    let _ = shred.is_data();
    let _ = shred.parent();
    let _ = shred.signature();
    let _ = shred.last_in_slot();
    let _ = shred.merkle_root();
    let _ = shred.chained_merkle_root();
    let _ = shred.payload();

    let _ = shred.sanitize();
});
