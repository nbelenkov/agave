//! The raw `layout` accessors run on unauthenticated bytes before sigverify: never panic.

#![no_main]

use {libfuzzer_sys::fuzz_target, solana_ledger::shred::layout};

fuzz_target!(|data: &[u8]| {
    let _ = layout::get_shred_type(data);
    let _ = layout::get_slot(data);
    let _ = layout::get_index(data);
    let _ = layout::get_fec_set_index(data);
    let _ = layout::get_flags(data);
    let _ = layout::get_shred_id(data);
    let _ = layout::get_common_header_bytes(data);

    let _ = layout::get_merkle_root(data);
    let _ = layout::is_retransmitter_signed_variant(data);
    let _ = layout::get_retransmitter_signature(data);

    let mut buf = data.to_vec();
    let _ = layout::get_shred_mut(&mut buf);
});
