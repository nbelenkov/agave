#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Total by construction: no indexing past len, no arithmetic that can overflow in release,
    // no panics. See the note in lib.rs on why this target must not crash.
    let _ = ci_test_harness::classify(data);
});
