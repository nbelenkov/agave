//! Fast-leader-handover generation harness as a fuzz target: the input bytes are a program over
//! the discard paths (see `solana_core::replay_stage::generation_harness`), and any oracle
//! finding that does not match a known open case is a crash.

#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    solana_core::replay_stage::generation_harness::{Program, run_program},
    std::collections::BTreeSet,
};

fuzz_target!(|data: &[u8]| {
    let program = Program::from_bytes(data);
    let unknown: Vec<_> = run_program(&program)
        .into_iter()
        .filter(|finding| finding.known.is_none())
        .collect();
    if unknown.is_empty() {
        return;
    }
    // The fleet keys a crash on the panic message's last non-structural line, normalized, plus the
    // panic location and the top stack frames, and it treats a new key as a new crash: enough new
    // ones in an hour and it stops the target as a broken build. So the title, one cell name and
    // nothing else, is the last line; it is also the first, which is what a person reads. Cells are
    // a fixed vocabulary, so one bug keeps one key however many programs reach it, and a program
    // that trips several does not mint a new key per combination. Everything that varies per run
    // (signatures, addresses, which op was last, the other cells) goes in between, where it is read
    // but not keyed on.
    let cells: BTreeSet<&str> = unknown.iter().map(|finding| finding.cell).collect();
    let title = cells
        .iter()
        .next()
        .expect("unknown is not empty, so it has at least one cell");
    let details: Vec<String> = unknown
        .iter()
        .map(|finding| format!("  [{}] {}", finding.cell, finding.detail))
        .collect();
    panic!(
        "{title}\n  cells: {cells:?}\n{}\n  program: {program:?}\n{title}",
        details.join("\n")
    );
});
