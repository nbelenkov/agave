# agave-shred-fuzz

libFuzzer targets for the Agave shred pipeline: wire parsing, the fetch-stage
filter, sigverify, erasure recovery, blockstore ingestion and replay
consumption. The crate is a member of the agave workspace, so every dependency
is the in-tree version. Agave itself carries two `dev-context-only-utils`
helpers in `ledger/src/shred/merkle.rs` that the mutate-then-reseal targets
need: `finish_erasure_batch_for_tests` (made `pub`) and
`reseal_erasure_batch_for_tests` (re-sign without re-encoding, so byte-level
faults survive in a leader-signed set).

## Targets

| Target | Drives | Oracles |
|---|---|---|
| `shred_layout` | `shred::layout::*` on raw bytes | never-panic (pre-sigverify, any peer) |
| `shred_parse` | `new_from_serialized_shred`, `sanitize`, accessors | never-panic |
| `shred_sigverify` | `verify_shred_cpu` | genuine verifies; tampered signature or signed root rejected; raw accessors agree with the parse |
| `shred_filter_packet` | `should_discard_packet` (turbine mode, repair nonce) | packet path never accepts what the shred filter rejects; nonce round-trip |
| `shred_filter_rules` | `should_discard_shred` on byte-faulted shreds, raw as the fetch stage sees them (no parse, no re-sign) | discards every shred breaking R1-R10, an independent restatement of the filter rules including the gated SIMD-0504 position and SIMD-0317 proof/data size rules; a coding shred with only its position moved is discarded exactly when SIMD-0504 is effective for its slot, on both sides of the activation boundary |
| `shred_recover` | `ShredRecoveryContext::recover` over an honest set, a set with a malformed data shred re-encoded into its coding shreds, and a set with corrupted parity | reconstruction is byte-identical; recovery never emits a shred the network filter rejects or a misplaced DATA_COMPLETE; every recovered shred verifies against the leader |
| `shred_ingest_sim` | `insert_shreds_handle_duplicate` driven by a multi-slot action script | I1-I11: metadata, chaining, stored shreds pass the filter, exists accounting with no false duplicate proofs, equivocation flagged and the slot then dead unless full, replay and RPC decoders agree, bounded state growth and recovery work |
| `shred_fec_verdict` | one leader-signed FEC set (any set of a block, full or partial, plain or legacy resigned), optionally faulted (including a mixed resigned/plain set), through blockstore under two schedules that reorder, batch and withhold shreds (data-only sets included), and with mixed signatures | SIMD-0504 Family 2: an honest set never fails the checks or kills its slot; a non-canonical set (by an independent restatement of the rules) fails them and, gated, kills the slot; the verdict ignores arrival order and which 32+ shreds arrive; gated, mixed signatures change nothing and raise no duplicate proof, ungated they fail the rebuild and raise `PayloadConflict` |
| `shred_parent_markers` | a slot of real `BlockComponent`s with a header and up to two `UpdateParent` markers, through blockstore under two schedules (one recovering marker shreds) | dead iff the markers break the insert-time rules (restated); a live slot records the effective parent and replay start; the outcome ignores arrival order; a complete slot's block id (double Merkle root) equals a recomputation over its FEC-set roots and effective parent; the markers replay decodes match what blockstore recorded |
| `shred_block_roundtrip` | entries -> shreds -> blockstore -> both block decoders | replay's decoder (`get_slot_component_views_with_shred_info`) and RPC's (`get_slot_entries`) each return the shredded entries |

## Feature gates

The bank-backed targets take a fuzzed `Gates` value and run against one of
eight cached banks: SIMD-0317 (`enforce_correct_proof_size`) and SIMD-0504
(`stricter_shred_validation`) each on or off, with the root either two epochs
past activation or at the activation slot itself. Both gates off is mainnet as
of 2026-11-08; the code does not enforce that 0317 activates first, so every
combination is reachable. At the activation slot, the shred slots a harness
picks straddle the first effective slot (shred gates take effect one epoch
after activation), and the harness computes that slot itself rather than
reusing the filter's helper, so an off-by-one there is caught. The banks use
400ms ticks so the live SIMD-0525 slot-time caps apply.

## Building and running

Use agave's pinned nightly (`ci/rust-nightly-version.toml`, which `build.sh`
reads; the builder image's is older than agave's rust-version):

```sh
cargo +nightly-2026-08-16 fuzz build shred_filter_rules --fuzz-dir fuzz
ASAN_OPTIONS=detect_leaks=0 \
  target/<host triple>/release/shred_filter_rules corpus/ -max_total_time=300
```

Run every target with `ASAN_OPTIONS=detect_leaks=0`: the blockstore and banks
persist across inputs on purpose. `SHRED_FUZZ_FRESH=1` gives every input its own blockstore, which
is the mode to replay a crash in.

## Bedlam

`targets.toml` is the bedlam contract and `build.sh` its build recipe
(`kind = "script"`; the header of `build.sh` says why). Bedlam's allowlist reads
the contract for `nbelenkov/agave` at `core/fuzz/targets.toml` (the FLH fuzz
branch keeps its contract there), so this branch carries a symlink to this one
at that path. Seeds committed under `seeds/<cargo bin>/` are shipped as
each target's starting corpus. For the four blockstore targets they are the 200
smallest inputs of a minimal merge: bedlam's 20 s build smoke runs libFuzzer
`-fork`, whose parent executes every seed before the first job starts, and
fails the build if no job has reported within 80 s.

The builder pins an older nightly and keeps it on a read-only root filesystem,
so `build.sh` installs its own nightly into `rustup/` beside the bundle when
the default rustup home is not writable. Each push of `shred-fuzz-v2` to the
fork requests a build (`.github/workflows/request-build.yml`, using the fork's
`fuzz` environment); re-run the workflow to request the same commit again, or
by hand:

```sh
bedlamctl request-build -repo nbelenkov/agave -commit <40-hex sha> -kind publish
```

## Triage

Classify a crash by who can deliver the input before reporting it:

- `shred_layout`, `shred_parse`, `shred_filter_packet`, `shred_sigverify`
  (raw mode): any peer, before signature verification.
- `shred_filter_rules`: any peer (the filter runs before sigverify), with
  consequence when a leader sends it.
- Leader-signed faulted sets (`shred_recover`, `shred_fec_verdict`,
  `shred_ingest_sim`, `shred_parent_markers`): a byzantine slot leader.
- `shred_block_roundtrip`: our own encoder or decoder.
