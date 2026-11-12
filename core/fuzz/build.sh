#!/usr/bin/env bash
# The bedlam build service's recipe for this crate (`[build] kind = "script"` in targets.toml). The
# service runs it with SRC (the checkout at the requested commit) and OUT (the bundle layout) set,
# with no credentials and a read-only root filesystem, and takes what it leaves in OUT/bin.
#
# It builds with the tree's pinned nightly, not the build image's: the workspace's rust-version is
# newer than the image's nightly, which the default cargo-fuzz recipe would use. The fuzz crate is a
# member of the dev-bins workspace, so the output directory is set with --target-dir rather than
# assumed to be under core/fuzz. It also ships the few committed seeds in seeds/ (see the end).
set -euo pipefail

: "${SRC:?SRC must name the checkout}"
: "${OUT:?OUT must name the bundle layout directory}"

readonly fuzz_dir="core/fuzz"
readonly cargo_target="flh_generation"
readonly target_name="agave-flh-generation"

pin="$(sed -n 's/^nightly = "\(.*\)"/\1/p' "$SRC/ci/rust-nightly-version.toml")"
if [[ -z "$pin" ]]; then
  echo "no nightly pin in $SRC/ci/rust-nightly-version.toml" >&2
  exit 1
fi
readonly toolchain="nightly-$pin"

work="$(dirname "$OUT")"
readonly target_dir="$work/target"
# The image's toolchains are read-only, so the tree's goes under the work dir. RUSTUP_TOOLCHAIN,
# which the image sets to its own nightly, then names the tree's for everything cargo runs.
export RUSTUP_HOME="$work/rustup"
export RUSTUP_TOOLCHAIN="$toolchain"
mkdir -p "$RUSTUP_HOME" "$OUT/bin"

echo "==> toolchain $toolchain"
# --no-self-update: rustup otherwise probes its own bin directory, which is read-only in the image.
rustup toolchain install --profile minimal --no-self-update "$toolchain"
host="$(rustc +"$toolchain" -vV | sed -n 's/^host: //p')"
readonly release="$target_dir/$host/release"

cd "$SRC"
echo "==> $cargo_target with ASan"
cargo +"$toolchain" fuzz build "$cargo_target" --fuzz-dir "$fuzz_dir" --target-dir "$target_dir"
cp "$release/$cargo_target" "$OUT/bin/$target_name"

# The coverage twin: instrumented, no sanitizer. It lands at the same path, so it is built after
# the ASan binary has been copied out.
echo "==> $cargo_target coverage twin"
RUSTFLAGS="-C instrument-coverage --cfg fuzzing" \
  cargo +"$toolchain" fuzz build "$cargo_target" --fuzz-dir "$fuzz_dir" \
  --target-dir "$target_dir" --sanitizer none
cp "$release/$cargo_target" "$OUT/bin/${target_name}_cov"

# bedlam caps a bundle member at 512 MiB, and the line tables are most of the ASan binary (629 MB,
# 108 MB without). Function names stay in .symtab and the twin keeps its __llvm_cov* sections.
strip --strip-debug "$OUT/bin/$target_name" "$OUT/bin/${target_name}_cov"

# A new corpus lineage (a `corpus_format` bump, or the first build under a new repo) starts from
# these; on a routine build they union into the corpus the fleet already has, by content hash.
# Kept to a handful: the platform's smoke run merges every seed first, at about one program a
# second under ASan, before it fuzzes. `FLH_CORPUS_SEEDS=16` with `write_seed_corpus` makes them.
mkdir -p "$OUT/corpus/$target_name"
cp "$SRC/$fuzz_dir/seeds/"* "$OUT/corpus/$target_name/"
