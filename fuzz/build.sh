#!/usr/bin/env bash
# Bedlam build recipe (kind = "script"): SRC is the checkout, OUT the bundle to fill. A script
# because the crate is an agave workspace member (binaries land in the workspace target dir),
# agave needs a newer nightly than the builder's, and ASan binaries (~720 MB) only fit bedlam's
# 512 MiB per-binary and 4 GiB bundle caps with DWARF stripped and coverage twins rationed.
set -euo pipefail

: "${SRC:?SRC must name the checkout}"
: "${OUT:?OUT must name the output dir}"

# Agave's pinned nightly: its rust-version is newer than the builder image's nightly.
pin="$(sed -n 's/^nightly = "\(.*\)"/\1/p' "$SRC/ci/rust-nightly-version.toml")"
if [ -z "$pin" ]; then
  echo "build.sh: no nightly pin in $SRC/ci/rust-nightly-version.toml" >&2
  exit 1
fi
NIGHTLY="nightly-$pin"
FUZZ_DIR="$SRC/fuzz"
TARGET_DIR="${SHRED_FUZZ_TARGET_DIR:-$SRC/target/shred-fuzz}"
# Well under bedlam's 4 GiB cap: finalize holds the bundle in memory (about 3.3x the binaries), and a
# fuzzer its smoke starts inherits that peak in getrusage, which libFuzzer's rss limit reads. At 1.09
# GB of binaries the first smoke failed at 3579 MB against the 2048 default before running an input.
BUDGET="${SHRED_FUZZ_BUNDLE_BUDGET:-$((450 * 1024 * 1024))}"
# Bedlam copies the contract it read into OUT; a local run uses the checkout's.
CONTRACT="$OUT/targets.toml"
[ -f "$CONTRACT" ] || CONTRACT="$FUZZ_DIR/targets.toml"

# Bedlam's builder has a read-only rustup home, so the nightly goes beside OUT. RUSTUP_TOOLCHAIN
# keeps the cargo and rustc that cargo-fuzz spawns off the image's pinned nightly.
if [ ! -w "$(rustup show home)" ]; then
  RUSTUP_HOME="$(dirname "$OUT")/rustup"
  export RUSTUP_HOME
fi
rustup toolchain install "$NIGHTLY" --no-self-update --profile minimal \
  --component rust-src,llvm-tools-preview
export RUSTUP_TOOLCHAIN="$NIGHTLY"
TRIPLE="$(rustup run "$NIGHTLY" rustc -vV | sed -n 's/^host: //p')"
RELEASE="$TARGET_DIR/$TRIPLE/release"
STRIP="$(rustup run "$NIGHTLY" rustc --print sysroot)/lib/rustlib/$TRIPLE/bin/llvm-strip"

# "name criticality" for each enabled [[target]].
enabled_targets() {
  awk '
    function flush() { if (name != "" && enabled != "false") print name, crit }
    /^\[\[target\]\]/ { flush(); name = ""; crit = "low"; enabled = "true"; next }
    /^name *=/ { v = $0; gsub(/^[^"]*"|".*$/, "", v); name = v }
    /^criticality *=/ { v = $0; gsub(/^[^"]*"|".*$/, "", v); crit = v }
    /^enabled *=/ { v = $0; gsub(/^[^=]*= *|[ #].*$/, "", v); enabled = v }
    END { flush() }
  ' "$CONTRACT"
}

mapfile -t ROWS < <(enabled_targets)
if [ "${#ROWS[@]}" -eq 0 ]; then
  echo "build.sh: no enabled targets in $CONTRACT" >&2
  exit 1
fi

mkdir -p "$OUT/bin" "$OUT/dict" "$OUT/corpus" "$TARGET_DIR"
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never
cd "$SRC"

# Builds fleet target $1 (cargo bin: - as _), stripped, to $2; extra args go to cargo fuzz.
build_one() {
  local target="$1" dest="$2"
  shift 2
  local bin="${target//-/_}"
  cargo "+$NIGHTLY" fuzz build "$bin" --fuzz-dir "$FUZZ_DIR" --target-dir "$TARGET_DIR" "$@"
  "$STRIP" --strip-debug -o "$dest" "$RELEASE/$bin"
}

total=0
for row in "${ROWS[@]}"; do
  target="${row%% *}"
  build_one "$target" "$OUT/bin/$target"
  total=$((total + $(stat -c %s "$OUT/bin/$target")))
done
if [ "$total" -gt "$BUDGET" ]; then
  echo "build.sh: ASan binaries alone are $total bytes, over the $BUDGET budget" >&2
  exit 1
fi

# Coverage twins rebuild the tree under other RUSTFLAGS into the same release dir, so they come
# last, highest criticality first, while they fit.
candidate="$TARGET_DIR/cov-candidate"
for tier in high medium low; do
  for row in "${ROWS[@]}"; do
    target="${row%% *}"
    [ "${row##* }" = "$tier" ] || continue
    RUSTFLAGS="-C instrument-coverage --cfg fuzzing" \
      build_one "$target" "$candidate" --sanitizer none
    size=$(stat -c %s "$candidate")
    if [ $((total + size)) -gt "$BUDGET" ]; then
      echo "build.sh: bundle budget reached; no coverage twin for $target or later targets"
      break 2
    fi
    mv -- "$candidate" "$OUT/bin/${target}_cov"
    total=$((total + size))
  done
done

cp "$FUZZ_DIR/dicts/shred.dict" "$OUT/dict/shred.dict"
for row in "${ROWS[@]}"; do
  target="${row%% *}"
  seeds="$FUZZ_DIR/seeds/${target//-/_}"
  if [ -d "$seeds" ]; then
    mkdir -p "$OUT/corpus/$target"
    find "$seeds" -maxdepth 1 -type f -exec cp {} "$OUT/corpus/$target/" \;
  fi
done
echo "build.sh: bundle binaries total $total bytes"
