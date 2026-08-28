#!/usr/bin/env bash
set -euo pipefail

# Make codegen output independent of what happens to be installed on the
# machine running it.
#
# ubrn formats its emitted C++ with `clang-format` and its TypeScript with
# `prettier` when it finds them, and silently skips formatting when it does
# not. assert-no-drift.sh already warned against adding either as a
# devDependency for this reason, but a devDependency was never the only
# vector: GitHub's ubuntu-latest image ships clang-format system-wide while
# a stock macOS developer machine does not. The same commit therefore
# generated differently formatted C++ in CI than locally, and the drift gate
# failed on pure whitespace -- `jsi::Runtime &rt` against `jsi::Runtime& rt`,
# two-space against four-space indentation -- with nothing semantically
# different at all.
#
# How ubrn actually behaves, read from its source rather than guessed
# (node_modules/uniffi-bindgen-react-native/crates/ubrn_common/src/fmt.rs):
#
#   - It locates clang-format with `which`, so PATH decides, and invokes it
#     IN PLACE: `clang-format -i --style=file --fallback-style=LLVM <files>`.
#     With no .clang-format in the tree it therefore applies LLVM style.
#   - It resolves prettier from `node_modules/.bin/prettier`, NOT from PATH.
#     PATH cannot influence prettier at all; the only guard against it is the
#     one assert-no-drift.sh already documents, namely not adding it as a
#     devDependency.
#
# So: shadow clang-format with an inert stand-in, first on PATH. `which`
# finds it, ubrn runs it, and because the real invocation is in-place rather
# than a pipe, doing nothing leaves the files exactly as generated. This is
# deliberately NOT the PATH-directory-scrubbing the cold-consume job uses:
# on ubuntu-latest clang-format lives in /usr/bin alongside `cc`, so removing
# whole directories takes the linker with it and cargo fails to build.
_fmt_shim="$(mktemp -d)"
trap 'rm -rf "$_fmt_shim"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$_fmt_shim/clang-format"
chmod +x "$_fmt_shim/clang-format"
PATH="$_fmt_shim:$PATH"
export PATH

if [ "$(command -v clang-format)" != "$_fmt_shim/clang-format" ]; then
  echo "FAIL: clang-format does not resolve to the inert stand-in;" >&2
  echo "      codegen output would depend on the host's formatter." >&2
  exit 1
fi

# Regenerates the UniFFI/JSI bindings from the Rust FFI crate. Invoked via
# `yarn codegen` from this package's directory (packages/react-native-matrix-crypto/),
# so every relative path below is relative to there.
#
# This is THREE separate ubrn invocations, not the single
# `ubrn generate jsi turbo-module` command the walking-skeleton plan
# originally assumed. Each step below exists for a specific, empirically-
# confirmed reason -- see task-5-report.md ("Surprise 2" and "Surprise 3")
# for the full investigation. Do not collapse this back to a one-liner:
# doing so does not error, it just silently emits empty stub files while
# scripts/assert-no-drift.sh keeps passing, because it would be diffing two
# equally-broken generations against each other.

# Step 1: build the FFI crate for the HOST platform (no cross-compilation).
#
# `ubrn generate jsi bindings` (step 2) reads UniFFI's metadata out of a
# compiled artifact from the outside, via `goblin`, rather than from source.
# That metadata is identical regardless of target architecture, so a plain
# host `cargo build` is sufficient -- codegen does not need an iOS/Android
# toolchain, only `cargo`.
cargo build --quiet --manifest-path ../../rust/matrix-crypto-ffi/Cargo.toml

# Step 2: generate the raw bindings from that artifact.
#
# Step 3 (`generate jsi turbo-module`) never generates the underlying
# bindings itself -- it only emits code that IMPORTS them by path. Confirmed
# empirically: run step 3 alone against a directory where src/generated/ and
# cpp/generated/ don't exist yet, and it exits 0 without ever creating them.
# ubrn's own docs concur: "In most cases, [generate jsi bindings] should not
# be called directly, but with the build, with --and-generate" -- we call it
# directly anyway, deliberately, to avoid requiring a full iOS/Android build
# toolchain in CI just to keep committed text files in sync with the Rust
# source.
(
  cd ../../rust/matrix-crypto-ffi
  ubrn generate jsi bindings ../target/debug/libmatrix_crypto_ffi.a \
    --library \
    --ts-dir ../../packages/react-native-matrix-crypto/src/generated \
    --cpp-dir ../../packages/react-native-matrix-crypto/cpp/generated
)

# Step 3: generate the turbo-module scaffold, wired to the bindings above.
#
# `matrix_crypto` MUST be passed as a positional namespace argument -- it is
# the UniFFI namespace from `uniffi::setup_scaffolding!("matrix_crypto")` in
# rust/matrix-crypto-ffi/src/lib.rs. Omit it and this command still exits 0
# with no error and no warning, but src/index.tsx and the C++ install shim
# come out as EMPTY STUBS: no `export * from './generated/matrix_crypto'`,
# and the native installRustCrate() body is just `return true;` with no JSI
# registration at all. Confirmed empirically.
#
# THIS STEP AND `ubrn build android --targets ... --and-generate` ARE NOT
# INTERCHANGEABLE for android/build.gradle's `abiFilters` list (Task 14).
# `ubrn build android` knows the specific target list it was invoked with and
# computes `abiFilters` from it. This step has no such context -- it always
# falls back to ubrn's default four-ABI Android template (arm64-v8a,
# armeabi-v7a, x86, x86_64), regardless of which Android targets were
# actually built. Whichever command ran LAST determines what a plain `git add`
# would capture for that one file, and only `scripts/assert-no-drift.sh` (which
# calls this script, never `ubrn build android` directly) is authoritative for
# what must be committed. Confirmed empirically: running this step twice in a
# row after `ubrn build android --targets <subset> --and-generate` deterministically
# restores the full four-ABI list and produces zero further diff either time --
# so THIS SCRIPT's output, not a full platform build's, is the canonical one.
# Consequence: `scripts/assert-no-drift.sh` MUST be the last step run before any
# commit that touches Android artifacts, including one made right after a real
# `ubrn build android` invocation -- otherwise a commit can silently capture the
# wrong `abiFilters` list, exactly as happened once in Task 14 (caught only
# because the drift gate was re-run as extra diligence, not because anything
# enforced it).
ubrn generate jsi turbo-module matrix_crypto --config ../../ubrn.config.yaml
