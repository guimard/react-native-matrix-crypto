#!/usr/bin/env bash
set -euo pipefail

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
ubrn generate jsi turbo-module matrix_crypto --config ../../ubrn.config.yaml
