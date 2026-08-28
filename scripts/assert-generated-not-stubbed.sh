#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3, the half gate:drift cannot cover.
#
# gate:drift proves the committed generated code MATCHES the Rust source. It
# cannot prove the committed generated code is USABLE, because it compares one
# generation against another: two equally-broken generations diff to nothing.
# This gate asserts, from file content alone, that the turbo module those
# artifacts describe is actually wired up.
#
# It exists because of a reproduced failure, not a hypothetical one.
# `ubrn build android --targets <t> --release --and-generate` -- which the CI
# build jobs ran -- exits 0, prints no warning, and rewrites two files into
# stubs:
#
#   * src/index.tsx loses `export * from './generated/matrix_crypto'`, its
#     `import * as matrix_crypto`, and the `matrix_crypto.default.initialize()`
#     call. Its default export becomes `{}`.
#   * cpp/react-native-matrix-crypto.cpp loses
#     `#include "generated/matrix_crypto.hpp"` and its
#     `NativeMatrixCrypto::registerModule(...)` call, leaving
#     `installRustCrate()` as a bare `return true;`.
#
# Neither file ends up empty -- they keep ~1.1 KB and ~330 B of intact
# comments and scaffolding -- so a size check alone does not see it. An app
# built on that output loads and then fails every native call.
#
# Reproduced 2026-08-28 against ubrn 0.31.0-5, on a copy of the tree, with the
# committed ubrn.config.yaml.
#
# Root cause, and it is Android-only: `--and-generate` re-derives the UniFFI
# module list from the artifact it just built. ubrn.config.yaml sets
# `android.useSharedLibrary: true`, so on Android that artifact is the cdylib
# (`libmatrix_crypto_ffi.so`) rather than the static archive. UniFFI's ELF
# extraction reads `.symtab`, and the cdylib exports its metadata through
# `.dynsym` only, so the module list comes back EMPTY -- and both files above
# are rendered from templates that loop over that list. Verified from the
# other side in the same session: `ubrn build ios ... --and-generate` feeds
# the `.a`, finds its modules, and regenerates output byte-identical to what
# is committed.
#
# Same shape of failure as ubrn's namespace-less `generate jsi turbo-module`,
# documented as "Surprise 3" in
# packages/react-native-matrix-crypto/scripts/codegen.sh, reached from a
# different direction.
#
# Content-based on purpose: this has to be runnable in the build jobs
# immediately after their build step, where gate:drift cannot run. Those jobs
# legitimately rewrite android/build.gradle's abiFilters for the subset of
# targets they build (see codegen.sh's step 3 comment), so a diff against the
# committed tree would fail there for a reason that is not a defect.

PKG=packages/react-native-matrix-crypto

# --- What namespace are we asserting about? ----------------------------------
#
# Derived from the Rust source rather than hardcoded, so a renamed UniFFI
# namespace fails loudly here instead of silently checking for a name nothing
# emits any more. This is the first of this gate's three "refuse to pass having
# scanned nothing" guards -- the same guard assert-no-logger.sh,
# assert-facade-agility.sh and assert-core-boundary.sh all carry.
FFI_LIB=rust/matrix-crypto-ffi/src/lib.rs
if [ ! -f "$FFI_LIB" ]; then
  echo "FAIL: '$FFI_LIB' does not exist."
  echo "      The gate cannot pass over a target that is not there --"
  echo "      if the FFI crate moved, update this path deliberately."
  exit 1
fi

# awk rather than `sed ... | head -1`: `head` closing the pipe early makes the
# pipeline fail under `set -o pipefail`, and a failed command substitution in
# an assignment aborts under `set -e`. Every scan below avoids pipes into an
# early-exiting reader for the same reason -- one of them silently dropped the
# two largest artifacts out of the scan before this was fixed.
NAMESPACE=$(awk '
  match($0, /uniffi::setup_scaffolding!\("[A-Za-z0-9_]+"\)/) {
    s = substr($0, RSTART, RLENGTH)
    sub(/.*\("/, "", s)
    sub(/"\).*/, "", s)
    print s
    exit
  }
' "$FFI_LIB")
if [ -z "$NAMESPACE" ]; then
  echo "FAIL: refusing to pass having scanned nothing."
  echo "      No uniffi::setup_scaffolding!(\"...\") namespace was found in"
  echo "      $FFI_LIB, so there is no name to assert the generated code is"
  echo "      wired to."
  exit 1
fi

# --- Which artifacts are we asserting about? ---------------------------------
#
# Committed files only: the build jobs run this on a tree that also holds
# gradle/CMake output carrying the same header (e.g.
# android/build/intermediates/.../proguard.txt), and none of that is an
# artifact anyone ships or reviews.
#
# The enumeration used to live here, selecting files by the tool's own header
# in their first 3 lines. It now comes from scripts/generated-file-set.sh,
# which requires that header oracle and scripts/generated-paths.txt to agree
# in both directions before it will answer at all. That is not a refactor: it
# is the fix for a hole this gate had.
#
# THE HOLE. Hollowing a non-required artifact WITH its header intact failed,
# correctly, on the check below. Hollowing the same artifact and also
# STRIPPING its header passed -- because the file then stopped being
# enumerated at all, and the set silently went 19 -> 18. Reproduced on
# ios/MatrixCrypto.mm, both directions, 2026-08-28. The edit that hollows the
# file was the same edit that disarmed the check meant to catch it, and the
# only floor was zero. The cross-check catches it from the other side: the
# file is still under a listed generated path, so it is still expected to
# carry the header, and its absence is now a failure with its own message.
GENERATED=$(./scripts/generated-file-set.sh)

if [ -z "${GENERATED//[[:space:]]/}" ]; then
  echo "FAIL: refusing to pass having scanned nothing."
  echo "      scripts/generated-file-set.sh named no committed generated file,"
  echo "      which means the enumeration broke rather than that the generated"
  echo "      code is fine."
  exit 1
fi

# And a floor above zero, pinned rather than printed.
#
# The count was reported on success and compared with nothing, so a set that
# shrank said so in a passing log and nowhere else. Same discipline as
# run-probe-on-emulator.sh's hardcoded `PROBE_SUMMARY 12/12`: when the Rust
# surface grows an artifact, CI fails until someone comes here and changes
# this number on purpose.
EXPECTED_ARTIFACTS=19

ARTIFACT_COUNT=$(printf '%s\n' "$GENERATED" | grep -c .)
if [ "$ARTIFACT_COUNT" -ne "$EXPECTED_ARTIFACTS" ]; then
  echo "FAIL: $ARTIFACT_COUNT committed generated artifacts, but this gate"
  echo "      expects exactly $EXPECTED_ARTIFACTS."
  printf '%s\n' "$GENERATED" | sed 's/^/        /'
  echo "      A set that changed size is either a real change to what the"
  echo "      generator emits -- in which case update EXPECTED_ARTIFACTS here,"
  echo "      deliberately -- or an artifact that quietly left the tree."
  exit 1
fi

# --- Nothing generated may be reduced to its own header ----------------------
#
# The generic half: every artifact must still carry something past the header
# that identifies it. Catches a truncated, emptied or header-only file
# anywhere in the set -- including the ten artifacts this gate knows nothing
# else about, such as ios/MatrixCrypto.mm and android/cpp-adapter.cpp.
#
# The floor is one non-blank line after line 3, which is what the smallest
# real artifact in the set has (android/proguard-rules.pro). Deliberately not
# a byte threshold: the observed stub failure leaves files over a kilobyte.
HOLLOW=""
for f in $GENERATED; do
  if ! awk '
    NR > 3 && /[^[:space:]]/ { found = 1; exit }
    END { exit(found ? 0 : 1) }
  ' "$f"; then
    HOLLOW="${HOLLOW:+$HOLLOW
}$f"
  fi
done
if [ -n "$HOLLOW" ]; then
  echo "FAIL: a committed generated artifact is empty or holds nothing but its"
  echo "      own header:"
  echo "$HOLLOW"
  echo "      Regenerate with 'yarn --cwd $PKG codegen' and commit the result."
  exit 1
fi

# --- The turbo module must actually be wired to the bindings -----------------
#
# The five files the observed stub failure touches or points at. Each is
# checked in its own right, with a distinct message per cause, rather than
# being left to the enumeration above: a required file that is missing,
# emptied, untracked or no longer generated-looking would simply drop out of
# $GENERATED, and a set that silently shrank is exactly the shape of failure
# this gate exists to refuse.
TS_ENTRY="$PKG/src/index.tsx"
CPP_SHIM="$PKG/cpp/react-native-matrix-crypto.cpp"
REQUIRED=(
  "$TS_ENTRY"
  "$CPP_SHIM"
  "$PKG/src/generated/$NAMESPACE.ts"
  "$PKG/cpp/generated/$NAMESPACE.hpp"
  "$PKG/cpp/generated/$NAMESPACE.cpp"
)

for f in "${REQUIRED[@]}"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: required generated artifact '$f' does not exist."
    echo "      Regenerate with 'yarn --cwd $PKG codegen' and commit the result."
    exit 1
  fi
  if ! grep -q '[^[:space:]]' "$f"; then
    echo "FAIL: required generated artifact '$f' is empty."
    echo "      Regenerate with 'yarn --cwd $PKG codegen' and commit the result."
    exit 1
  fi
  # Pure-bash membership test, again to keep an early-exiting reader out of a
  # pipeline: $GENERATED is newline-separated, so bracket the haystack and the
  # needle with newlines and match the whole line.
  if [[ $'\n'"$GENERATED"$'\n' != *$'\n'"$f"$'\n'* ]]; then
    echo "FAIL: required generated artifact '$f' is not a committed, generated"
    echo "      file: it is either untracked by git or no longer carries the"
    echo "      uniffi-bindgen-react-native header in its first 3 lines."
    echo "      Never hand-write it -- regenerate with"
    echo "      'yarn --cwd $PKG codegen' and commit the result."
    exit 1
  fi
done

# Whitespace-tolerant on purpose: ubrn runs clang-format on its C++ when it
# finds one on PATH, so the same commit is formatted differently on a runner
# that ships clang-format (ubuntu) than on one that does not (stock macOS).
# assert-no-drift.sh handles that by shimming the formatter away; this gate
# has to read whatever the build job actually left behind, formatted either
# way.
if ! grep -qE "export[[:space:]]+\*[[:space:]]+from[[:space:]]*['\"]\./generated/${NAMESPACE}['\"]" "$TS_ENTRY"; then
  echo "FAIL: $TS_ENTRY does not re-export ./generated/$NAMESPACE."
  echo "      This is the stubbed turbo module: the package would load and then"
  echo "      export none of the bindings."
  echo "      Regenerate with 'yarn --cwd $PKG codegen'. Do not build with"
  echo "      'ubrn build android ... --and-generate'."
  exit 1
fi

if ! grep -qE "${NAMESPACE}\.default\.initialize\(\)" "$TS_ENTRY"; then
  echo "FAIL: $TS_ENTRY never calls $NAMESPACE.default.initialize()."
  echo "      The bindings' checksums and callbacks would never be installed."
  echo "      Regenerate with 'yarn --cwd $PKG codegen'. Do not build with"
  echo "      'ubrn build android ... --and-generate'."
  exit 1
fi

if ! grep -qE "#include[[:space:]]*\"generated/${NAMESPACE}\.hpp\"" "$CPP_SHIM"; then
  echo "FAIL: $CPP_SHIM does not include generated/$NAMESPACE.hpp."
  echo "      This is the stubbed install shim."
  echo "      Regenerate with 'yarn --cwd $PKG codegen'. Do not build with"
  echo "      'ubrn build android ... --and-generate'."
  exit 1
fi

if ! grep -qE "registerModule[[:space:]]*\(" "$CPP_SHIM"; then
  echo "FAIL: $CPP_SHIM never registers a module with JSI."
  echo "      installRustCrate() would return true having installed nothing,"
  echo "      and every native call from JS would fail at runtime."
  echo "      Regenerate with 'yarn --cwd $PKG codegen'. Do not build with"
  echo "      'ubrn build android ... --and-generate'."
  exit 1
fi

# --- The bindings must still carry the whole exported surface ----------------
#
# The checks above prove index.tsx points AT the bindings. This one proves
# there is something behind the pointer: every function the FFI crate exports
# has to appear in the generated TypeScript. Derived from the Rust source, so
# it grows with the surface instead of rotting against a hardcoded list, and it
# is the third "scanned nothing" guard -- an extraction that yields no names
# fails rather than trivially passing.
#
# Only the bare `#[uniffi::export]` attribute on a free function is collected:
# the trait form (`#[uniffi::export(with_foreign)] pub trait ...`) generates an
# interface, not a function of the same name.
EXPORTED=$(awk '
  /^#\[uniffi::export\]$/ { armed = 1; next }
  armed && /^pub (async )?fn [a-z0-9_]+/ {
    name = $0
    sub(/^pub (async )?fn /, "", name)
    sub(/[^a-z0-9_].*$/, "", name)
    print name
  }
  { armed = 0 }
' "$FFI_LIB")

if [ -z "${EXPORTED//[[:space:]]/}" ]; then
  echo "FAIL: refusing to pass having scanned nothing."
  echo "      No #[uniffi::export] function was found in $FFI_LIB, so there is"
  echo "      no exported surface to look for in the generated bindings."
  exit 1
fi

# UniFFI renames snake_case Rust functions to camelCase TypeScript ones.
#
# EXPORTED, not merely MENTIONED. This was `grep -qwF "$camel"` over the whole
# file, which a comment satisfies: the bindings reduced to their 3-line header
# plus one comment line listing all eleven camelCase names passed this gate
# outright, 19 artifacts and all (reproduced 2026-08-28). The file was four
# lines long and every check here was happy. What has to be true is that the
# name is DECLARED and EXPORTED, so the pattern anchors on the export keyword
# and a declaration keyword.
#
# Whitespace-tolerant in the same spirit as the greps above, since this gate
# reads whatever a build job left behind. `export const` and `export let` are
# accepted alongside `function` because ubrn renders some of the surface as
# consts (every generated record type is an `export const`), and a future
# non-async free function would be `export function`.
MISSING=""
for name in $EXPORTED; do
  camel=$(echo "$name" | awk -F_ '{ out=$1; for (i=2;i<=NF;i++) out = out toupper(substr($i,1,1)) substr($i,2); print out }')
  if ! grep -qE "^[[:space:]]*export[[:space:]]+(async[[:space:]]+)?(function|const|let|var)[[:space:]]+${camel}\b" \
      "$PKG/src/generated/$NAMESPACE.ts"; then
    MISSING="${MISSING:+$MISSING
}$name -> $camel"
  fi
done
if [ -n "$MISSING" ]; then
  echo "FAIL: the generated TypeScript bindings do not EXPORT every function"
  echo "      exported from $FFI_LIB:"
  echo "$MISSING"
  echo "      A name appearing in a comment does not count; the binding has to"
  echo "      be declared and exported."
  echo "      Regenerate with 'yarn --cwd $PKG codegen' and commit the result."
  exit 1
fi

echo "PASS: generated code is not stubbed ($ARTIFACT_COUNT artifacts, asserted,"
echo "      namespace '$NAMESPACE')"
