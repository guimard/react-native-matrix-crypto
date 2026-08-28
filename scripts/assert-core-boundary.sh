#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3: all logic lives in matrix-crypto-core, which must
# therefore never depend on uniffi directly. A transitive uniffi is fine;
# a direct one means FFI concerns have leaked into the core.
DIRECT_DEPS=$(cargo metadata --format-version 1 --no-deps \
  --manifest-path rust/Cargo.toml \
  | node -e '
      const m = JSON.parse(require("fs").readFileSync(0, "utf8"));
      const core = m.packages.find(p => p.name === "matrix-crypto-core");
      if (!core) { console.error("matrix-crypto-core not found"); process.exit(2); }
      console.log(core.dependencies.map(d => d.name).join("\n"));
    ')

# Refuse to pass having scanned nothing.
#
# The Node step above already exits 2 when the crate itself is missing, so a
# renamed or moved crate cannot slip through. What it does not distinguish is
# an empty dependency list from a working scan that found no `uniffi`: both
# reach the grep below and both pass. `matrix-crypto-core` has dependencies,
# so an empty list means the extraction broke, not that the boundary holds.
#
# This gap was found twice by reasoning about the script and got the wrong
# answer both times, then settled by feeding the extraction synthetic empty
# input and watching it pass. Sibling gates carry the same guard.
if [ -z "${DIRECT_DEPS//[[:space:]]/}" ]; then
  echo "FAIL: refusing to pass having scanned nothing."
  echo "      matrix-crypto-core reported zero direct dependencies, which means"
  echo "      the extraction broke rather than that the boundary holds."
  exit 1
fi

# The whole uniffi family, not the single crate named `uniffi`.
#
# This was `grep -qx 'uniffi'`, which is a whole-line match on the package
# name -- correct as far as it went, and it went one crate. `uniffi_core`
# added as a direct dependency of matrix-crypto-core passed: constructed
# 2026-08-28, `cargo metadata --no-deps` listed it among the core's direct
# dependencies, and the gate printed "PASS: core boundary". `uniffi_core` and
# `uniffi_macros` bring exactly the concerns section 4bis.3 keeps out of the
# core -- RustBuffer, the call-status ABI, the export macros -- so the check
# now matches the family and the README's "no direct uniffi dependency" is
# true of all of it.
#
# Still anchored at both ends: a crate merely CONTAINING "uniffi" in its name
# is not matched, only `uniffi` itself and `uniffi-*` / `uniffi_*`.
if echo "$DIRECT_DEPS" | grep -qxE 'uniffi([-_][A-Za-z0-9_-]*)?'; then
  echo "FAIL: matrix-crypto-core has a direct dependency on uniffi:"
  echo "$DIRECT_DEPS" | grep -xE 'uniffi([-_][A-Za-z0-9_-]*)?' | sed 's/^/        /'
  echo "      FFI concerns belong in matrix-crypto-ffi. See spec section 4bis.3."
  echo "      A transitive uniffi is fine; a direct one is not, and that holds"
  echo "      for uniffi_core and uniffi_macros as much as for uniffi itself."
  exit 1
fi

# The core must also be testable with no Node, no simulator, no Turbo Module.
cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml --quiet

echo "PASS: core boundary"
