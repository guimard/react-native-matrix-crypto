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

if echo "$DIRECT_DEPS" | grep -qx 'uniffi'; then
  echo "FAIL: matrix-crypto-core has a direct dependency on uniffi."
  echo "      FFI concerns belong in matrix-crypto-ffi. See spec section 4bis.3."
  exit 1
fi

# The core must also be testable with no Node, no simulator, no Turbo Module.
cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml --quiet

echo "PASS: core boundary"
