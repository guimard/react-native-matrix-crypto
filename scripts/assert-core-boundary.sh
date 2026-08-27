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

if echo "$DIRECT_DEPS" | grep -qx 'uniffi'; then
  echo "FAIL: matrix-crypto-core has a direct dependency on uniffi."
  echo "      FFI concerns belong in matrix-crypto-ffi. See spec section 4bis.3."
  exit 1
fi

# The core must also be testable with no Node, no simulator, no Turbo Module.
cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml --quiet

echo "PASS: core boundary"
