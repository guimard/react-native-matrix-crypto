#!/usr/bin/env bash
set -euo pipefail

# Cargo workspace resolves and contains the core crate.
cargo metadata --format-version 1 --no-deps --manifest-path rust/Cargo.toml \
  | grep -q '"name":"matrix-crypto-core"' \
  || { echo "FAIL: matrix-crypto-core not in cargo workspace"; exit 1; }

# yarn workspace root is declared and private.
node -e '
  const p = require("./package.json");
  if (p.private !== true) { console.error("FAIL: root package.json must be private"); process.exit(1); }
  if (!Array.isArray(p.workspaces)) { console.error("FAIL: root package.json must declare workspaces"); process.exit(1); }
'

echo "PASS: workspaces"
