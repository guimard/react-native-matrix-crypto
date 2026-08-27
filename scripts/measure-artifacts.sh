#!/usr/bin/env bash
set -euo pipefail

# Spec section 10: artifact size decides whether binaries can ship inside the
# npm tarball at all. Record it rather than guess at it.
size_of() {
  [ -e "$1" ] && du -sk "$1" | cut -f1 || echo 0
}

XC=$(find packages -name '*.xcframework' -maxdepth 4 | head -1)
AAR=$(find packages -name '*.aar' -maxdepth 5 | head -1)

XC_KB=$(size_of "${XC:-/nonexistent}")
AAR_KB=$(size_of "${AAR:-/nonexistent}")

# `npm pack --dry-run --json` output shape is not stable across npm versions:
# some print a top-level ARRAY (`[{...}]`, `j[0]` below), but npm 12.0.2
# (confirmed empirically in this environment) prints a top-level OBJECT keyed
# by package name (`{"react-native-matrix-crypto": {...}}`). Indexing that
# shape with `j[0]` silently resolves to `undefined`, and `size ?? 0` then
# reports a tarball of exactly 0 KB -- no error, just a wrong number that
# looks like a real measurement. Handle both shapes explicitly rather than
# assume one.
TARBALL_KB=$(cd packages/react-native-matrix-crypto && npm pack --dry-run --json 2>/dev/null \
  | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); const entry=Array.isArray(j)?j[0]:Object.values(j)[0]; console.log(Math.round((entry?.size??0)/1024))')

node -e "
  const fs = require('fs');
  const row = {
    label: process.argv[1],
    xcframeworkKB: Number(process.argv[2]),
    aarKB: Number(process.argv[3]),
    tarballKB: Number(process.argv[4]),
  };
  const path = 'artifact-sizes.json';
  const all = fs.existsSync(path) ? JSON.parse(fs.readFileSync(path,'utf8')) : [];
  all.push(row);
  fs.writeFileSync(path, JSON.stringify(all, null, 2));
  console.log(JSON.stringify(row));
" "${1:-unlabelled}" "$XC_KB" "$AAR_KB" "$TARBALL_KB"
