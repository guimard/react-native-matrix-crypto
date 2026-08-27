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
# some print a top-level ARRAY (`[{...}]`), but npm 12.0.2 (confirmed
# empirically in this environment) prints a top-level OBJECT keyed by package
# name (`{"react-native-matrix-crypto": {...}}`). Indexing that shape with
# `j[0]` silently resolves to `undefined`, and `size ?? 0` then reports a
# tarball of exactly 0 KB -- no error, just a wrong number that looks like a
# real measurement. Handle both shapes explicitly rather than assume one.
#
# `tarballKB` only means what the M1b size gate (spec section 10, ~150 MB)
# assumes it means once whatever binaries exist on disk actually reach the
# packed tarball -- and that is *not* guaranteed just because they are on
# disk. It requires package.json's "files" allowlist to name them, which,
# once, it did not: `*.xcframework`/`*.aar` were absent from "files", so
# `npm pack` silently shipped source only (confirmed via `npm pack --dry-run`
# with a real, ~51 MB xcframework present on disk: it was not in the file
# list, and the reported tarball was 39 KB). Fixed by adding `*.xcframework`
# and `*.aar` to "files" alongside this script.
#
# Rather than trust that fix stays correct forever, ask npm what it actually
# packed on every run: `tarballIncludesXcframework`/`tarballIncludesAar`
# come from the real per-file listing in `npm pack --dry-run --json`, not
# from whether a binary merely exists on disk. If a future change to
# "files" (or an .npmignore) silently drops a binary again, these flags go
# false on the next measurement instead of the gap going unnoticed the way
# it did before this task -- the whole point of "record the components
# separately and label the projection explicitly" rather than reporting a
# tarball size that quietly stopped including what it claims to.
PACK_INFO=$(cd packages/react-native-matrix-crypto && npm pack --dry-run --json 2>/dev/null | node -e '
  const j = JSON.parse(require("fs").readFileSync(0, "utf8"));
  const entry = Array.isArray(j) ? j[0] : Object.values(j)[0];
  const files = entry?.files ?? [];
  console.log(JSON.stringify({
    tarballKB: Math.round((entry?.size ?? 0) / 1024),
    includesXcframework: files.some((f) => f.path.includes(".xcframework/")),
    includesAar: files.some((f) => f.path.endsWith(".aar")),
  }));
')

node -e "
  const fs = require('fs');
  const pack = JSON.parse(process.argv[4]);
  const row = {
    label: process.argv[1],
    xcframeworkKB: Number(process.argv[2]),
    aarKB: Number(process.argv[3]),
    tarballKB: pack.tarballKB,
    // Explicit, per spec section 10's ~150 MB M1b gate comparing a single
    // combined tarball across both platforms (Task 14): whether *this*
    // tarballKB actually reflects each binary, rather than a platform that
    // simply was not built yet at measurement time (e.g. Android before
    // Task 12) being silently indistinguishable from one that was built but
    // failed to pack.
    tarballIncludesXcframework: pack.includesXcframework,
    tarballIncludesAar: pack.includesAar,
  };
  const path = 'artifact-sizes.json';
  const all = fs.existsSync(path) ? JSON.parse(fs.readFileSync(path,'utf8')) : [];
  // Upsert by label rather than always appending: a repeated label (e.g.
  // re-measuring 'm1a-baseline' after fixing a measurement bug) must replace
  // the stale row, not shadow it. 'Array.prototype.find' -- which is exactly
  // how the M1b comparison script (spec section 10 / Task 14) looks a label
  // up -- returns the *first* match, so a blind push would leave that
  // consumer silently reading the old, wrong entry forever.
  const i = all.findIndex((r) => r.label === row.label);
  if (i === -1) all.push(row); else all[i] = row;
  fs.writeFileSync(path, JSON.stringify(all, null, 2) + '\n');
  console.log(JSON.stringify(row));
" "${1:-unlabelled}" "$XC_KB" "$AAR_KB" "$PACK_INFO"
