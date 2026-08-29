#!/usr/bin/env bash
set -euo pipefail

# Spec section 10: artifact size decides whether binaries can ship inside the
# npm tarball at all. Record it rather than guess at it.
size_of() {
  [ -e "$1" ] && du -sk "$1" | cut -f1 || echo 0
}

XC=$(find packages -name '*.xcframework' -maxdepth 4 | head -1)
AAR=$(find packages -name '*.aar' -maxdepth 5 | head -1)

# REFUSE A ROW MEASURED FROM A BINARY OLDER THAN THE RUST IT CLAIMS TO CARRY
#
# Every column below except the source ones is a property of compiled code,
# and nothing in the rest of this script asks whether the compiled code on
# disk was built from the Rust in the tree. It was not, once, and it was not
# caught by anything here: at the end of M3 the only `.xcframework` on disk
# predated `verification.rs` by a day, so a row taken from it would have
# recorded roughly 1,800 lines of new Rust as costing nothing -- and would
# have looked exactly like a real measurement, because it *is* a real
# measurement of the wrong artifact. The whole delta would have been shipped
# source: `src`, `interop`, the README.
#
# That is the shape spec section 3.2 counts: a check reporting success
# without having examined its target. So this refuses rather than measuring.
# In CI and at release the binaries are built in the same job, minutes
# before, and this never fires; on a developer's tree it fires exactly when
# the number would have been meaningless.
#
# Compared file-by-file, not by the enclosing directory's own timestamp: a
# directory's mtime does not move when a file nested inside it is rewritten,
# so the container would go on looking fresh while its contents aged.
NEWEST_RUST=$(find rust/matrix-crypto-core/src rust/matrix-crypto-ffi/src \
  -name '*.rs' -type f -exec ls -t {} + 2>/dev/null | head -1 || true)

refuse_if_stale() {
  local what="$1" path="$2"
  [ -n "$path" ] && [ -e "$path" ] || return 0
  [ -n "$NEWEST_RUST" ] || return 0
  # Any file inside it newer than the newest Rust source means it was built
  # after that source, which is all this needs to establish.
  local fresh
  fresh=$( (find "$path" -type f -newer "$NEWEST_RUST" 2>/dev/null || true) | head -1 )
  [ -n "$fresh" ] && return 0
  echo "FAIL: refusing to record a size measured from a stale binary."
  echo "      $what"
  echo "        $path"
  echo "      is older than the newest Rust source it would be reported as carrying:"
  echo "        $NEWEST_RUST"
  echo "      Every size column here is a property of compiled code. A row taken"
  echo "      from a binary that predates the Rust in this tree is a real"
  echo "      measurement of the wrong artifact, and reads exactly like a real"
  echo "      measurement of the right one. Rebuild both legs and run this again,"
  echo "      or take the number from the release build, which builds them."
  exit 1
}

refuse_if_stale "the iOS framework" "${XC:-}"
refuse_if_stale "the Android archive" "${AAR:-}"
refuse_if_stale "the prebuilt Rust libraries" \
  "packages/react-native-matrix-crypto/android/src/main/jniLibs"

XC_KB=$(size_of "${XC:-/nonexistent}")
# aarKB below measures the .aar build output on disk exactly as it always
# has -- unchanged by the 2026-08-28 decision (spec section 9 step 2) to stop
# building and shipping one. That decision means this column will normally
# read 0 from here on: release.yml no longer runs the Gradle step that
# produced an .aar, so `find` finds nothing. A developer with a stray one
# left on disk from before that change still sees its real size here, while
# tarballIncludesAar (below) correctly reports it is not in the packed
# tarball -- which is the useful signal, not a bug. Kept as a live
# measurement rather than dropped or hardcoded to zero, so every row in
# artifact-sizes.json keeps meaning the same thing it always meant: what this
# script found on disk for that label, not a value it stopped looking for.
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
#
# Task 11 (size-reduction-report.md, Finding 3): `tarballKB` alone -- built
# from `entry.size`, the *compressed* .tgz byte count -- has never told
# anyone what is actually inside the tarball, only its gzip result. That
# silently changes with how compressible the shipped bytes happen to be
# (LTO'd code compresses worse than unstripped code at the same *unpacked*
# size), which is exactly how a real xcframework/aar win upstream ended up
# looking like a regression downstream. `xcframeworkKB`/`aarKB` above are
# real signal for the two build outputs this project produces, but they are
# not the whole tarball -- `package.json`'s "files" allowlist also ships
# `android/src/main`, which carries four pre-link `jniLibs/*.a` archives
# neither of those two numbers ever sees. Report the actual composition,
# not just the two outputs this repo happens to build: the per-file
# `files[]` listing in the same `npm pack --dry-run --json` payload gives
# real, *unpacked* (pre-gzip) sizes, which is the number that answers "what
# is in here" without the compression-ratio noise `tarballKB` carries.
#
# One correctness trap already bit a previous attempt at exactly this fix:
# `npm pack --dry-run --json`'s payload is not reliably on one particular
# stream across npm versions/invocations -- a prior attempt piped it through
# `2>/dev/null`, assuming stdout, and silently lost the whole per-file
# listing when it did not land there. Do not repeat that: capture BOTH
# streams to real files and accept whichever one actually parses as the
# expected `{ files: [...] }` shape, rather than betting on either.
PACK_STDOUT=$(mktemp)
PACK_STDERR=$(mktemp)
trap 'rm -f "$PACK_STDOUT" "$PACK_STDERR"' EXIT
(cd packages/react-native-matrix-crypto && npm pack --dry-run --json) \
  >"$PACK_STDOUT" 2>"$PACK_STDERR" || true

PACK_INFO=$(node -e '
  const fs = require("fs");
  function tryParse(path) {
    try {
      const j = JSON.parse(fs.readFileSync(path, "utf8"));
      const entry = Array.isArray(j) ? j[0] : Object.values(j)[0];
      if (entry && Array.isArray(entry.files)) return entry;
    } catch {
      // Not this stream -- try the other one.
    }
    return null;
  }
  const [stdoutPath, stderrPath] = process.argv.slice(1);
  const entry = tryParse(stdoutPath) || tryParse(stderrPath);
  if (!entry) {
    console.error(
      "measure-artifacts.sh: npm pack --dry-run --json produced no " +
      "parseable { files: [...] } payload on stdout or stderr"
    );
    process.exit(1);
  }
  const files = entry.files;

  // Composition, not just two component sizes: group every packed file by
  // its top-level path segment -- the shipped component it belongs to
  // (".xcframework", the whole "android" tree including jniLibs, the root
  // ".aar", "src", "cpp", ...) -- and sum the real *unpacked* (pre-gzip)
  // byte size of each group. This needs no hardcoded knowledge of which
  // components exist; it reports whatever is actually in "files" today.
  const buckets = new Map();
  for (const f of files) {
    const top = f.path.includes("/") ? f.path.split("/")[0] : f.path;
    buckets.set(top, (buckets.get(top) || 0) + f.size);
  }
  const largestContributors = [...buckets.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([component, size]) => ({ component, unpackedKB: Math.round(size / 1024) }));

  const unpackedSize = entry.unpackedSize ?? files.reduce((a, f) => a + f.size, 0);

  console.log(JSON.stringify({
    tarballKB: Math.round((entry.size ?? 0) / 1024),
    tarballUnpackedKB: Math.round(unpackedSize / 1024),
    includesXcframework: files.some((f) => f.path.includes(".xcframework/")),
    includesAar: files.some((f) => f.path.endsWith(".aar")),
    largestContributors,
  }));
' "$PACK_STDOUT" "$PACK_STDERR")

node -e "
  const fs = require('fs');
  const pack = JSON.parse(process.argv[4]);
  const row = {
    label: process.argv[1],
    xcframeworkKB: Number(process.argv[2]),
    aarKB: Number(process.argv[3]),
    tarballKB: pack.tarballKB,
    // Real, unpacked (pre-gzip) size of everything 'files' ships -- the
    // number Finding 3 needed and 'tarballKB' (a compressed byte count)
    // cannot give: it does not move with how well the payload happens to
    // gzip, only with what is actually shipped.
    tarballUnpackedKB: pack.tarballUnpackedKB,
    // The tarball's actual composition: the largest contributors by
    // unpacked size, grouped by shipped component, computed fresh from
    // npm's own per-file listing on every run -- not assumed to still be
    // 'just the xcframework and the aar' the way xcframeworkKB/aarKB alone
    // read. See size-reduction-report.md Finding 3.
    tarballLargestContributors: pack.largestContributors,
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
  console.log(JSON.stringify(row, null, 2));
" "${1:-unlabelled}" "$XC_KB" "$AAR_KB" "$PACK_INFO"
