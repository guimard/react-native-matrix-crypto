#!/usr/bin/env bash
set -euo pipefail

# Spec section 10: artifact size decides whether binaries can ship inside the
# npm tarball at all. Record it rather than guess at it.
size_of() {
  [ -e "$1" ] && du -sk "$1" | cut -f1 || echo 0
}

XC=$(find packages -name '*.xcframework' -maxdepth 4 | head -1)
AAR=$(find packages -name '*.aar' -maxdepth 5 | head -1)
JNI=packages/react-native-matrix-crypto/android/src/main/jniLibs

PROV_TSV=$(mktemp)
PACK_STDOUT=$(mktemp)
PACK_STDERR=$(mktemp)
trap 'rm -f "$PROV_TSV" "$PACK_STDOUT" "$PACK_STDERR"' EXIT

# ---------------------------------------------------------------- provenance
#
# REFUSE A ROW MEASURED FROM A BINARY THIS TREE DID NOT BUILD
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
#
# WHY THIS IS AN IDENTITY CHECK AND NO LONGER A TIMESTAMP COMPARISON
#
# It used to establish provenance by comparing modification times: it refused
# if any shipped binary was older than the newest Rust source. That works on
# one machine and it does not survive CI. Release run 33261962635 (tag
# v0.1.0) failed in the `pack` job because the iOS framework -- built in that
# same run, from that same commit, minutes earlier on a macOS runner -- was
# older than `rust/matrix-crypto-ffi/src/lib.rs`. `actions/checkout` writes
# the Rust sources at job start; the tar that carries the framework between
# jobs preserves its original build timestamps, which are earlier. The gate
# reported a stale binary for the one build where the number was genuinely
# right: a false positive on exactly the case it exists to bless. Both
# platform legs are affected by the same mechanism; that run happened to fail
# on iOS first.
#
# A modification time is a guess about provenance. A commit sha is an
# identity. So the release build now states what it built from --
# `scripts/record-build-provenance.sh` writes a stamp next to the binary, and
# the stamp travels in the same artifact -- and this requires that statement
# to name the tree it is measuring. `observer::EMIT_BUILD` solved the same
# problem the same way one milestone earlier: make the artifact identify
# itself rather than make the reader trust the procedure that produced it.
#
# TWO CHECKS, AND WHICH ONE RAN IS SAID OUT LOUD -- IN THE OUTPUT AND IN THE
# RECORDED ROW
#
# A contributor's own machine has no CI provenance stamp, and there the
# modification-time heuristic is still a reasonable thing to have: it fires
# exactly when the number would have been meaningless. So it is kept as a
# fallback. But a fallback that silently substitutes a weaker check for a
# stronger one is the failure this repository keeps finding, so it is not
# silent in either place a reader could look:
#
#   - the run prints, per binary, which check ran, what it proves and what it
#     does not;
#   - `artifact-sizes.json` records it, so a row measured under the weak
#     check stays distinguishable from one measured under the strong check
#     for as long as the file exists.
#
# And it is not available at all where the strong check is required:
# `REQUIRE_BUILD_PROVENANCE=1` (set by the release workflow and by both CI
# build legs) makes a missing or unverifiable stamp a refusal rather than a
# downgrade. That is deliberate -- the mtime heuristic is not merely weaker in
# CI, it is *wrong* there, and the release path must never silently reach for
# a check that is known to report the correct case as a failure.

# The two directories whose contents decide what these sizes are a
# measurement OF. Kept identical to the list in
# scripts/record-build-provenance.sh, and scripts/assert-artifact-provenance.sh
# compares the two lines to keep them that way.
RUST_SRC_DIRS=(rust/matrix-crypto-core/src rust/matrix-crypto-ffi/src)

STAMP_DIR=packages/react-native-matrix-crypto/.build-provenance

REQUIRE_PROV=false
case "${REQUIRE_BUILD_PROVENANCE:-}" in
  ''|0|false|no) ;;
  *) REQUIRE_PROV=true ;;
esac

HEAD_COMMIT=$(git rev-parse HEAD 2>/dev/null || true)
RUST_DIRTY=$(git status --porcelain -- "${RUST_SRC_DIRS[@]}" 2>/dev/null || true)

echo "--- provenance: what the sizes below are a measurement of ---"
echo

if [ "$REQUIRE_PROV" = true ] && [ -z "$HEAD_COMMIT" ]; then
  echo "FAIL: refusing to record a size that cannot be tied to a commit."
  echo "      REQUIRE_BUILD_PROVENANCE is set, so this run must compare each"
  echo "      binary's build stamp against this tree's HEAD -- and"
  echo "      'git rev-parse HEAD' produced nothing here, so there is no HEAD"
  echo "      to compare against."
  echo "      Falling back to the modification-time heuristic is not available"
  echo "      here on purpose: in CI a binary arrives from another job through"
  echo "      a tar that preserves its original build times, so that heuristic"
  echo "      reports every correct release build as stale (run 33261962635)."
  exit 1
fi

# $1 what it is, in prose. $2 path. $3 leg (which build produced it).
check_provenance() {
  local what=$1 path=$2 leg=$3
  [ -n "$path" ] && [ -e "$path" ] || return 0
  path=${path#./}
  path=${path%/}

  local stamp="$STAMP_DIR/$leg.env"
  if [ -f "$stamp" ] && [ -n "$HEAD_COMMIT" ]; then
    check_by_identity "$what" "$path" "$leg" "$stamp"
    return 0
  fi

  if [ "$REQUIRE_PROV" = true ]; then
    echo "FAIL: refusing to record a size measured without a build stamp."
    echo "      $what"
    echo "        $path"
    echo "      carries no provenance stamp at"
    echo "        $stamp"
    echo "      REQUIRE_BUILD_PROVENANCE is set, so this run demands the"
    echo "      identity check: the build that produced this binary must have"
    echo "      recorded the commit it built from, in the same step, and that"
    echo "      commit must be this tree's HEAD."
    echo
    echo "      This is not a downgrade to the modification-time heuristic,"
    echo "      and that is the point. In CI the binary is unpacked from a tar"
    echo "      that preserves its original build timestamps, which are older"
    echo "      than the checkout this job made -- so mtime reports every"
    echo "      correct release build as stale. Release run 33261962635 (tag"
    echo "      v0.1.0) failed in 'pack' for exactly that reason. Substituting"
    echo "      a check that is known to be wrong here, quietly, would be"
    echo "      worse than refusing."
    echo
    echo "      The stamp is written by scripts/record-build-provenance.sh in"
    echo "      the same step that collects the binary, and travels in the"
    echo "      same artifact. If it is missing, that step did not run, or the"
    echo "      artifact was assembled by something other than the release"
    echo "      workflow."
    exit 1
  fi

  check_by_mtime "$what" "$path" "$leg" "$stamp"
}

# The strong check. A commit is an identity: it names the exact source the
# build had, and it is the same value whatever a filesystem thinks the time
# is or whichever machine wrote the bytes.
check_by_identity() {
  local what=$1 path=$2 leg=$3 stamp=$4
  local stamped_commit stamped_covers
  stamped_commit=$(sed -n 's/^commit=//p' "$stamp" | head -1)
  stamped_covers=$(sed -n 's/^covers=//p' "$stamp" | head -1)

  if [ -z "$stamped_commit" ] || [ -z "$stamped_covers" ]; then
    echo "FAIL: refusing to record a size from an unreadable build stamp."
    echo "      $what"
    echo "        $path"
    echo "      has a stamp at $stamp with no 'commit=' or no 'covers=' line."
    echo "      A stamp that cannot be read is not a weaker check than an"
    echo "      identity check -- it is no check at all, and it must not pass"
    echo "      for one."
    exit 1
  fi

  # A stamp naming a different artifact must not bless this one: two binaries
  # from two different builds would otherwise share whichever stamp happened
  # to be on disk.
  if [ "$stamped_covers" != "$path" ]; then
    echo "FAIL: refusing to record a size blessed by another artifact's stamp."
    echo "      $what"
    echo "        $path"
    echo "      but the stamp at $stamp says it covers"
    echo "        $stamped_covers"
    echo "      A stamp describes the one binary its build produced. Reading"
    echo "      it as evidence about a different path is how one good build"
    echo "      would come to vouch for another build nobody checked."
    exit 1
  fi

  if [ "$stamped_commit" != "$HEAD_COMMIT" ]; then
    echo "FAIL: refusing to record a size measured from a binary this tree"
    echo "      did not build."
    echo "      $what"
    echo "        $path"
    echo "      was built from commit"
    echo "        $stamped_commit"
    echo "      and this tree is at"
    echo "        $HEAD_COMMIT"
    echo "      Every size column here is a property of compiled code. A row"
    echo "      taken from a binary built at another commit is a real"
    echo "      measurement of the wrong artifact, and reads exactly like a"
    echo "      real measurement of the right one -- it would attribute this"
    echo "      tree's Rust to bytes that never contained it."
    echo "      Rebuild both legs from this commit and run this again, or take"
    echo "      the number from the release build, which builds them."
    exit 1
  fi

  # The sha means the source only if the source has not moved since. In CI
  # this is trivially true -- actions/checkout makes a clean tree -- and on a
  # developer's machine it is the difference between "this commit" and "this
  # commit plus whatever I have not committed".
  if [ -n "$RUST_DIRTY" ]; then
    echo "FAIL: refusing to record a size against a modified Rust tree."
    echo "      $what"
    echo "        $path"
    echo "      carries a stamp for $HEAD_COMMIT, which is this tree's HEAD --"
    echo "      but 'git status --porcelain' reports changes under"
    echo "      ${RUST_SRC_DIRS[*]}:"
    printf '%s\n' "$RUST_DIRTY" | sed 's/^/        /'
    echo "      So the commit no longer names the Rust on disk, and the sha"
    echo "      comparison above proves less than it appears to. Commit the"
    echo "      change and rebuild, or measure without a stamp and read what"
    echo "      the weaker check below says it cannot prove."
    exit 1
  fi

  echo "checking: $what"
  echo "  $path"
  echo "  check: IDENTITY, from the build stamp at $stamp"
  echo "  built from commit $stamped_commit, which is this tree's HEAD"
  echo "  proves:    the job that produced this binary had this repository"
  echo "             checked out at this commit, with nothing uncommitted and"
  echo "             nothing untracked under ${RUST_SRC_DIRS[*]}."
  echo "  does not prove: that a compiler ran rather than a cache being"
  echo "             reused, or that these bytes are that compiler's output."
  echo "             The stamp is a record written by the build, not a"
  echo "             signature: anyone who can write the file can write any"
  echo "             value in it."
  echo
  printf '%s\t%s\t%s\t%s\n' "$leg" "build-stamp" "$path" "$stamped_commit" >>"$PROV_TSV"
}

# The weak check, kept for a developer's own tree, where there is no build to
# have stamped anything. Compared file-by-file, not by the enclosing
# directory's own timestamp: a directory's mtime does not move when a file
# nested inside it is rewritten, so the container would go on looking fresh
# while its contents aged.
check_by_mtime() {
  local what=$1 path=$2 leg=$3 stamp=$4
  local newest_rust fresh reason
  newest_rust=$(find "${RUST_SRC_DIRS[@]}" \
    -name '*.rs' -type f -exec ls -t {} + 2>/dev/null | head -1 || true)

  if [ -f "$stamp" ]; then
    reason="a stamp is present but there is no git HEAD here to check it against"
  else
    reason="no build stamp at $stamp"
  fi

  if [ -n "$newest_rust" ]; then
    # Any file inside it newer than the newest Rust source means it was
    # written after that source, which is all this can establish.
    fresh=$( (find "$path" -type f -newer "$newest_rust" 2>/dev/null || true) | head -1 )
    if [ -z "$fresh" ]; then
      echo "FAIL: refusing to record a size measured from a stale binary."
      echo "      $what"
      echo "        $path"
      echo "      is older than the newest Rust source it would be reported as"
      echo "      carrying:"
      echo "        $newest_rust"
      echo "      Every size column here is a property of compiled code. A row"
      echo "      taken from a binary that predates the Rust in this tree is a"
      echo "      real measurement of the wrong artifact, and reads exactly"
      echo "      like a real measurement of the right one. Rebuild both legs"
      echo "      and run this again, or take the number from the release"
      echo "      build, which builds them."
      echo
      echo "      This is the fallback check, reached because $reason."
      echo "      It is a heuristic about modification times, not an identity."
      exit 1
    fi
  fi

  echo "checking: $what"
  echo "  $path"
  echo "  check: MODIFICATION TIME -- the weaker fallback, reached because"
  echo "         $reason."
  echo "  proves:    some file in this binary was written after"
  echo "             ${newest_rust:-<no Rust source found>}, so it is not one"
  echo "             of the binaries that predate the Rust in this tree."
  echo "  does not prove: that it was BUILT from this tree at all. A touch, an"
  echo "             unpack, or a copy moves a modification time; none of them"
  echo "             compile anything. It is also wrong in the other direction"
  echo "             in CI, where a correctly built binary arrives through a"
  echo "             tar that preserves build times older than the checkout --"
  echo "             which is why the release workflow sets"
  echo "             REQUIRE_BUILD_PROVENANCE and refuses this check outright."
  echo
  printf '%s\t%s\t%s\t%s\n' "$leg" "mtime" "$path" "${newest_rust:-}" >>"$PROV_TSV"
}

check_provenance "the iOS framework" "${XC:-}" ios
check_provenance "the Android archive" "${AAR:-}" android
check_provenance "the prebuilt Rust libraries" "$JNI" android

if [ ! -s "$PROV_TSV" ]; then
  echo "checking: nothing. No .xcframework, no .aar and no jniLibs/ on disk,"
  echo "  so the size columns below are zeroes and there is no compiled code"
  echo "  for this run to have established the provenance of."
  echo
fi

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

  // How the provenance of each measured binary was established, written by
  // the shell above, one tab-separated line per binary it checked.
  // 'evidence' is what the check actually read: for 'build-stamp', the
  // commit the build recorded having checked out; for 'mtime', the newest
  // Rust source the binary was compared against.
  const checks = fs.readFileSync(process.argv[5], 'utf8')
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => {
      const [leg, method, path, evidence] = line.split('\t');
      return { leg, method, path, evidence };
    });
  const methods = [...new Set(checks.map((c) => c.method))];

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
    // WHAT THESE NUMBERS ARE A MEASUREMENT OF, recorded rather than assumed.
    //
    // 'build-stamp' is the identity check: every binary measured carried a
    // stamp naming the commit its build had checked out, and that commit was
    // required to be 'treeCommit' below, with a clean Rust source tree.
    // 'mtime' is the weaker fallback a developer's own machine gets, which
    // establishes only that the binary is newer than the newest Rust source,
    // never that it was built from it. 'mixed' means the binaries in this row
    // were not all established the same way. 'none' means nothing was on disk
    // to check, so every size column is a zero.
    //
    // 'treeCommit' is this tree's HEAD when the measurement was taken -- the
    // source the sizes are attributed to. Under 'build-stamp' every stamp
    // matched it, which is what makes the attribution true rather than
    // assumed; under 'mtime' it records only which tree did the attributing.
    //
    // Recorded because a fallback that silently substitutes a weaker check
    // for a stronger one is the failure this repository keeps finding. A row
    // measured under the heuristic stays distinguishable from a row measured
    // under the identity check for as long as this file exists, instead of
    // both reading as 'measured'.
    provenance: {
      method: checks.length === 0 ? 'none'
        : methods.length === 1 ? methods[0]
        : 'mixed',
      treeCommit: process.argv[6] || null,
      checks,
    },
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
" "${1:-unlabelled}" "$XC_KB" "$AAR_KB" "$PACK_INFO" "$PROV_TSV" "$HEAD_COMMIT"
