#!/usr/bin/env bash
set -euo pipefail

# Records, next to a binary that has just been built, the commit it was built
# from. scripts/measure-artifacts.sh reads what this writes.
#
# WHY A COMMIT, AND NOT A MODIFICATION TIME
#
# measure-artifacts.sh refuses to record a size measured from a binary that
# was not built from the Rust in the tree. That refusal is worth keeping: at
# the end of M3 the only .xcframework on disk predated verification.rs by a
# day, and a row taken from it would have recorded roughly 1,800 lines of new
# Rust as costing nothing -- a real measurement of the wrong artifact, which
# reads exactly like a real measurement of the right one.
#
# It established provenance by comparing file modification times: it refused
# if any shipped binary was older than the newest Rust source. That works on
# one machine, and it does not survive CI. Release run 33261962635 (tag
# v0.1.0) failed in the `pack` job with
#
#   FAIL: refusing to record a size measured from a stale binary.
#         the iOS framework ... is older than the newest Rust source
#
# for a framework built in that same run, from that same commit, minutes
# earlier. actions/checkout writes the Rust sources at job start; the tar that
# carries the framework between jobs preserves its original build timestamps,
# which are earlier. So the check reported a stale binary for the one build
# where the number was genuinely right -- a false positive on exactly the case
# it exists to bless. Both platform legs are affected by the same mechanism;
# the run happened to fail on iOS first.
#
# A modification time is a guess about provenance. A commit sha is an
# identity. So the build states what it built from, in a file that travels in
# the same artifact as the binary it describes, and the gate requires that
# statement to name the tree it is measuring. This is the shape
# rust/matrix-crypto-core/src/observer.rs already uses for the same problem:
# EMIT_BUILD makes the artifact identify itself rather than making the reader
# trust the procedure that produced it.
#
# WHAT THIS FILE CAN PROVE
#
# That the job which produced the binary had this repository checked out at
# the named commit, with no uncommitted and no untracked change under the Rust
# sources -- refused below rather than merely recorded, because a stamp naming
# a commit whose source is not what was compiled is a lie at birth.
#
# WHAT IT CANNOT PROVE
#
# That a compiler ran at all, that it read these sources rather than a cache,
# or that the bytes next to this file are its output. And it is not a
# signature: anyone who can write this file can write any value into it. It
# establishes provenance within the trust boundary of the workflow that writes
# it, which is the boundary that matters here -- the failure being closed is a
# build system misattributing its own output, not a forgery.

usage() {
  echo "usage: $0 <leg> <path>"
  echo "  leg   ios | android -- which release build leg produced the binary"
  echo "  path  the built binary, relative to the repository root"
}

if [ "$#" -ne 2 ]; then
  usage
  exit 2
fi

LEG=$1
TARGET=$2

case "$LEG" in
  ios|android) ;;
  *)
    echo "FAIL: '$LEG' is not a build leg this repository has."
    usage
    exit 2
    ;;
esac

# The two directories whose contents decide what a size measurement is a
# measurement OF. Kept identical to the list in scripts/measure-artifacts.sh,
# and scripts/assert-artifact-provenance.sh compares the two lines to keep
# them that way: a stamp asserting a clean tree over a narrower set of sources
# than the gate attributes the bytes to would assert less than it appears to.
RUST_SRC_DIRS=(rust/matrix-crypto-core/src rust/matrix-crypto-ffi/src)

# Normalise so the `covers` line below and the path measure-artifacts.sh
# arrives at through `find` are the same string for the same directory.
TARGET=${TARGET#./}
TARGET=${TARGET%/}

if [ -z "$TARGET" ] || [ ! -e "$TARGET" ]; then
  echo "FAIL: refusing to stamp a binary that is not there."
  echo "      ${TARGET:-<empty path>}"
  echo "      This step runs after the build that produces it. A stamp written"
  echo "      for a missing artifact would be a provenance record for nothing,"
  echo "      and the job that measures it would trust it."
  exit 1
fi

if ! COMMIT=$(git rev-parse HEAD 2>/dev/null) || [ -z "$COMMIT" ]; then
  echo "FAIL: refusing to stamp a binary from outside a git checkout."
  echo "      'git rev-parse HEAD' produced nothing here, so there is no"
  echo "      commit to record and nothing this stamp could honestly say."
  exit 1
fi

# A clean checkout is what makes the sha mean the source. actions/checkout
# gives one; this refuses rather than assumes, so a stamp can never name a
# commit whose Rust is not the Rust that was compiled. Untracked files count:
# an untracked .rs is source the build read and no commit names.
DIRTY=$(git status --porcelain -- "${RUST_SRC_DIRS[@]}" 2>/dev/null || true)
if [ -n "$DIRTY" ]; then
  echo "FAIL: refusing to stamp a binary built from a modified Rust tree."
  echo "      'git status --porcelain' reports changes under ${RUST_SRC_DIRS[*]}:"
  printf '%s\n' "$DIRTY" | sed 's/^/        /'
  echo "      The commit below would name source that is not what was compiled,"
  echo "      so the stamp would read as an identity while proving nothing."
  echo "      Commit the change, or measure without a stamp and accept the"
  echo "      weaker check measure-artifacts.sh names in its own output."
  exit 1
fi

if [ -n "${GITHUB_RUN_ID:-}" ]; then
  BUILDER="github-actions run ${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT:-1}"
else
  BUILDER="local"
fi

STAMP_DIR="packages/react-native-matrix-crypto/.build-provenance"
STAMP="$STAMP_DIR/$LEG.env"
mkdir -p "$STAMP_DIR"

# Deliberately not a tracked file, and .gitignore keeps it that way: it
# describes one build on one machine, so a committed copy would be wrong for
# every checkout but the one that wrote it.
cat > "$STAMP" <<STAMP_EOF
# Written by scripts/record-build-provenance.sh. Read by
# scripts/measure-artifacts.sh, which refuses to record a size unless
# 'commit' below is this tree's HEAD and 'covers' is the path it measured.
#
# Not a signature. Anyone who can write this file can write any value in it.
commit=$COMMIT
covers=$TARGET
leg=$LEG
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
builder=$BUILDER
STAMP_EOF

echo "provenance recorded: $TARGET"
echo "  built from commit $COMMIT"
echo "  stamped at        $STAMP"
echo "  by                $BUILDER"
echo
echo "The stamp travels in the same artifact as the binary. Whatever job"
echo "measures that binary must find this commit to be its own HEAD, or"
echo "measure-artifacts.sh refuses the row."
