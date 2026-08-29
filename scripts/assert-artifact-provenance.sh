#!/usr/bin/env bash
set -euo pipefail

# Faces scripts/measure-artifacts.sh's provenance gate with the binaries it
# must refuse and the binaries it must accept, on both of its paths.
#
# WHY THIS EXISTS AT ALL
#
# The gate refuses to record an artifact size measured from a binary that was
# not built from the Rust in the tree, because such a number is a real
# measurement of the wrong artifact and reads exactly like a real measurement
# of the right one. It had caught that once, for real.
#
# It used to establish provenance by comparing modification times, and that
# check did not survive CI: release run 33261962635 (tag v0.1.0) failed in the
# `pack` job because a framework built minutes earlier in that same run, from
# that same commit, was older than the Rust sources `actions/checkout` had
# just written. A false positive on exactly the case the gate exists to bless.
#
# The fix replaces the proxy with an identity -- the build records the commit
# it built from, next to the binary, and the gate requires that to match the
# tree it is measuring. The obvious wrong version of that fix is one that
# weakens the gate until the release passes, and nothing about reading the
# script tells the two apart: both are green. So both directions are run here.
#
# THE FOUR THINGS IT PINS, AND WHY EACH ONE
#
# 1. A genuinely stale binary is still refused -- on the CI path AND on the
#    local path. This is the whole reason the gate exists and the property a
#    "fix" that merely unblocks the release would quietly lose.
# 2. A correctly built binary is accepted on the CI path even when its
#    modification times are older than the checkout's. That is the exact
#    shape of run 33261962635, and it is the case the release needs blessed.
# 3. The weaker check is never substituted silently. Under
#    REQUIRE_BUILD_PROVENANCE a missing stamp is a refusal, not a downgrade,
#    and every accepted run names the check that ran, in its output and in
#    the row it writes.
# 4. Wherever a stamp exists, the identity check governs -- including
#    locally, where the mtime heuristic would otherwise have accepted a
#    binary from another commit.
#
# WHAT IS FAKED, AND WHAT IS NOT
#
# The fixture is a real git repository with real commits, real (tiny) binary
# files whose modification times are set explicitly, and real provenance
# stamps -- written by the shipped scripts/record-build-provenance.sh where
# the case calls for a genuine one, and written by hand where the case is
# "a binary from another commit", which is the only honest way to produce one
# without a second full cross-compile. `npm pack --dry-run` runs for real
# against the fixture package. Everything under test -- the stamp parsing,
# the sha comparison, the `covers` comparison, the dirty-tree check, the
# fallback and the row written -- is the shipped script, unmodified.
#
# What this cannot reach is a real release run: that both platform legs write
# their stamp in the step that collects the binary, and that the stamp
# survives the tar between jobs, are properties of .github/workflows/release.yml
# and ci.yml, and only a real run proves them.

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
MEASURE="$REPO_ROOT/scripts/measure-artifacts.sh"
RECORD="$REPO_ROOT/scripts/record-build-provenance.sh"

for f in "$MEASURE" "$RECORD"; do
  [ -x "$f" ] || { echo "FAIL: $f is missing or not executable."; exit 1; }
done
command -v git >/dev/null 2>&1 || { echo "FAIL: git is needed to build the fixture repository."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "FAIL: npm is needed; measure-artifacts.sh runs 'npm pack --dry-run'."; exit 1; }

# --- the two scripts must agree on which sources a measurement is OF -------
#
# Both files carry the same RUST_SRC_DIRS line: the recorder asserts a clean
# tree over those directories, the gate attributes the measured bytes to
# them. If they ever drift apart the stamp would assert less than the gate
# claims, and nothing else here would notice -- every case below would still
# pass.
REC_DIRS=$(grep -n '^RUST_SRC_DIRS=' "$RECORD" | head -1 | cut -d: -f2-)
MEA_DIRS=$(grep -n '^RUST_SRC_DIRS=' "$MEASURE" | head -1 | cut -d: -f2-)
if [ -z "$REC_DIRS" ] || [ "$REC_DIRS" != "$MEA_DIRS" ]; then
  echo "FAIL: the two scripts disagree about which Rust sources a size"
  echo "      measurement is a measurement of, or the line moved."
  echo "      record-build-provenance.sh: ${REC_DIRS:-<not found>}"
  echo "      measure-artifacts.sh:       ${MEA_DIRS:-<not found>}"
  echo "      The recorder asserts a clean tree over those directories and the"
  echo "      gate attributes the bytes to them. Drift makes the stamp assert"
  echo "      less than the gate claims, with every case below still green."
  exit 1
fi
echo "ok: both scripts name the same Rust sources -- ${REC_DIRS}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
REPO="$WORK/repo"
PKG="$REPO/packages/react-native-matrix-crypto"
XCF="packages/react-native-matrix-crypto/MatrixCryptoFramework.xcframework"
JNI="packages/react-native-matrix-crypto/android/src/main/jniLibs"
STAMPS="$PKG/.build-provenance"

# Explicit times rather than sleeps: "stale" and "fresh" have to be decided
# by the fixture, not by how fast the machine got here.
OLD=200001010000
RUSTTIME=202401010000
NEW=202501010000

mkdir -p "$REPO/rust/matrix-crypto-core/src" "$REPO/rust/matrix-crypto-ffi/src" \
  "$REPO/scripts" "$PKG/src" "$PKG/$(basename "$XCF")/ios-arm64" \
  "$PKG/android/src/main/jniLibs/x86_64"

cp "$MEASURE" "$RECORD" "$REPO/scripts/"

printf 'pub fn core() {}\n' > "$REPO/rust/matrix-crypto-core/src/lib.rs"
printf 'pub fn ffi() {}\n' > "$REPO/rust/matrix-crypto-ffi/src/lib.rs"
printf 'export const x = 1;\n' > "$PKG/src/index.ts"
cat > "$PKG/package.json" <<'PKG_EOF'
{
  "name": "react-native-matrix-crypto",
  "version": "0.0.0-fixture",
  "private": true,
  "files": ["src", "android/src/main", "MatrixCryptoFramework.xcframework"]
}
PKG_EOF
cat > "$REPO/.gitignore" <<'IGNORE_EOF'
*.xcframework
jniLibs/
.build-provenance/
artifact-sizes.json
IGNORE_EOF

cd "$REPO"
git init -q -b main
git add .gitignore scripts rust packages
git -c user.email=gate@example.invalid -c user.name='provenance gate' \
  commit -q -m 'fixture tree'
HEAD_SHA=$(git rev-parse HEAD)
# A sha this fixture has never been at: the binary from another build.
OTHER_SHA=$(printf '%s' "$HEAD_SHA" | tr '0-9a-f' '1-9a-f0')

# The binaries. Content is irrelevant; only their presence, their
# modification times and what claims to have built them are under test.
printf 'MACHO' > "$PKG/$(basename "$XCF")/ios-arm64/libmatrix.a"
printf 'ELF' > "$PKG/android/src/main/jniLibs/x86_64/libmatrix_crypto_ffi.so"
touch -t "$RUSTTIME" rust/matrix-crypto-core/src/lib.rs rust/matrix-crypto-ffi/src/lib.rs

FAILURES=0

reset_binaries() {
  rm -rf "$STAMPS"
  rm -f "$REPO/artifact-sizes.json"
  # Fresh by modification time: newer than every Rust source, so the
  # fallback heuristic would accept them. Cases that need a stale binary say
  # so explicitly.
  find "$XCF" "$JNI" -type f -exec touch -t "$NEW" {} +
}

make_stale() {
  find "$1" -type f -exec touch -t "$OLD" {} +
}

# $1 leg, $2 commit, $3 covers -- a stamp written by hand, which is how a
# binary from another commit is manufactured without a second cross-compile.
forge_stamp() {
  mkdir -p "$STAMPS"
  cat > "$STAMPS/$1.env" <<FORGED_EOF
commit=$2
covers=$3
leg=$1
built=2026-01-01T00:00:00Z
builder=fixture
FORGED_EOF
}

# $1 case name, $2 expected exit status, $3 substring the output must carry.
# Runs the shipped gate with whatever REQUIRE_BUILD_PROVENANCE the caller set.
expect() {
  local name=$1 want=$2 needle=$3 out status
  set +e
  out=$("$REPO/scripts/measure-artifacts.sh" fixture 2>&1)
  status=$?
  set -e
  if [ "$status" != "$want" ]; then
    echo "FAIL: $name exited $status, expected $want."
    printf '%s\n' "$out" | sed 's/^/      | /'
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  if ! printf '%s' "$out" | grep -qF -- "$needle"; then
    echo "FAIL: $name exited $want but never said \"$needle\"."
    echo "      A gate that refuses without saying why, or accepts without"
    echo "      saying which check ran, is half a gate."
    printf '%s\n' "$out" | sed 's/^/      | /'
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  echo "ok: $name"
}

# $1 case name, $2 the provenance.method the written row must carry.
expect_recorded_method() {
  local name=$1 want=$2 got
  if [ ! -f "$REPO/artifact-sizes.json" ]; then
    echo "FAIL: $name -- artifact-sizes.json was never written."
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  got=$(node -e '
    const rows = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const row = rows.find((r) => r.label === "fixture");
    process.stdout.write(String(row && row.provenance && row.provenance.method));
  ' "$REPO/artifact-sizes.json")
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name -- the recorded row says provenance.method '$got', expected '$want'."
    echo "      A row measured under the heuristic must stay distinguishable"
    echo "      from a row measured under the identity check; that is the"
    echo "      whole reason the field is written."
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  echo "ok: $name records provenance.method '$want'"
}

echo
echo "=== the CI path: REQUIRE_BUILD_PROVENANCE is set ==="
echo

# 1. A binary built at another commit, whose modification times are FRESH.
#    The old heuristic accepted exactly this. The identity check must not.
reset_binaries
forge_stamp ios "$OTHER_SHA" "$XCF"
forge_stamp android "$HEAD_SHA" "$JNI"
REQUIRE_BUILD_PROVENANCE=1 \
  expect "a stale iOS framework, stamped with another commit, mtime-fresh" \
    1 "measured from a binary this tree"

# 1b. The same on the Android leg, with iOS correct. The release run failed on
#     iOS first only because that job finished first; both legs carry the
#     mechanism, so both must carry the refusal.
reset_binaries
forge_stamp ios "$HEAD_SHA" "$XCF"
forge_stamp android "$OTHER_SHA" "$JNI"
REQUIRE_BUILD_PROVENANCE=1 \
  expect "stale prebuilt Rust libraries, stamped with another commit" \
    1 "the prebuilt Rust libraries"

# 2. No stamp at all, binaries mtime-fresh. The heuristic would have passed
#    this; on the CI path there must be no downgrade to it, silent or not.
reset_binaries
REQUIRE_BUILD_PROVENANCE=1 \
  expect "an unstamped binary on the CI path" 1 "carries no provenance stamp at"

# 3. A stamp that describes a different artifact must not bless this one.
reset_binaries
forge_stamp ios "$HEAD_SHA" "some/other/artifact"
forge_stamp android "$HEAD_SHA" "$JNI"
REQUIRE_BUILD_PROVENANCE=1 \
  expect "a stamp naming a different artifact" 1 "blessed by another artifact's stamp"

# 4. A correctly built binary whose modification times are OLDER than the
#    Rust sources -- run 33261962635 exactly: built in the same run, from the
#    same commit, then carried between jobs in a tar that preserved its build
#    times while actions/checkout wrote fresh sources. It must be accepted.
#    Stamps here are written by the shipped recorder, not forged.
reset_binaries
"$REPO/scripts/record-build-provenance.sh" ios "$XCF" >/dev/null
"$REPO/scripts/record-build-provenance.sh" android "$JNI" >/dev/null
make_stale "$XCF"
make_stale "$JNI"
REQUIRE_BUILD_PROVENANCE=1 \
  expect "the run-33261962635 case: correctly built, mtime older than the checkout" \
    0 "check: IDENTITY"
expect_recorded_method "the accepted CI row" build-stamp

# 5. A stamp matching HEAD over a Rust tree that has moved since. The sha
#    would compare equal and would be proving less than it appears to.
reset_binaries
"$REPO/scripts/record-build-provenance.sh" ios "$XCF" >/dev/null
"$REPO/scripts/record-build-provenance.sh" android "$JNI" >/dev/null
printf 'pub fn core() { /* uncommitted */ }\n' > "$REPO/rust/matrix-crypto-core/src/lib.rs"
REQUIRE_BUILD_PROVENANCE=1 \
  expect "a matching stamp over a modified Rust tree" 1 "against a modified Rust tree"

# 5b. The recorder refuses to write such a stamp in the first place, so a lie
#     of that shape cannot be created, only forged.
set +e
REC_OUT=$("$REPO/scripts/record-build-provenance.sh" ios "$XCF" 2>&1)
REC_STATUS=$?
set -e
if [ "$REC_STATUS" != 1 ] || ! printf '%s' "$REC_OUT" | grep -qF "built from a modified Rust tree"; then
  echo "FAIL: the recorder stamped a binary built from a modified Rust tree."
  printf '%s\n' "$REC_OUT" | sed 's/^/      | /'
  FAILURES=$((FAILURES + 1))
else
  echo "ok: the recorder refuses to stamp a modified Rust tree"
fi
git checkout -q -- rust/matrix-crypto-core/src/lib.rs
touch -t "$RUSTTIME" rust/matrix-crypto-core/src/lib.rs

echo
echo "=== the local path: no REQUIRE_BUILD_PROVENANCE, no CI stamp ==="
echo

# 6. The original refusal, unchanged in what it rejects: a binary older than
#    the newest Rust source, on a machine with nothing to have stamped it.
#    This is the check that caught the M3 near miss, and losing it is the
#    failure mode a fix that merely unblocks the release would have.
reset_binaries
make_stale "$XCF"
expect "a genuinely stale binary on the local path" 1 "measured from a stale binary"

# 6b. And on the Android leg.
reset_binaries
make_stale "$JNI"
expect "genuinely stale prebuilt Rust libraries on the local path" \
  1 "the prebuilt Rust libraries"

# 7. The accepting case for the local path. Without it, a "fix" that refuses
#    everything passes every case above. It must also SAY that the weaker
#    check ran: a fallback that substitutes silently is the failure this
#    repository keeps finding.
reset_binaries
expect "a locally rebuilt binary, no stamp" 0 "check: MODIFICATION TIME"
expect_recorded_method "the accepted local row" mtime

# 8. Wherever a stamp exists the identity check governs, local or not. The
#    binary here is mtime-fresh, so the heuristic alone would accept it.
reset_binaries
forge_stamp ios "$OTHER_SHA" "$XCF"
forge_stamp android "$HEAD_SHA" "$JNI"
expect "a binary from another commit, on the local path" \
  1 "measured from a binary this tree"

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "FAIL: $FAILURES of the artifact provenance gate's cases did not behave"
  echo "      as documented. scripts/measure-artifacts.sh describes what it"
  echo "      refuses and what each check proves; one of those is now wrong."
  exit 1
fi

echo "PASS: artifact provenance -- a binary from another commit is refused on"
echo "      both the CI and the local path, an unstamped binary is refused"
echo "      rather than downgraded on the CI path, a genuinely stale binary is"
echo "      still refused locally on both legs, and a correctly built binary"
echo "      whose modification times are older than the checkout is accepted"
echo "      with the check that ran named in the output and in the row."
