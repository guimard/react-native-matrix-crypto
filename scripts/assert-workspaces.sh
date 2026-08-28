#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3: the Cargo and yarn workspaces resolve, and each holds
# the package this repository is built around.
#
# WHAT THIS GATE USED TO DO, and why none of it established that claim. The
# 2026-08-28 verification-infrastructure review constructed three violations
# and watched all three pass:
#
#   "workspaces": []                 PASS   nothing resolves
#   "workspaces": ["does-not-exist/*"]  PASS   nothing resolves
#   matrix-crypto-core renamed to
#   matrix-crypto-kernel             PASS   the crate it names is absent
#
# The first two: the yarn half checked that `private === true` and that
# `workspaces` was an array. An array of nothing is an array. Confirmed with
# the real yarn: `yarn workspaces info` prints `{}` for both, exit 0.
#
# The third, and it is the one that matters: the cargo half piped
# `cargo metadata` into `grep -q '"name":"matrix-crypto-core"'`. With the core
# crate renamed, `cargo metadata --no-deps` reports packages
# matrix-crypto-kernel and matrix-crypto-ffi -- and the grep still matched,
# because matrix-crypto-ffi's `dependencies` array declares that name. The
# gate asserted on a dependency declaration rather than on a package, which is
# the same defect class this milestone has now found eight times. gate:boundary
# reads the same metadata correctly and exits 2 on that tree; the contrast is
# what made this legible.
#
# This gate was also the only one of the seven with no "refuse to pass having
# scanned nothing" guard. It has one on each half now.

EXPECTED_CRATES=(matrix-crypto-core matrix-crypto-ffi)
EXPECTED_YARN_PACKAGE=react-native-matrix-crypto

# --- The Cargo workspace ------------------------------------------------------
#
# Package NAMES, one per line, extracted the way assert-core-boundary.sh does
# it -- through a JSON parser, so that `grep -qx` below compares a whole name
# against a whole name and cannot match a substring of some other field.
CRATES=$(cargo metadata --format-version 1 --no-deps --manifest-path rust/Cargo.toml \
  | node -e '
      const m = JSON.parse(require("fs").readFileSync(0, "utf8"));
      m.packages.forEach(p => console.log(p.name));
    ')

if [ -z "${CRATES//[[:space:]]/}" ]; then
  echo "FAIL: refusing to pass having scanned nothing."
  echo "      cargo metadata reported no packages at all for rust/Cargo.toml,"
  echo "      which means the workspace does not resolve or the extraction"
  echo "      broke -- not that its members are fine."
  exit 1
fi

for crate in "${EXPECTED_CRATES[@]}"; do
  if ! printf '%s\n' "$CRATES" | grep -qx "$crate"; then
    echo "FAIL: '$crate' is not a package in the cargo workspace."
    echo "      cargo metadata --no-deps reported:"
    printf '%s\n' "$CRATES" | sed 's/^/        /'
    echo "      A crate that was renamed or dropped out of rust/Cargo.toml's"
    echo "      members must be changed here deliberately, not discovered by"
    echo "      a build failing somewhere downstream."
    exit 1
  fi
done

# The list is asserted to CONTAIN these two rather than to equal them: a crate
# added to the workspace later is picked up automatically by gate:boundary and
# gate:logger, both of which derive their scan roots from this same metadata,
# so a new member is covered rather than merely tolerated.

# --- The yarn workspace -------------------------------------------------------
#
# The manifest checks come FIRST, before yarn is asked to resolve anything.
# `yarn workspaces info` refuses outright on a non-private root ("Workspaces
# can only be enabled in private projects."), so running it first made yarn's
# message the only one anybody saw and left this gate's own diagnosis
# unreachable. Observed while proving the rewrite.
node -e '
  const p = JSON.parse(require("fs").readFileSync("package.json", "utf8"));
  if (p.private !== true) {
    console.error("FAIL: root package.json must be private.");
    console.error("      yarn refuses to enable workspaces in a public root,");
    console.error("      so nothing below this line could resolve either.");
    process.exit(1);
  }
  if (!Array.isArray(p.workspaces)) {
    console.error("FAIL: root package.json must declare workspaces");
    process.exit(1);
  }
'

# `yarn workspaces info` is the only thing here that actually RESOLVES the
# globs in "workspaces": it walks them and reports the packages it found, so
# an empty result is the failure the two manifest checks above could never
# see.
YARN_INFO=$(yarn --silent workspaces info)

node -e '
  const fs = require("fs");
  const p = JSON.parse(fs.readFileSync("package.json", "utf8"));

  const info = JSON.parse(process.argv[1]);
  const names = Object.keys(info);
  if (names.length === 0) {
    console.error("FAIL: refusing to pass having scanned nothing.");
    console.error("      The \"workspaces\" globs " + JSON.stringify(p.workspaces));
    console.error("      resolve to no package at all. An array of nothing is");
    console.error("      still an array, which is all this gate used to check.");
    process.exit(1);
  }

  const wanted = process.argv[2];
  if (!names.includes(wanted)) {
    console.error("FAIL: the yarn workspace does not contain " + wanted + ".");
    console.error("      It resolved to: " + names.join(", "));
    console.error("      That is the package this repository publishes; a");
    console.error("      workspace that resolves without it resolves to the");
    console.error("      wrong thing.");
    process.exit(1);
  }

  const loc = info[wanted].location;
  if (!fs.existsSync(loc + "/package.json")) {
    console.error("FAIL: " + wanted + " resolves to " + loc + ", which holds no");
    console.error("      package.json.");
    process.exit(1);
  }
' "$YARN_INFO" "$EXPECTED_YARN_PACKAGE"

YARN_NAMES=$(printf '%s' "$YARN_INFO" | node -e '
  const info = JSON.parse(require("fs").readFileSync(0, "utf8"));
  console.log(Object.keys(info).join(", "));
')

echo "PASS: workspaces resolve"
echo "      cargo: $(printf '%s' "$CRATES" | tr '\n' ' ')"
echo "      yarn:  $YARN_NAMES"
