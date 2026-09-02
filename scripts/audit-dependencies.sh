#!/usr/bin/env bash
set -euo pipefail

# `npm audit` over what installing this package actually pulls onto a
# consumer's machine.
#
# It reads the PACKED tarball installed into an empty directory, not the
# checkout, for the same reason `cold-consume` in ci.yml does: the checkout's
# `node_modules` is a yarn workspace holding every development tool this
# repository uses, and none of that reaches anybody who runs
# `npm install react-native-matrix-crypto`. Auditing the workspace would answer
# a question nobody asked, loudly, forever -- the React Native toolchain is
# large and has advisories against it most weeks.
#
# `npm audit` cannot read this workspace anyway. packages/example-app depends
# on the library through yarn's `link:` protocol, which npm does not implement:
# `npm install --package-lock-only` at the root fails with
# `EUNSUPPORTEDPROTOCOL Unsupported URL Type "link:"`, and it fails inside
# packages/react-native-matrix-crypto too, because npm walks up to the
# workspace root and finds the same manifest. Packing sidesteps that entirely.
#
# THIS IS NOT A `gate:*` SCRIPT, and the difference is not cosmetic. Every gate
# in this repository asserts something about the tree, so a gate that is green
# today is green tomorrow unless someone changes the tree. This reads an
# advisory database that changes on its own: it can turn red on a commit that
# passed yesterday, with nothing in the repository having moved. That is the
# point of running it -- but it is not the promise the README's gate table
# makes, and `gate:readme` would require a row claiming it.

# --- Two audits, two thresholds, and the reason they differ -----------------
#
# This package declares two runtime dependencies (`@ubjs/core` and
# `uniffi-bindgen-react-native`) and two peers (`react` and `react-native`).
# The distinction is who can fix an advisory.
#
# A finding in the DEPENDENCY tree is this repository's to fix, by bumping or
# by dropping the dependency, so nothing is tolerated there: the threshold is
# `low`. That tree is four packages deep today and clean, so this is a
# threshold this repository can actually hold rather than one it will learn to
# ignore.
#
# A finding in the PEER tree is React Native's, and it arrives here as a
# version range this repository does not control -- the consumer's own
# `react-native` is what gets installed. At the time of writing that tree
# carries seven high advisories, all of them one `image-size` parser reachable
# through `metro`, which is a build-time tool for an app developer and not code
# that ships in one. Failing on those would make this job permanently red and
# therefore unread. So the peer tree fails on `critical` only, and every
# finding below that is printed, because "printed and not failed" is a
# decision a reader has to be able to see rather than a silence.
PROD_LEVEL=low
PEER_LEVEL=critical

PKG=packages/react-native-matrix-crypto

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "--- Packing $PKG ---"
TARBALL=$(cd "$PKG" && npm pack --silent --pack-destination "$WORK")
if [ ! -s "$WORK/$TARBALL" ]; then
  echo "FAIL: npm pack produced no tarball."
  echo "      Refusing to report a clean audit of nothing."
  exit 1
fi
echo "Packed $TARBALL ($(du -h "$WORK/$TARBALL" | cut -f1))"

# `--ignore-scripts`, because this installs a React Native peer tree and there
# is no reason to run anyone's install hooks to read a lockfile. The cold-
# consume job is where the absence of install scripts is asserted; this one
# only needs the dependency graph. `--no-audit` so the install's own summary
# does not get mistaken for either of the two below.
echo
echo "--- Installing it into an empty directory ---"
cd "$WORK"
npm init -y >/dev/null
npm install --ignore-scripts --no-audit --no-fund "$WORK/$TARBALL" >/dev/null

# npm exits non-zero when it finds something, which is the whole point, so the
# exit status is captured rather than allowed to end the script here.
audit_json() {
  npm audit --json "$@" 2>/dev/null || true
}

report() {
  # $1 label, $2 json, $3 the dependency count that must not be zero,
  # $4 the severity at or above which this call fails.
  # shellcheck disable=SC2016  # The `${...}` below are JavaScript template
  # literals read by node, not shell expansions; the arguments this function
  # was given are passed positionally on the last line instead.
  node -e '
    const [label, json, countKey, level] = process.argv.slice(1)
    const ORDER = ["info", "low", "moderate", "high", "critical"]
    let report
    try {
      report = JSON.parse(json)
    } catch {
      console.error(`FAIL: npm audit produced no JSON for ${label}.`)
      console.error("      That is a broken run, not a clean one.")
      process.exit(1)
    }
    const meta = report.metadata || {}
    const deps = (meta.dependencies || {})[countKey]

    // Refuse to pass having scanned nothing -- the rule every check in this
    // directory follows. `npm audit` says exactly the same thing about a tree
    // it could not resolve as about a tree with nothing wrong in it, and the
    // difference is the entire value of the run.
    if (!deps) {
      console.error(`FAIL: refusing to pass having audited nothing.`)
      console.error(`      npm reports ${deps} ${countKey} dependencies for ${label},`)
      console.error(`      so the install resolved nothing rather than resolving`)
      console.error(`      something clean.`)
      process.exit(1)
    }

    const counts = meta.vulnerabilities || {}
    const summary = ORDER.map(s => `${counts[s] || 0} ${s}`).join(", ")
    console.log(`${label}: ${deps} packages, ${summary}`)

    for (const [name, v] of Object.entries(report.vulnerabilities || {})) {
      if (!v.isDirect && !(v.via || []).some(x => typeof x === "object")) continue
      const urls = (v.via || [])
        .filter(x => typeof x === "object")
        .map(x => `${x.title} (${x.url})`)
      console.log(`  ${v.severity.padEnd(8)} ${name}${urls.length ? " -- " + urls.join("; ") : ""}`)
    }

    const failFrom = ORDER.indexOf(level)
    const failing = ORDER.slice(failFrom).reduce((n, s) => n + (counts[s] || 0), 0)
    if (failing > 0) {
      console.error(`FAIL: ${failing} advisory/advisories at ${level} or above in ${label}.`)
      process.exit(1)
    }
    console.log(`PASS: nothing at ${level} or above in ${label}.`)
  ' "$1" "$2" "$3" "$4"
}

echo
echo "--- What this package installs (threshold: $PROD_LEVEL) ---"
report "the package's own dependencies" \
  "$(audit_json --omit=dev --omit=peer)" prod "$PROD_LEVEL"

echo
echo "--- What its peers bring with them (threshold: $PEER_LEVEL) ---"
report "the react and react-native peer tree" \
  "$(audit_json --omit=dev)" peer "$PEER_LEVEL"
