#!/usr/bin/env bash
set -euo pipefail

# Everything a public module means to export must reach the entry point a
# product imports from.
#
# # The hole this closes
#
# `src/index.ts` decides the public surface, and nothing checked it. Nothing in
# the package imports it, and nothing can: importing it installs the native
# module, and there is none under vitest. So a call left out of its export list
# passed every test in the repository while being unreachable by any product.
# Measured rather than assumed, twice: removing one export left both suites and
# both typechecks green, and a review then deleted the entire M3 verification
# surface -- ten names -- with every check in the repository still green.
#
# `gate:agility` does not close it and cannot: it forbids what a public name may
# be *called* and never asserts that a name is *there*. It passes with ten
# public exports deleted.
#
# # Why this derives both sides instead of listing them
#
# A list of expected names passes for the surface that existed when somebody
# wrote it and says nothing about what was added afterwards. A first attempt at
# this check was such a list, of four names out of forty-four, and its own
# commit message predicted it would rot. This reads both sides out of the source
# on every run, so a function added tomorrow is covered tomorrow, by nobody's
# diligence. Same argument `errors.test.ts` makes for walking the generated tag
# enums rather than a list of variants.
#
# # Why a gate rather than a vitest test
#
# It has to read source files, and `assert-no-logger.sh` forbids a filesystem
# import anywhere under the shipped roots -- correctly, because React Native has
# no `fs` and reaching for one there is always deliberate. Written as a test it
# failed that gate on its first line. Structural checks over source text are
# what `scripts/` is for; this is the ninth.
#
# # What it does not cover
#
# It is a text check over `export` declarations, not a type-level one. `tsc`
# already catches an entry point naming something no module declares. It reads
# only the five modules `index.ts` re-exports from: a sixth public module would
# have to be added to PUBLIC_MODULES below, though a module nothing re-exports
# from is a module nothing imports either. And it says only that a name is
# reachable, never that it is right.

PKG=packages/react-native-matrix-crypto/src
PUBLIC_MODULES="facade.ts types.ts errors.ts probe.ts signals.ts"
INDEX="$PKG/index.ts"

for f in $INDEX; do
  if [ ! -s "$f" ]; then
    echo "FAIL: refusing to pass having scanned nothing."
    echo "      $f is missing or empty."
    exit 1
  fi
done
for m in $PUBLIC_MODULES; do
  if [ ! -s "$PKG/$m" ]; then
    echo "FAIL: refusing to pass having scanned nothing."
    echo "      $PKG/$m is missing or empty."
    exit 1
  fi
done

# Declarations a module exports on purpose and the entry point withholds on
# purpose. **An allowlist, not an expected-names list**, which is the whole
# reason this grows instead of rotting: a new export nobody thought about
# fails, and only a deliberate line here excuses it. Each entry carries why.
#
#   toArrayBuffer  probe.ts   the Uint8Array-to-ArrayBuffer shim, exported so
#                             facade.ts shares it rather than keeping a second
#                             copy of the byteOffset trap. Not a product concern.
#   toCryptoError  errors.ts  normalises anything the generated layer throws.
#                             Every public call already routes its failures
#                             through it, so a product never needs to.
DELIBERATELY_INTERNAL="toArrayBuffer toCryptoError"

RESULT=$(
  PKG="$PKG" PUBLIC_MODULES="$PUBLIC_MODULES" INDEX="$INDEX" \
  DELIBERATELY_INTERNAL="$DELIBERATELY_INTERNAL" python3 <<'PY'
import os
import re
import sys

pkg = os.environ["PKG"]
modules = os.environ["PUBLIC_MODULES"].split()
index_path = os.environ["INDEX"]
internal = set(os.environ["DELIBERATELY_INTERNAL"].split())

DECLARATION = re.compile(
    r"^export\s+(?:async\s+)?(?:function|interface|type|const|enum|class)\s+([A-Za-z0-9_]+)",
    re.M,
)
# Every `export { ... } from '...'` and `export type { ... } from '...'` block,
# single-line or multi-line. `X as Y` publishes Y, so the last word wins.
REEXPORT = re.compile(r"export\s+(?:type\s+)?\{([^}]*)\}\s*from", re.S)

declared = {}
for module in modules:
    with open(os.path.join(pkg, module), encoding="utf-8") as handle:
        for name in DECLARATION.findall(handle.read()):
            declared[name] = module

with open(index_path, encoding="utf-8") as handle:
    index = handle.read()
published = set()
for body in REEXPORT.findall(index):
    for piece in body.split(","):
        piece = piece.strip()
        if piece:
            published.add(piece.split()[-1])

# The guard every check here carries: a regex that stopped matching would make
# the comparison below trivially empty, and a pass would mean "nothing was
# compared" rather than "nothing is missing".
if len(declared) < 20 or len(published) < 20:
    print("SCANNED-NOTHING %d %d" % (len(declared), len(published)))
    sys.exit(0)

missing = sorted(n for n in declared if n not in published and n not in internal)
stale = sorted(n for n in internal if n not in declared)
for name in missing:
    print("MISSING %s %s" % (name, declared[name]))
for name in stale:
    print("STALE %s" % name)
print("COUNTS %d %d" % (len(declared), len(published)))
PY
)

if printf '%s' "$RESULT" | grep -q '^SCANNED-NOTHING'; then
  echo "FAIL: refusing to pass having compared almost nothing."
  printf '%s\n' "$RESULT"
  echo "      The declaration or re-export pattern stopped matching."
  exit 1
fi

if printf '%s' "$RESULT" | grep -q '^MISSING'; then
  echo "FAIL: a public module exports a name src/index.ts does not re-export."
  printf '%s\n' "$RESULT" | grep '^MISSING' | while read -r _ name module; do
    echo "      $name  (declared in $module)"
  done
  echo "      A product cannot reach it. Add it to the entry point, or, if it is"
  echo "      internal to this package, add it to DELIBERATELY_INTERNAL in this"
  echo "      script with the reason."
  exit 1
fi

if printf '%s' "$RESULT" | grep -q '^STALE'; then
  echo "FAIL: DELIBERATELY_INTERNAL names something no module exports any more."
  printf '%s\n' "$RESULT" | grep '^STALE' | while read -r _ name; do
    echo "      $name"
  done
  echo "      Dead text that reads as though something is still being withheld."
  exit 1
fi

COUNTS=$(printf '%s' "$RESULT" | grep '^COUNTS')
echo "PASS: public surface ($(printf '%s' "$COUNTS" | cut -d' ' -f2) declarations,"
echo "      $(printf '%s' "$COUNTS" | cut -d' ' -f3) re-exported names, 2 withheld on purpose)"
