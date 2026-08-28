#!/usr/bin/env bash
set -euo pipefail

# Assert that the package directory `npm pack` is about to read really holds
# the prebuilt binaries, and that npm really intends to pack them.
#
# WHY THIS EXISTS. scripts/assert-tarball-ships-binaries.sh opens the packed
# tarball and reads what is inside it, which is the right thing to check and
# the only thing that can authorise a publish. But it proves nothing about the
# tree that tarball was packed from, so when it refuses, it names the last
# step rather than the guilty one.
#
# That is not hypothetical. Release run 33209898397 (tag v0.1.0-rc.1,
# 2026-08-28) died exactly there: build-ios-release had succeeded on a real
# macOS runner and printed "Slices built: Info.plist / ios-arm64 /
# ios-arm64_x86_64-simulator", the artifact downloaded with a verified digest,
# `tar xzf ... -C packages/react-native-matrix-crypto` exited 0, and the
# tarball still came out with no xcframework in it. Three different faults
# produce that same symptom and need three different fixes:
#
#   1. the untar put the directory somewhere `npm pack` does not look;
#   2. the directory is there and npm dropped it -- a "files" entry that does
#      not match the way it is assumed to, an .npmignore, an npm version whose
#      packlist semantics differ;
#   3. something between the two removed or emptied it.
#
# Nothing in the run log could tell them apart. So this script runs
# immediately after the untar and separates them, in two parts:
#
#   PART 1, on disk. Every binary a consumer needs is where the package root
#   expects it, is big enough to be real, and has the right magic number. If
#   this part fails, the fault is upstream of npm -- the untar, the artifact,
#   or the build.
#
#   PART 2, in npm's own packlist. `npm pack --dry-run --json` is asked what
#   it would ship, and every file part 1 just found on disk must appear in
#   that answer. If part 1 passes and part 2 fails, the bytes are on disk and
#   npm chose not to pack them: the fault is package.json's "files", an
#   ignore file, or the npm version -- not the build, and not the untar.
#
# Part 2 is what the v0.1.0-rc.1 failure actually was. package.json's "files"
# listed `*.xcframework`, and under the npm bundled with the .nvmrc Node on
# the runner -- npm 10.9.8, npm-packlist 9.0.0 -- a bare glob in "files" that
# matches a DIRECTORY does not pull in that directory's contents, while a
# literal directory path (`android/src/main`, which is why Android packed
# fine) and a `dir/**` glob both do. npm 12 packs all three. So the tarball
# lost the xcframework and kept the Android libraries, on a tree that held
# both, and a contributor rehearsing locally on npm 12 saw it pass. "files"
# now names `MatrixCryptoFramework.xcframework` literally, which both npm
# versions pack -- and this script is here so that the next divergence of this
# kind is reported as a manifest problem in one line instead of being
# rediscovered.
#
# NOT a `gate:*` script, for the same reason assert-tarball-ships-binaries.sh
# is not: scripts/assert-readme-sync.sh requires every `gate:*` to run as a
# step in ci.yml, and on a fresh pull-request checkout there are no binaries
# to find, so wiring it there would make it fail on every pull request or
# teach whoever fixed that to weaken it. It belongs to the release path, where
# the binaries exist, and is invoked directly.
#
# Usage:
#   scripts/assert-tree-ships-binaries.sh [package-directory]
#
# Defaults to packages/react-native-matrix-crypto, so it can be run by hand
# after a local `ubrn build` -- scripts/rehearse-publish.sh runs it first, for
# exactly the same reason the release workflow does.

PKG="${1:-packages/react-native-matrix-crypto}"

# A real per-ABI Rust library is 4.6-9.5 MB and a real iOS slice is ~50 MB
# (artifact-sizes.json). One megabyte is far below any of them and far above
# any placeholder, so it separates "the build wrote something real here" from
# "something created this path". Same floor assert-tarball-ships-binaries.sh
# uses, deliberately: the two must not disagree about what counts as real.
MIN_BINARY_KB=1024

if [ ! -s "$PKG/package.json" ]; then
  echo "FAIL: no package.json at $PKG."
  echo "      Refusing to pass having inspected nothing."
  exit 1
fi

echo "Inspecting the package tree at $PKG"
echo "  npm $(npm --version), node $(node --version)"
echo

FAILURES=""
fail() {
  echo "FAIL: $1"
  shift
  for line in "$@"; do echo "      $line"; done
  FAILURES="${FAILURES}x"
}

size_kb() {
  # `wc -c` rather than `stat`, whose flags differ between GNU and BSD and
  # whose failure mode on the wrong platform is an error message parsed as a
  # number.
  echo $(( ( $(wc -c < "$1") + 1023 ) / 1024 ))
}

magic() { od -An -tx1 -N8 "$1" 2>/dev/null | tr -d ' \n'; }
is_elf() { case "$(magic "$1")" in 7f454c46*) return 0 ;; *) return 1 ;; esac; }
is_apple_static_lib() {
  case "$(magic "$1")" in
    213c617263683e*) return 0 ;;      # "!<arch>" -- a single-architecture ar archive
    cafebabe*)       return 0 ;;      # a fat/universal archive produced by lipo
    cffaedfe*|cefaedfe*) return 0 ;;  # Mach-O, if a slice ever ships a dylib
    *) return 1 ;;
  esac
}

# Every path this script proved is really on disk. Part 2 requires npm to
# name each of them, so the two parts can never drift apart: a binary that
# stops being checked here also stops being required in the packlist, and
# both facts are visible in one list rather than in two hardcoded copies.
REQUIRED=""

require_on_disk() {
  # require_on_disk <relative path> <kind: elf|applelib> <what it is for>
  local rel="$1" kind="$2" why="$3"
  local abs="$PKG/$rel"
  if [ ! -f "$abs" ]; then
    fail "$rel is not on disk under $PKG." \
         "$why" \
         "This is BEFORE npm pack, so npm is not the suspect: either the" \
         "artifact that carried it never arrived, the untar put it somewhere" \
         "else, or something removed it. Check the 'Unpack both platforms'" \
         "step and the artifact it read."
    return
  fi
  local kb
  kb=$(size_kb "$abs")
  if [ "$kb" -lt "$MIN_BINARY_KB" ]; then
    fail "$rel is only ${kb} KB." \
         "A real one is megabytes. This is a placeholder, a truncated" \
         "download, or a build that produced nothing."
    return
  fi
  case "$kind" in
    elf)      is_elf "$abs"              || fail "$rel is not an ELF object (first bytes: $(magic "$abs"))." ;;
    applelib) is_apple_static_lib "$abs" || fail "$rel is not an ar/Mach-O binary (first bytes: $(magic "$abs"))." ;;
  esac
  REQUIRED="${REQUIRED}${rel}
"
  echo "  ok  $rel (${kb} KB)"
}

echo "--- Part 1a: the iOS xcframework, on disk ---"

PLIST="$PKG/MatrixCryptoFramework.xcframework/Info.plist"
if [ ! -s "$PLIST" ]; then
  fail "$PKG/MatrixCryptoFramework.xcframework/Info.plist is missing or empty." \
       "Without it Xcode cannot read the framework at all, whatever binaries" \
       "happen to sit beside it -- and npm has not run yet, so this is the" \
       "untar, the artifact, or the build, not the packlist."
else
  # The plist emits LibraryIdentifier and LibraryPath in the same per-slice
  # order, so the two lists are pasted positionally -- the same reading
  # assert-tarball-ships-binaries.sh makes of the same file.
  SLICES=$(grep -A1 '<key>LibraryIdentifier</key>' "$PLIST" \
           | grep '<string>' | sed 's#.*<string>\(.*\)</string>.*#\1#')
  LIBPATHS=$(grep -A1 '<key>LibraryPath</key>' "$PLIST" \
             | grep '<string>' | sed 's#.*<string>\(.*\)</string>.*#\1#')

  if [ -z "${SLICES//[[:space:]]/}" ]; then
    fail "Info.plist advertises no slice at all." \
         "Refusing to pass having checked an xcframework that claims to" \
         "contain nothing."
  else
    i=0
    for slice in $SLICES; do
      i=$((i + 1))
      libpath=$(printf '%s\n' "$LIBPATHS" | sed -n "${i}p")
      require_on_disk "MatrixCryptoFramework.xcframework/$slice/$libpath" applelib \
        "It is the compiled Rust core for iOS, and the reason an iOS consumer needs no Rust toolchain."
    done
    echo "  ok  Info.plist advertises: $(printf '%s' "$SLICES" | tr '\n' ' ')"
  fi
  REQUIRED="${REQUIRED}MatrixCryptoFramework.xcframework/Info.plist
"
fi

echo
echo "--- Part 1b: the per-ABI Android libraries, on disk ---"

# Read the required ABI set out of android/build.gradle rather than hardcode
# it, so adding an ABI there makes this demand it without anyone remembering
# to edit two files. Same source assert-tarball-ships-binaries.sh reads.
GRADLE="$PKG/android/build.gradle"
if [ ! -s "$GRADLE" ]; then
  fail "$PKG/android/build.gradle is missing or empty." \
       "There is nothing for a consumer's Gradle build to autolink, and no" \
       "list of ABIs to check against."
  ABIS=""
else
  ABIS=$(grep -E '^[[:space:]]*abiFilters[[:space:]]+"' "$GRADLE" \
         | head -1 | grep -o '"[^"]*"' | tr -d '"')
fi

if [ -z "${ABIS//[[:space:]]/}" ]; then
  fail "could not read an abiFilters list out of android/build.gradle." \
       "Refusing to pass having compared the libraries on disk against an" \
       "empty list of required ABIs, which every check would trivially" \
       "satisfy."
else
  for abi in $ABIS; do
    require_on_disk "android/src/main/jniLibs/$abi/libmatrix_crypto_ffi.so" elf \
      "android/CMakeLists.txt imports exactly this path as my_rust_lib, for ABI $abi."
  done
fi

if [ -n "$FAILURES" ]; then
  echo
  echo "REFUSING: ${#FAILURES} problem(s) above, all of them on disk."
  echo "          npm pack has not run and is not the suspect. Nothing was"
  echo "          packed, so do not read this as a packaging problem."
  exit 1
fi

echo
echo "--- Part 2: what npm says it would pack ---"
echo
# `npm pack --dry-run --json`'s payload is not reliably on one particular
# stream across npm versions, and a previous investigation in this repository
# piped it through `2>/dev/null`, lost the whole listing, and concluded from
# the silence that there was nothing to see. Capture BOTH streams to real
# files and accept whichever one parses -- the identical precaution
# scripts/measure-artifacts.sh takes, for the identical reason.
PACK_STDOUT=$(mktemp)
PACK_STDERR=$(mktemp)
trap 'rm -f "$PACK_STDOUT" "$PACK_STDERR"' EXIT
(cd "$PKG" && npm pack --dry-run --json) >"$PACK_STDOUT" 2>"$PACK_STDERR" || true

MISSING=$(node -e '
  const fs = require("fs");
  function tryParse(p) {
    try {
      const j = JSON.parse(fs.readFileSync(p, "utf8"));
      const e = Array.isArray(j) ? j[0] : Object.values(j)[0];
      if (e && Array.isArray(e.files)) return e;
    } catch {
      // Not this stream -- try the other one.
    }
    return null;
  }
  const [outPath, errPath, requiredRaw] = process.argv.slice(1);
  const entry = tryParse(outPath) || tryParse(errPath);
  if (!entry) {
    console.log("__NOPAYLOAD__");
    process.exit(0);
  }
  const packed = new Set(entry.files.map((f) => f.path));
  const required = requiredRaw.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!required.length) {
    console.log("__NOREQUIRED__");
    process.exit(0);
  }
  console.log("__COUNT__ " + entry.files.length);
  for (const rel of required) if (!packed.has(rel)) console.log(rel);
' "$PACK_STDOUT" "$PACK_STDERR" "$REQUIRED")

if printf '%s\n' "$MISSING" | grep -q '^__NOPAYLOAD__$'; then
  fail "npm pack --dry-run --json produced no parseable { files: [...] }" \
       "payload on stdout or stderr. This check cannot say what npm would" \
       "pack, so it refuses rather than pass having read nothing."
elif printf '%s\n' "$MISSING" | grep -q '^__NOREQUIRED__$'; then
  fail "part 1 proved no required file, so comparing the packlist against it" \
       "would trivially succeed. Refusing to pass having compared nothing."
else
  PACKED_COUNT=$(printf '%s\n' "$MISSING" | sed -n 's/^__COUNT__ //p')
  ABSENT=$(printf '%s\n' "$MISSING" | grep -v '^__COUNT__' | grep . || true)
  if [ -n "$ABSENT" ]; then
    echo "  npm would pack $PACKED_COUNT files, and these are not among them:"
    printf '%s\n' "$ABSENT" | sed 's/^/    /'
    echo
    fail "every file above is on disk and npm would not pack it." \
         "The build and the untar are exonerated: part 1 read these bytes." \
         "Look at package.json's \"files\" allowlist, at any .npmignore, and" \
         "at the npm version printed at the top of this output -- npm 10's" \
         "packlist and npm 12's do not agree about a bare glob in \"files\"" \
         "that matches a directory (npm 10 packs nothing under it). Name the" \
         "directory literally, the way \"android/src/main\" is named."
  else
    REQ_COUNT=$(printf '%s\n' "$REQUIRED" | grep -c . || true)
    echo "  ok  npm would pack $PACKED_COUNT files, including all $REQ_COUNT binaries above"
  fi
fi

echo
if [ -n "$FAILURES" ]; then
  echo "REFUSING: ${#FAILURES} problem(s) above."
  exit 1
fi

echo "PASS: the package tree holds the prebuilt binaries and npm's own packlist"
echo "      names every one of them. Whatever the packed tarball turns out to"
echo "      contain, it was not assembled from a tree that was missing them."
