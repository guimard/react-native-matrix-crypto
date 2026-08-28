#!/usr/bin/env bash
set -euo pipefail

# Assert that a packed npm tarball actually contains the prebuilt binaries the
# README promises, before anything publishes it.
#
# WHY THIS EXISTS. The README has said since M1: "No Rust toolchain is
# required. The published package ships prebuilt binaries ... This is verified
# in CI by a job that installs the real tarball." It was not verified. The
# `.aar`, the `.xcframework` and `jniLibs/` are build outputs, all three
# gitignored, so the tarball `cold-consume` packed from a fresh checkout
# contained no binary at all -- 68 KB of source, measured 2026-08-28 -- and the
# job passed anyway because it only ever asked whether `npm pack` had produced
# *a* file and whether `require.resolve` returned *a* path.
#
# The lesson is narrow and worth stating: a build step exiting zero is not
# evidence that its output reached the artifact. Between `ubrn build` and
# `npm publish` sit `package.json`'s "files" allowlist, `.npmignore`, and
# whatever happened to be left on the builder's disk -- and that gap has
# already swallowed a real xcframework once (see scripts/measure-artifacts.sh,
# which was written after `npm pack` silently shipped a 39 KB source-only
# tarball with a 51 MB xcframework sitting right next to it). So this script
# asserts on the packed bytes: it opens the tarball that is about to be
# published and reads what is inside it.
#
# WHAT IT REFUSES, and each of these has been watched failing (see
# release-workflow-report.md):
#   * a tarball with no iOS xcframework, or one whose Info.plist advertises a
#     slice whose binary is not in the tarball;
#   * an xcframework with no device slice, or no simulator slice, or missing
#     an architecture the README's platform table promises;
#   * a missing `android/src/main/jniLibs/<abi>/libmatrix_crypto_ffi.so` for
#     any ABI `android/build.gradle` declares -- this is the file
#     `android/CMakeLists.txt` links as `my_rust_lib`, so it is *the* reason a
#     consumer needs no Rust toolchain, and it is the one most easily lost:
#     `.gitignore` ignores `jniLibs/`;
#   * a binary present but implausibly small, or not actually a binary --
#     a zero-byte or text placeholder is caught by a size floor and a magic
#     number check, so "the path exists" is never mistaken for "the code is
#     there";
#   * a `.aar` that is present but is not a real zip, or does not carry
#     every ABI -- its absence is not refused, see that section's comment;
#   * a package.json in the tarball that declares an install-time script or
#     ships a binding.gyp, either of which can reach for a compiler on a
#     consumer's machine;
#   * a tarball over the spec section 10 size budget.
#
# Deliberately NOT a `gate:*` script. `scripts/assert-readme-sync.sh` requires
# every `gate:*` in package.json to run as a step in `.github/workflows/ci.yml`,
# and this check cannot run there: on a fresh checkout there are no binaries to
# find, so wiring it into the pull-request job would make it fail on every pull
# request or, worse, teach whoever fixed that to weaken it. It belongs to the
# release path, where the binaries exist. It is invoked directly, the way
# `scripts/measure-artifacts.sh` and `scripts/run-level-two-interop.sh` are.
#
# Usage:
#   scripts/assert-tarball-ships-binaries.sh <tarball.tgz> [expected-version]

if [ $# -lt 1 ]; then
  echo "usage: $0 <tarball.tgz> [expected-version]" >&2
  exit 2
fi

TARBALL="$1"
EXPECTED_VERSION="${2:-}"

# Spec section 10's M1b budget: a single combined tarball across both
# platforms, roughly 150 MB. Expressed in KB against the *packed* .tgz, which
# is the byte count npm uploads and the registry enforces against.
MAX_TARBALL_KB=$((150 * 1024))

# A real per-ABI Rust library is 4.6-9.5 MB and a real iOS slice is ~50 MB
# (artifact-sizes.json). One megabyte is far below any of them and far above
# any placeholder, so it separates "the build wrote something real here" from
# "something created this path".
MIN_BINARY_KB=1024

if [ ! -s "$TARBALL" ]; then
  echo "FAIL: no tarball at $TARBALL (missing or empty)."
  echo "      Refusing to pass having inspected nothing."
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

tar xzf "$TARBALL" -C "$WORK"
PKG="$WORK/package"

if [ ! -d "$PKG" ]; then
  echo "FAIL: $TARBALL does not unpack to a 'package/' directory."
  echo "      That is not an npm tarball."
  exit 1
fi

# The packed file list, printed once so a failure below can be read against
# what was actually in the tarball rather than against what someone assumed.
FILE_LIST=$(cd "$PKG" && find . -type f | sed 's#^\./##' | sort)
FILE_COUNT=$(printf '%s\n' "$FILE_LIST" | grep -c . || true)

echo "Packed file list ($FILE_COUNT files, $(du -k "$TARBALL" | cut -f1) KB packed):"
printf '%s\n' "$FILE_LIST" | sed 's/^/  /'
echo

# Refuse to pass having inspected nothing: an empty or near-empty unpack would
# otherwise sail through every "is this file missing" test below by having no
# files to contradict them. The real tarball carries 30-plus entries.
if [ "$FILE_COUNT" -lt 20 ]; then
  echo "FAIL: only $FILE_COUNT files unpacked from $TARBALL."
  echo "      Refusing to pass having inspected an all-but-empty tarball."
  exit 1
fi

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

# Magic numbers, read straight off the file. A path existing proves a path
# exists; these prove the bytes are the kind of object they are named after,
# which is what stops a stray text file or a truncated download from reading
# as a shipped binary.
magic() { od -An -tx1 -N8 "$1" 2>/dev/null | tr -d ' \n'; }

is_elf() { case "$(magic "$1")" in 7f454c46*) return 0 ;; *) return 1 ;; esac; }
is_zip() { case "$(magic "$1")" in 504b0304*) return 0 ;; *) return 1 ;; esac; }
is_apple_static_lib() {
  case "$(magic "$1")" in
    213c617263683e*) return 0 ;;  # "!<arch>"  -- a single-architecture ar archive
    cafebabe*)       return 0 ;;  # a fat/universal archive produced by lipo
    cffaedfe*|cefaedfe*) return 0 ;;  # Mach-O, if a slice ever ships a dylib
    *) return 1 ;;
  esac
}

require_binary() {
  # require_binary <relative path> <kind: elf|zip|applelib> <what it is for>
  local rel="$1" kind="$2" why="$3"
  local abs="$PKG/$rel"
  if [ ! -f "$abs" ]; then
    fail "the tarball does not contain $rel" \
         "$why" \
         "It is a build output and .gitignore ignores it, so a tarball packed" \
         "from a checkout that did not run the build will be missing it and" \
         "npm will report no error at all."
    return
  fi
  local kb
  kb=$(size_kb "$abs")
  if [ "$kb" -lt "$MIN_BINARY_KB" ]; then
    fail "$rel is only ${kb} KB." \
         "A real one is megabytes. This is a placeholder, a truncated copy," \
         "or a build that produced nothing, not a shipped binary."
    return
  fi
  case "$kind" in
    elf)      is_elf "$abs"              || fail "$rel is not an ELF object (first bytes: $(magic "$abs"))." ;;
    zip)      is_zip "$abs"              || fail "$rel is not a zip archive (first bytes: $(magic "$abs"))." ;;
    applelib) is_apple_static_lib "$abs" || fail "$rel is not an ar/Mach-O binary (first bytes: $(magic "$abs"))." ;;
  esac
  echo "  ok  $rel (${kb} KB)"
}

echo "--- iOS: the xcframework ---"

PLIST="$PKG/MatrixCryptoFramework.xcframework/Info.plist"
if [ ! -s "$PLIST" ]; then
  fail "the tarball has no MatrixCryptoFramework.xcframework/Info.plist." \
       "Without it Xcode cannot read the framework at all, whatever binaries" \
       "happen to sit beside it."
else
  # Every slice the plist advertises must have its binary in the tarball. This
  # is the direction that actually breaks a consumer: Xcode reads the plist,
  # picks the slice matching the destination, and fails on a missing file.
  SLICES=$(grep -A1 '<key>LibraryIdentifier</key>' "$PLIST" \
           | grep '<string>' | sed 's#.*<string>\(.*\)</string>.*#\1#')
  LIBPATHS=$(grep -A1 '<key>LibraryPath</key>' "$PLIST" \
             | grep '<string>' | sed 's#.*<string>\(.*\)</string>.*#\1#')

  if [ -z "${SLICES//[[:space:]]/}" ]; then
    fail "Info.plist advertises no slice at all." \
         "Refusing to pass having checked an xcframework that claims to" \
         "contain nothing."
  else
    # paste the two lists positionally: the plist emits them in the same
    # per-slice order.
    i=0
    for slice in $SLICES; do
      i=$((i + 1))
      libpath=$(printf '%s\n' "$LIBPATHS" | sed -n "${i}p")
      require_binary "MatrixCryptoFramework.xcframework/$slice/$libpath" applelib \
        "It is the compiled Rust core for iOS, and the reason an iOS consumer needs no Rust toolchain."
    done

    # And the other direction: what the README's platform support table
    # promises. Reading only the plist would be circular -- a plist listing a
    # single simulator slice would satisfy itself -- so the coverage a
    # consumer was promised is asserted independently of what this particular
    # build happened to produce.
    #
    # A device slice has no SupportedPlatformVariant key; a simulator slice's
    # identifier ends in -simulator (Apple's xcframework layout).
    if ! printf '%s\n' "$SLICES" | grep -qv -- '-simulator$'; then
      fail "the xcframework has no device slice, only simulator slices:" \
           "$(printf '%s' "$SLICES" | tr '\n' ' ')" \
           "An app built for a real iPhone would not link. The release build" \
           "must pass --targets aarch64-apple-ios as well as the simulator" \
           "targets."
    fi
    if ! printf '%s\n' "$SLICES" | grep -q -- '-simulator$'; then
      fail "the xcframework has no simulator slice:" \
           "$(printf '%s' "$SLICES" | tr '\n' ' ')" \
           "Nobody could run the library in Xcode's simulator."
    fi
    for arch in arm64 x86_64; do
      if ! grep -q "<string>$arch</string>" "$PLIST"; then
        fail "the xcframework advertises no $arch architecture." \
             "The README's platform support table promises arm64 device," \
             "arm64 simulator and x86_64 simulator."
      fi
    done
    echo "  ok  slices: $(printf '%s' "$SLICES" | tr '\n' ' ')"
  fi
fi

echo
echo "--- Android: the per-ABI Rust libraries CMake links ---"

# The required ABI set is read out of the packed android/build.gradle rather
# than hardcoded here, so adding an ABI there makes this assertion demand it
# without anyone remembering to edit two files.
GRADLE="$PKG/android/build.gradle"
if [ ! -s "$GRADLE" ]; then
  fail "the tarball has no android/build.gradle." \
       "There is nothing for a consumer's Gradle build to autolink."
  ABIS=""
else
  ABIS=$(grep -E '^[[:space:]]*abiFilters[[:space:]]+"' "$GRADLE" \
         | head -1 | grep -o '"[^"]*"' | tr -d '"')
fi

if [ -z "${ABIS//[[:space:]]/}" ]; then
  fail "could not read an abiFilters list out of android/build.gradle." \
       "Refusing to pass having compared the shipped libraries against an" \
       "empty list of required ABIs, which every check below would trivially" \
       "satisfy."
else
  for abi in $ABIS; do
    require_binary "android/src/main/jniLibs/$abi/libmatrix_crypto_ffi.so" elf \
      "android/CMakeLists.txt imports exactly this path as my_rust_lib and links it into the module's own .so, for ABI $abi."
  done
fi

echo
echo "--- Android: the prebuilt .aar ---"

# NOT required, and this used to require it.
#
# The reason given for requiring it was a README sentence: "A fully prebuilt,
# already linked `.aar` ships alongside those, for a consumer who would rather
# not build from source at all." No such consumer exists, and no mechanism
# serves one. React Native autolinking includes `android/build.gradle` as a
# Gradle subproject and builds the module from source; nothing in that file,
# in `android/CMakeLists.txt`, in `MatrixCrypto.podspec` or in the example
# app's Gradle setup names the `.aar`, and no document tells a consumer how to
# use it. M2 spec section 9 step 2 records it as "Not needed. Retained."
#
# So a sentence with no mechanism behind it had become a hard release
# requirement, over a file that is 29068 KB of the 219772 KB unpacked tarball
# and duplicates the per-ABI `.so` files checked directly above.
#
# What survives is the narrower true claim: `package.json`'s "files" names
# `*.aar`, so while one ships it must be a real archive carrying every ABI,
# because a broken 29 MB zip in the artifact is worse than no zip. Whether it
# should ship at all is a packaging decision, deliberately left open here
# rather than settled by a gate: see the M2 spec section 9 step 2.
AAR=$(printf '%s\n' "$FILE_LIST" | grep -E '\.aar$' | head -1 || true)
if [ -z "$AAR" ]; then
  echo "  --  no .aar in the tarball. Not a failure: nothing autolinks against"
  echo "      it and no consumer path uses it. See this section's comment."
else
  require_binary "$AAR" zip \
    "package.json's \"files\" ships it, so while it ships it must be real code rather than an empty archive."
  # A zip with the right name and no native code in it would pass every check
  # above. Look inside.
  if [ -n "${ABIS//[[:space:]]/}" ] && command -v unzip >/dev/null 2>&1; then
    AAR_ENTRIES=$(unzip -Z1 "$PKG/$AAR" 2>/dev/null || true)
    if [ -z "${AAR_ENTRIES//[[:space:]]/}" ]; then
      fail "could not list the contents of $AAR." \
           "Refusing to pass having looked inside an archive and seen nothing."
    else
      for abi in $ABIS; do
        if ! printf '%s\n' "$AAR_ENTRIES" | grep -q "^jni/$abi/libmatrix_crypto_ffi\.so$"; then
          fail "$AAR carries no jni/$abi/libmatrix_crypto_ffi.so." \
               "It was built for fewer ABIs than android/build.gradle declares."
        fi
      done
      echo "  ok  $AAR carries all of: $(printf '%s' "$ABIS" | tr '\n' ' ')"
    fi
  fi
fi

echo
echo "--- The rest of what a consumer needs ---"

# Not binaries, but shipped-or-broken all the same. Each of these is reachable
# only through package.json's "files" allowlist, and every one of them has a
# consumer that fails at build time rather than at install time if it is
# absent -- the class of breakage npm reports as success.
for required in \
  package.json \
  README.md \
  LICENSE \
  MatrixCrypto.podspec \
  src/index.ts \
  src/index.tsx \
  src/NativeMatrixCrypto.ts \
  src/generated/matrix_crypto.ts \
  src/generated/matrix_crypto-ffi.ts \
  cpp/generated/matrix_crypto.cpp \
  cpp/generated/matrix_crypto.hpp \
  android/build.gradle \
  android/CMakeLists.txt \
  android/cpp-adapter.cpp
do
  if [ ! -s "$PKG/$required" ]; then
    fail "the tarball does not contain $required (or it is empty)."
  fi
done
echo "  ok  entry point, generated bindings, podspec and Gradle/CMake wiring present"

echo
echo "--- The manifest npm would publish ---"

MANIFEST_REPORT=$(node -e '
  const fs = require("fs");
  const pkg = JSON.parse(fs.readFileSync(process.argv[1] + "/package.json", "utf8"));
  const forbidden = ["preinstall", "install", "postinstall", "prepare"];
  const found = forbidden.filter((s) => (pkg.scripts || {})[s]);
  const out = [];
  if (found.length) {
    out.push("SCRIPTS " + found.join(","));
  }
  if (fs.existsSync(process.argv[1] + "/binding.gyp")) {
    out.push("BINDING_GYP");
  }
  out.push("NAME " + pkg.name);
  out.push("VERSION " + pkg.version);
  console.log(out.join("\n"));
' "$PKG")

PACKED_NAME=$(printf '%s\n' "$MANIFEST_REPORT" | sed -n 's/^NAME //p')
PACKED_VERSION=$(printf '%s\n' "$MANIFEST_REPORT" | sed -n 's/^VERSION //p')

if printf '%s\n' "$MANIFEST_REPORT" | grep -q '^SCRIPTS '; then
  fail "the packed package.json declares install-time scripts: $(printf '%s\n' "$MANIFEST_REPORT" | sed -n 's/^SCRIPTS //p')" \
       "npm runs preinstall/install/postinstall (and prepare, for some install" \
       "shapes) on the consumer's machine. Any of them can invoke a compiler," \
       "which is exactly what \"no Rust toolchain is required\" denies."
fi
if printf '%s\n' "$MANIFEST_REPORT" | grep -q '^BINDING_GYP'; then
  fail "the tarball ships a binding.gyp." \
       "npm runs node-gyp against it at install time even with no script" \
       "declared."
fi
if [ -z "$PACKED_NAME" ] || [ -z "$PACKED_VERSION" ]; then
  fail "could not read a name and version out of the packed package.json." \
       "Refusing to pass having read no manifest."
else
  echo "  ok  $PACKED_NAME@$PACKED_VERSION, no install-time script, no binding.gyp"
fi

if [ -n "$EXPECTED_VERSION" ] && [ "$PACKED_VERSION" != "$EXPECTED_VERSION" ]; then
  fail "the tarball carries version $PACKED_VERSION, not the expected $EXPECTED_VERSION." \
       "Whatever produced this tarball is not the tree the release is for."
fi

echo
echo "--- Size ---"

TARBALL_KB=$(du -k "$TARBALL" | cut -f1)
UNPACKED_KB=$(du -sk "$PKG" | cut -f1)
echo "  packed   ${TARBALL_KB} KB"
echo "  unpacked ${UNPACKED_KB} KB"
if [ "$TARBALL_KB" -gt "$MAX_TARBALL_KB" ]; then
  fail "the packed tarball is ${TARBALL_KB} KB, over the ${MAX_TARBALL_KB} KB budget." \
       "Spec section 10 sizes a single combined tarball across both platforms" \
       "at roughly 150 MB. Record the measurement with" \
       "scripts/measure-artifacts.sh and decide deliberately before raising" \
       "this."
fi

echo
if [ -n "$FAILURES" ]; then
  echo "REFUSING: ${#FAILURES} problem(s) above. This tarball must not be published."
  exit 1
fi

echo "PASS: $TARBALL ships the prebuilt binaries it promises."
echo "      iOS xcframework with every advertised slice present, device and"
echo "      simulator, arm64 and x86_64; the per-ABI Rust libraries Android's"
echo "      CMake links; any .aar present carrying every ABI; no install-time"
echo "      script."
