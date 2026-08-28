#!/usr/bin/env bash
set -euo pipefail

# Spec section 7.2: the bridge has no logger. The example app is excluded
# because it is not the bridge.
#
# Generated code is NOT excluded wholesale, and the C++ half of it used not to
# be scanned at all. `cpp/generated/matrix_crypto.cpp` carries five
# `std::cout` writes on UniFFI callback error paths, it is compiled into the
# shipped `libreact-native-matrix-crypto.so` and into every consumer's iOS
# binary, and until 2026-08-28 this gate had never read a line of C++. It
# reported "no logger" over a surface it did not open. See the C++ section
# below for what is now scanned, what is tolerated there, and why.

# What counts as generated is scripts/generated-paths.txt, shared with
# scripts/assert-no-drift.sh. See that file's header for the C9 history.
GENERATED_PATHS_FILE="scripts/generated-paths.txt"

if [ ! -f "$GENERATED_PATHS_FILE" ]; then
  echo "FAIL: $GENERATED_PATHS_FILE is missing."
  echo "      It decides which files this gate may exempt; without it the"
  echo "      exemptions cannot be justified and the gate must not pass."
  exit 1
fi

GENERATED_PREFIXES=()
while IFS= read -r ln; do
  ln="${ln%%#*}"
  ln="$(printf '%s' "$ln" | tr -d '[:space:]')"
  [ -n "$ln" ] || continue
  GENERATED_PREFIXES+=("$ln")
done < "$GENERATED_PATHS_FILE"

if [ "${#GENERATED_PREFIXES[@]}" -eq 0 ]; then
  echo "FAIL: $GENERATED_PATHS_FILE lists no paths."
  echo "      Refusing to pass with an exemption list nobody wrote."
  exit 1
fi

# True when $1 is, or is under, a path scripts/assert-no-drift.sh regenerates
# and diffs. That gate's empty-diff requirement is what makes an exemption
# here safe: a file it covers is byte-for-byte what `ubrn generate` emits, so
# a tolerated write cannot have been planted by hand without gate:drift
# failing first.
is_generated() {
  candidate="$1"
  for prefix in "${GENERATED_PREFIXES[@]}"; do
    case "$candidate" in
      "$prefix" | "$prefix"/*) return 0 ;;
    esac
  done
  return 1
}

# Derive Rust crate source directories from workspace metadata instead of
# hardcoding them, so new crates added to the workspace are automatically
# covered without editing this script.
RUST_SRC_DIRS=$(cargo metadata --format-version 1 --no-deps \
  --manifest-path rust/Cargo.toml 2>/dev/null \
  | node -e '
      const m = JSON.parse(require("fs").readFileSync(0, "utf8"));
      m.packages.forEach(p => {
        const src = p.manifest_path.replace(/\/Cargo\.toml$/, "/src");
        console.log(src);
      });
    ' 2>/dev/null || printf "rust/matrix-crypto-core/src\nrust/matrix-crypto-ffi/src")

# Verify that we actually got some Rust crate directories. If cargo metadata
# succeeds but produces no output (e.g. due to JSON shape change), RUST_SRC_DIRS
# would be empty, the existence loop below would iterate zero times, and we would
# silently pass having scanned no Rust at all — exactly the failure mode we guard
# against elsewhere.
if [ -z "${RUST_SRC_DIRS// /}" ]; then
  echo "FAIL: could not determine any Rust crate source directories."
  echo "      Refusing to pass having scanned no Rust at all."
  exit 1
fi

# Verify each Rust scan root exists before scanning. A missing root makes
# grep produce an empty result indistinguishable from "no violations found",
# which would silently pass over a moved or deleted crate.
for root in $RUST_SRC_DIRS; do
  if [ ! -d "$root" ]; then
    echo "FAIL: scan root '$root' does not exist."
    echo "      The gate cannot pass over a target that is not there --"
    echo "      if a path moved, update the workspace metadata deliberately."
    exit 1
  fi
done

# Check Rust crates for logging patterns.
# - print! and eprint! are included, not just println!/eprintln!
# - Forbid imports outright (use log::*, use tracing::*) because that
#   prevents bare calls like info!("...") after "use log::info;"
RUST_HITS=$(for root in $RUST_SRC_DIRS; do
  grep -rnE '(println!|eprintln!|print!|eprint!|dbg!|use\s+(log|tracing)::)' "$root" 2>/dev/null || true
done)

PKG_DIR="packages/react-native-matrix-crypto"

# Derive the scan roots from package.json's "files" allowlist -- i.e. from
# what actually ships -- instead of naming directories here.
#
# This gate scanned only `src` until 2026-08-28, and `interop/` had by then
# been in "files" for two tasks, carrying 445 lines of library TypeScript that
# nothing ever looked at. There was no violation in it; the rule was simply
# unenforced over half the shipped surface, which is indistinguishable from a
# rule that holds. Deriving the roots means a directory added to "files"
# tomorrow is covered without anyone remembering to come back here.
#
# Negations (`!src/**/*.test.ts`) and globs (`*.aar`, `*.xcframework`,
# `*.podspec`) are skipped: the first remove files rather than name roots, and
# the second name binaries. Test files inside a shipped directory ARE scanned,
# which is what this gate already did for `src`.
#
# FILE entries are kept alongside directory entries, because "files" names
# some shipped sources individually: `android/cpp-adapter.cpp` is a shipped
# C++ translation unit that no directory entry reaches. `find` takes a file as
# a root perfectly well, so both kinds go into one list.
SHIPPED_ROOTS=$(node -e '
  const fs = require("fs");
  const dir = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(dir + "/package.json", "utf8"));
  for (const entry of pkg.files || []) {
    if (entry.startsWith("!") || entry.includes("*")) continue;
    const p = dir + "/" + entry;
    if (fs.existsSync(p)) console.log(p);
  }
' "$PKG_DIR")

# Refuse to pass having scanned nothing: an unreadable package.json, an empty
# "files", or a renamed directory would leave SHIPPED_ROOTS empty, the finds
# below would return nothing, and this gate would print PASS having read no
# source at all.
if [ -z "${SHIPPED_ROOTS//[[:space:]]/}" ]; then
  echo "FAIL: no shipped scan root could be derived from"
  echo "      $PKG_DIR/package.json's \"files\"."
  echo "      Refusing to pass having scanned nothing."
  exit 1
fi

for root in $SHIPPED_ROOTS; do
  if [ ! -e "$root" ]; then
    echo "FAIL: scan root '$root' does not exist."
    echo "      The gate cannot pass over a target that is not there."
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# TypeScript: the bridge may not use console.*
# ---------------------------------------------------------------------------
#
# Generated TypeScript is exempt because we do not control it. WHICH files
# those are is now decided by scripts/generated-paths.txt -- the same list
# gate:drift regenerates -- and no longer by sniffing the first three lines of
# every file for the string "uniffi-bindgen-react-native".
#
# The sniff was a second oracle answering a question the drift gate already
# answered, and the two disagreed in the direction that hides things: any
# hand-written .ts under a shipped directory the drift gate does not
# regenerate -- anything in `interop/`, anything in `src/` outside
# `src/generated` -- could exempt itself from this scan by naming the tool in
# a comment on line 1, while gate:drift never looked at it because it is not a
# generated path. Neither gate watched it. Deciding by the drift list means an
# exemption is always backed by an empty-diff proof that the file really is
# machine-generated. (M1 final review, item C9.)
TS_FILES=""
for f in $(find $SHIPPED_ROOTS -type f \( -name '*.ts' -o -name '*.tsx' \)); do
  if ! is_generated "$f"; then
    TS_FILES="$TS_FILES $f"
  fi
done

# The second half of the "scanned nothing" guard. The roots exist and were
# derived from what ships, but if every file under them were excluded -- or if
# the find above stopped matching -- the grep would return no hits, which is
# byte-for-byte what a clean tree looks like. This package's public entry
# point is TypeScript, so zero hand-written TypeScript files means the scan
# broke, not that the bridge is clean.
if [ -z "${TS_FILES//[[:space:]]/}" ]; then
  echo "FAIL: no hand-written TypeScript was found under: $(echo $SHIPPED_ROOTS | tr '\n' ' ')"
  echo "      Refusing to pass having scanned nothing."
  exit 1
fi

TS_HITS=$(grep -nE '\bconsole\.[a-z]+' $TS_FILES 2>/dev/null || true)

# ---------------------------------------------------------------------------
# C++ and Objective-C++: the shipped native surface
# ---------------------------------------------------------------------------
#
# This section did not exist until 2026-08-28. The gate had never read a line
# of C++, and every write to a stream anywhere in the shipped bridge is in
# C++: five `std::cout` calls in cpp/generated/matrix_crypto.cpp, one per
# UniFFI callback trampoline, each on a `catch (const jsi::JSError &error)`
# path. `strings` on the release AAR's libreact-native-matrix-crypto.so finds
# four of the five literals plus an undefined `_ZNSt6__ndk14coutE`, so they
# are in the shipped binary and not merely in the shipped source. The fifth
# (UniffiForeignFutureDroppedCallback) is dropped by the linker only because
# nothing references it today.
#
# THESE CANNOT BE CONFIGURED AWAY. ubrn's C++ generator takes no configuration
# at all (`pub(crate) struct CppConfig {}` is literally empty), the write is
# unconditional in the askama template compiled into the binary
# (crates/ubrn_bindgen/src/bindings/gen_cpp/templates/CallbackFunction.cpp),
# no CLI flag overrides templates, and the `logLevel` knob in uniffi.toml
# governs generated TypeScript only. Editing the generated file is forbidden
# and gate:drift would catch it. So the honest choices were to fail forever or
# to tolerate exactly this shape and say so in the README and the spec. We
# tolerate exactly this shape and say so.
#
# WHAT IS TOLERATED, and only inside a path gate:drift regenerates:
#
#     } catch (const jsi::JSError &error) {
#         std::cout << "Error in callback <Name>: "
#                 << error.what() << std::endl;
#
# All three lines must match. That pins the write to a fixed literal plus
# `jsi::JSError::what()`, which is the JS exception's `.message` and `.stack`
# (jsi.cpp: `what_ = message_ + "\n\n" + stack_`). It is not a general amnesty
# for generated C++: any other `std::cout`, any other stream, any platform
# logger, or this same site with one more `<<` on it, fails.
#
# A callback interface added in M2 generates this same shape and passes
# without anyone editing this file. A CHANGED shape does not, which is the
# point: if a ubrn upgrade starts printing an argument rather than a fixed
# literal, this gate fails and someone re-reads the template.
FORBIDDEN_NATIVE='std::(cout|cerr|clog|wcout|wcerr)|(^|[^_[:alnum:]])(printf|fprintf|vprintf|vfprintf|puts|fputs|perror|syslog|NSLog|RCTLog)[[:space:]]*[(]|__android_log|os_log|(^|[^_[:alnum:]])ALOG[A-Z]*[[:space:]]*[(]'

NATIVE_FILES=$(find $SHIPPED_ROOTS -type f \( \
  -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \
  -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \
  -o -name '*.m' -o -name '*.mm' \) | sort)

# Same discipline as the TypeScript half. This package is a JSI turbo module:
# it ships the C++ translation unit that installs the host object. Zero native
# sources means the derivation broke, not that the C++ is clean.
if [ -z "${NATIVE_FILES//[[:space:]]/}" ]; then
  echo "FAIL: no C/C++/Objective-C source was found under: $(echo $SHIPPED_ROOTS | tr '\n' ' ')"
  echo "      This package ships a JSI turbo module; zero native sources means"
  echo "      the scan broke. Refusing to pass having scanned nothing."
  exit 1
fi

NATIVE_HITS=""
for f in $NATIVE_FILES; do
  gen=0
  if is_generated "$f"; then gen=1; fi
  out=$(awk -v FORBIDDEN="$FORBIDDEN_NATIVE" -v GEN="$gen" -v FNAME="$f" '
    function is_ubrn_callback_site(i) {
      return (line[i]   ~ /^[[:space:]]*std::cout << "Error in callback [A-Za-z0-9_]+: "$/ &&
              line[i+1] ~ /^[[:space:]]*<< error[.]what[(][)] << std::endl;$/ &&
              line[i-1] ~ /^[[:space:]]*[}] catch [(]const jsi::JSError &error[)] [{]$/)
    }
    { line[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        if (line[i] !~ FORBIDDEN) continue
        if (GEN == 1 && is_ubrn_callback_site(i)) continue
        printf "%s:%d:%s\n", FNAME, i, line[i]
      }
    }
  ' "$f")
  if [ -n "$out" ]; then
    NATIVE_HITS="$NATIVE_HITS$out
"
  fi
done

# Count the tolerated sites and print the number on success. An allowlist
# whose size nobody sees is an allowlist that rots: this makes the count move
# in the CI log the day the Rust surface grows a callback interface.
NATIVE_ALLOWED=$(grep -hcE '^[[:space:]]*std::cout << "Error in callback [A-Za-z0-9_]+: "$' \
  $NATIVE_FILES 2>/dev/null | awk '{ s += $1 } END { print s + 0 }')

if [ -n "${RUST_HITS}${TS_HITS}${NATIVE_HITS}" ]; then
  echo "FAIL: the bridge must not log. Spec section 7.2."
  [ -n "$RUST_HITS" ] && echo "$RUST_HITS"
  [ -n "$TS_HITS" ] && echo "$TS_HITS"
  [ -n "$NATIVE_HITS" ] && printf '%s' "$NATIVE_HITS"
  echo "      Diagnostics belong in a sink the product injects and owns."
  echo "      In generated C++ the ONLY tolerated write is ubrn's"
  echo "      'std::cout << \"Error in callback X: \" << error.what()' on a"
  echo "      catch(jsi::JSError) path, and all three of its lines must match."
  exit 1
fi

echo "PASS: no logger"
echo "      Scanned: Rust crates, shipped TypeScript, shipped C/C++/Objective-C."
echo "      Tolerated: $NATIVE_ALLOWED ubrn callback-error std::cout sites in generated C++,"
echo "      documented in README.md and design spec section 7.2."
