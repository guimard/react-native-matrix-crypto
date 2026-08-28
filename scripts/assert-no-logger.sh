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

# Every exemption below rests on this, so it is checked before any exemption
# is granted rather than trusted.
#
# The comment that used to stand here said the drift gate's empty diff made an
# exemption safe, because "a tolerated write cannot have been planted by hand
# without gate:drift failing first". THAT WAS FALSE, and it was false for the
# only case that matters. gate:drift sees modifications and untracked files.
# It never sees ADDITIONS: codegen does not delete what it does not emit, so a
# hand-written file COMMITTED under a listed directory produces no diff at
# all. Reproduced 2026-08-28 with a tracked
# src/generated/review-helper.ts holding `console.log('PLAINTEXT ' +
# plaintext)`: gate:logger, gate:drift and gate:stubs all passed, and
# `files: ["src"]` ships it.
#
# So the prefix list alone cannot justify an exemption, and does not any more.
# scripts/generated-file-set.sh requires the path oracle and the generator's
# own header to select exactly the same committed files, in both directions --
# which the planted file above fails, because nothing wrote a header into it.
# See that script for the full argument and for what each direction catches.
#
# WHAT THIS GATE ALONE STILL CANNOT SEE, said plainly rather than left for the
# next reviewer to find: a forger who types the header in as well as choosing
# the directory satisfies both oracles here. Constructed and watched passing
# this gate. It does not survive the `gates` job, because two other checks run
# in it and each rejects that file on its own terms -- assert-no-drift.sh runs
# the generator and requires every committed file under a generated path to be
# one this run actually WROTE, and assert-generated-not-stubbed.sh pins how
# many artifacts there are, so a twentieth is a failure whatever it contains.
# Neither of those can run from here: one needs a codegen, the other is the
# gate that owns the count.
if ! ./scripts/generated-file-set.sh >/dev/null; then
  echo "FAIL: the generated-file set does not hold together, so this gate"
  echo "      cannot justify exempting anything from the no-logger rule."
  echo "      The cross-check's own message above says which file broke it."
  exit 1
fi

# True when $1 is, or is under, a path scripts/assert-no-drift.sh regenerates
# and diffs. Two things now make an exemption here safe, and it takes both:
# gate:drift proves a listed file is byte-for-byte what `ubrn generate`
# emits, and the cross-check above proves no hand-written file is sitting
# under a listed path claiming the same exemption.
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
#     try {
#         ... no jsi::JSError constructed here ...
#     } catch (const jsi::JSError &error) {
#         std::cout << "Error in callback Uniffi<Name>: "
#                 << error.what() << std::endl;
#
# All three of the last lines must match. That pins the write to a fixed
# literal plus `jsi::JSError::what()`, which is the JS exception's `.message`
# and `.stack` (jsi.cpp: `what_ = message_ + "\n\n" + stack_`). It is not a
# general amnesty for generated C++: any other `std::cout`, any other stream,
# any platform logger, or this same site with one more `<<` on it, fails.
#
# ARRANGEMENT IS NOT ENOUGH, and until 2026-08-28 arrangement was all that was
# checked. The 2026-08-28 verification-infrastructure review constructed this,
# under cpp/generated/ so `is_generated()` is true, and the gate PASSED --
# printing "Tolerated: 6" where it had printed 5:
#
#     try {
#       throw jsi::JSError(rt, sessionKey);
#     } catch (const jsi::JSError &error) {
#       std::cout << "Error in callback Exfil: "
#               << error.what() << std::endl;
#     }
#
# `error.what()` is whatever the code put into the JSError. The README's
# justification for tolerating this site -- "No call argument, ciphertext, key
# or identifier is interpolated into that stream" -- is a property of ubrn's
# template, and the gate now checks the two parts of it that are checkable:
#
#   * THE NAME. The only free text in the shape is the callback name in the
#     literal, which ubrn fills with the name of the trampoline it just
#     generated. Every one of them begins with "Uniffi"
#     (UniffiRustFutureContinuationCallback, UniffiCallbackInterfaceFree,
#     UniffiCallbackInterfaceProbeObserverMethod0, ...). "Exfil" does not.
#
#   * THE PROVENANCE OF `error`. The tolerated write prints an error the
#     JAVASCRIPT side threw out of `cb.call(...)`, never one this translation
#     unit manufactured. So the try block the catch closes may not mention
#     jsi::JSError at all. Verified against the committed file: none of the
#     five try blocks does, while ubrn's 23 other JSError constructions all
#     sit outside them.
#
# If the try block cannot be found at all, the site is NOT tolerated. A write
# whose provenance this gate cannot read is a write it cannot justify.
#
# A callback interface added in M2 generates this same shape and passes
# without anyone editing this file, EXCEPT for the count below, which is
# deliberate. A CHANGED shape does not, which is the point: if a ubrn upgrade
# starts printing an argument rather than a fixed literal, this gate fails and
# someone re-reads the template.
FORBIDDEN_NATIVE='std::(cout|cerr|clog|wcout|wcerr)|(^|[^_[:alnum:]])(printf|fprintf|vprintf|vfprintf|puts|fputs|perror|syslog|NSLog|RCTLog)[[:space:]]*[(]|__android_log|os_log|(^|[^_[:alnum:]])ALOG[A-Z]*[[:space:]]*[(]'

# The number of tolerated sites, pinned rather than printed.
#
# It was printed and not asserted until 2026-08-28, with a comment saying the
# count exists so it "moves in the CI log" -- i.e. it depended on a human
# reading a PASSING job's log and noticing a digit. The forgery above moved it
# from 5 to 6 and the gate still exited 0. Twelve lines of
# scripts/run-probe-on-emulator.sh hardcode `PROBE_SUMMARY 12/12` and say why:
# "CI failing until you do is the point". Same rule here.
#
# Five sites, all in cpp/generated/matrix_crypto.cpp, one per UniFFI callback
# trampoline. If you add a callback interface to the Rust surface this number
# goes up, and CI fails until you come here, read the new site, and change it
# on purpose. That is the whole mechanism.
EXPECTED_NATIVE_ALLOWED=5

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
NATIVE_TOLERATED=""
for f in $NATIVE_FILES; do
  gen=0
  if is_generated "$f"; then gen=1; fi
  # One pass emits both records, so the count below is the number of sites
  # this gate actually TOLERATED rather than the number of lines that look
  # like the first line of the shape. The old count was the latter, computed
  # by a separate grep -- a second oracle for the same question, which is the
  # mistake this repository has already paid for twice.
  out=$(awk -v FORBIDDEN="$FORBIDDEN_NATIVE" -v GEN="$gen" -v FNAME="$f" '
    function is_ubrn_callback_site(i,   name, j, try_at) {
      # Arrangement.
      if (line[i]   !~ /^[[:space:]]*std::cout << "Error in callback [A-Za-z0-9_]+: "$/) return 0
      if (line[i+1] !~ /^[[:space:]]*<< error[.]what[(][)] << std::endl;$/) return 0
      if (line[i-1] !~ /^[[:space:]]*[}] catch [(]const jsi::JSError &error[)] [{]$/) return 0

      # Content, part 1: the callback name ubrn writes into the literal.
      name = line[i]
      sub(/^.*Error in callback /, "", name)
      sub(/: ".*$/, "", name)
      if (name !~ /^Uniffi[A-Za-z0-9_]*$/) return 0

      # Content, part 2: the try block this catch closes, found by walking up
      # to the nearest `try {`. Bounded, and stopping at another catch, so a
      # site with no try block of its own cannot borrow the one above it.
      try_at = 0
      for (j = i - 2; j >= 1 && j >= i - 200; j--) {
        if (line[j] ~ /^[[:space:]]*[}] catch [(]/) break
        if (line[j] ~ /^[[:space:]]*try[[:space:]]*[{][[:space:]]*$/) { try_at = j; break }
      }
      if (try_at == 0) return 0

      for (j = try_at + 1; j <= i - 2; j++) {
        if (line[j] ~ /jsi::JSError/) return 0
      }
      return 1
    }
    { line[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        if (GEN == 1 && is_ubrn_callback_site(i)) {
          printf "OK %s:%d\n", FNAME, i
          continue
        }
        if (line[i] !~ FORBIDDEN) continue
        printf "HIT %s:%d:%s\n", FNAME, i, line[i]
      }
    }
  ' "$f")
  while IFS= read -r rec; do
    case "$rec" in
      "HIT "*) NATIVE_HITS="$NATIVE_HITS${rec#HIT }
" ;;
      "OK "*)  NATIVE_TOLERATED="$NATIVE_TOLERATED${rec#OK }
" ;;
    esac
  done <<< "$out"
done

NATIVE_ALLOWED=$(printf '%s' "$NATIVE_TOLERATED" | grep -c . || true)

if [ -n "${RUST_HITS}${TS_HITS}${NATIVE_HITS}" ]; then
  echo "FAIL: the bridge must not log. Spec section 7.2."
  [ -n "$RUST_HITS" ] && echo "$RUST_HITS"
  [ -n "$TS_HITS" ] && echo "$TS_HITS"
  [ -n "$NATIVE_HITS" ] && printf '%s' "$NATIVE_HITS"
  echo "      Diagnostics belong in a sink the product injects and owns."
  echo "      In generated C++ the ONLY tolerated write is ubrn's"
  echo "      'std::cout << \"Error in callback UniffiX: \" << error.what()' on a"
  echo "      catch(jsi::JSError) path: all three of its lines must match, the"
  echo "      name must be one ubrn generates, and the try block it closes must"
  echo "      not construct a jsi::JSError of its own."
  exit 1
fi

if [ "$NATIVE_ALLOWED" -ne "$EXPECTED_NATIVE_ALLOWED" ]; then
  echo "FAIL: this gate tolerated $NATIVE_ALLOWED ubrn callback-error std::cout"
  echo "      sites in generated C++, but expects exactly"
  echo "      $EXPECTED_NATIVE_ALLOWED."
  printf '%s' "$NATIVE_TOLERATED" | sed 's/^/      /'
  if [ "$NATIVE_ALLOWED" -gt "$EXPECTED_NATIVE_ALLOWED" ]; then
    echo "      A site appeared. If the Rust surface grew a callback interface,"
    echo "      read the new site, satisfy yourself that it prints a fixed"
    echo "      literal and jsi::JSError::what() and nothing else, and raise"
    echo "      EXPECTED_NATIVE_ALLOWED in this script deliberately."
  else
    echo "      A site disappeared. Either ubrn stopped emitting it -- good"
    echo "      news, lower the number -- or this gate stopped recognising it,"
    echo "      which means the shape moved and the scan is now blind."
  fi
  exit 1
fi

echo "PASS: no logger"
echo "      Scanned: Rust crates, shipped TypeScript, shipped C/C++/Objective-C."
echo "      Tolerated: $NATIVE_ALLOWED ubrn callback-error std::cout sites in generated C++,"
echo "      documented in README.md and design spec section 7.2."
