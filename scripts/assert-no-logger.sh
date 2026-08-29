#!/usr/bin/env bash
set -euo pipefail

# Spec section 7.2: the bridge has no logger. The example app is excluded
# because it is not the bridge.
#
# Generated code is NOT excluded wholesale, and the C++ half of it used not to
# be scanned at all. `cpp/generated/matrix_crypto.cpp` carries eight
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

# The integration tests, which this gate never opened.
#
# The README says "Tests assert, they do not print. The no logger rule has no
# test exemption." There was an exemption, and it was the whole of
# rust/*/tests/: the scan roots above are each crate's `src`, so a `println!`
# in an integration test passed. Reproduced 2026-08-28. It was unused -- no
# print existed in those directories -- which is the only reason the sentence
# was not already false in fact as well as in enforcement.
#
# Tests get the PRINT rule and not the file-write rule, deliberately. A test
# fixture may legitimately need a file: level_two_interop.rs writes a marker
# that a spawned child process reads back, which is how the cross-process
# openCryptoStore restore is proved at all. The library may not. That
# distinction is the reason the two rules are separate variables below rather
# than one regex.
RUST_TEST_DIRS=$(for d in $RUST_SRC_DIRS; do
  t="${d%/src}/tests"
  [ -d "$t" ] && echo "$t"
done)

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

# Check Rust for logging patterns.
#
# - print! and eprint! are included, not just println!/eprintln!
# - Imports are forbidden outright (use log::*, use tracing::*) because that
#   prevents bare calls like info!("...") after "use log::info;"
# - AND the qualified call is forbidden too. Forbidding only the import was a
#   hole with a one-character workaround: `tracing::info!("{}", plaintext)`
#   needs no `use` at all and passed this gate until 2026-08-28. Reproduced.
FORBIDDEN_RUST_PRINT='(println!|eprintln!|print!|eprint!|dbg!|use[[:space:]]+(log|tracing)::|(^|[^_[:alnum:]])(log|tracing)::[a-z_]+!)'

# The file-write rule, which the README has promised since M1 and which was
# enforced in no language at all. `std::fs::write`, `File::create` and
# `std::io::stdout().write_all` all passed. None of these patterns appears in
# either crate's `src` today, so this is a tripwire rather than a cleanup.
#
# Library sources only. See RUST_TEST_DIRS above for why tests are exempt from
# this one rule and from no other.
FORBIDDEN_RUST_WRITE='(std::)?fs::(write|create_dir|OpenOptions|File)|File::create|OpenOptions::new|(std::)?io::(stdout|stderr)[[:space:]]*\(|\.write_all[[:space:]]*\(|\.write_fmt[[:space:]]*\('

RUST_HITS=$(for root in $RUST_SRC_DIRS; do
  grep -rnE "$FORBIDDEN_RUST_PRINT|$FORBIDDEN_RUST_WRITE" "$root" 2>/dev/null || true
done
for root in $RUST_TEST_DIRS; do
  grep -rnE "$FORBIDDEN_RUST_PRINT" "$root" 2>/dev/null || true
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
# Negations (`!src/**/*.test.ts`) are skipped: they remove files rather than
# name roots. Test files inside a shipped directory ARE scanned, which is what
# this gate already did for `src`.
#
# Globs used to be skipped wholesale, on the reasoning that they "name
# binaries". Two of the three do. `*.podspec` does not: it is a Ruby program
# CocoaPods executes on a consumer's machine, it is the file that decides
# which iOS sources compile into their app, and skipping it left it shipped
# and unscanned -- the same shape as the `interop/` gap above, found the same
# way, by the M2 final review. So globs are expanded now, with exactly one
# kind of entry excluded:
#
#   anything ending in .aar or .xcframework -- build outputs whose contents
#     are compiled code. They are gitignored, so they are present or absent
#     depending on whether a platform build has run, and a gate whose reach
#     depends on that reports a different answer to two people looking at the
#     same commit.
#
#     Matched on the suffix rather than on the exact strings `*.aar` and
#     `*.xcframework`, because on 2026-08-29 the xcframework entry stopped
#     being a glob: npm 10's packlist does not pack the contents of a
#     directory a bare glob in "files" matches, so `*.xcframework` shipped a
#     tarball with no xcframework in it and "files" now names
#     `MatrixCryptoFramework.xcframework` literally
#     (scripts/assert-tree-ships-binaries.sh carries the whole account). An
#     exclusion keyed to the glob spelling would have silently stopped
#     matching, and this gate would have started grepping 150 MB of compiled
#     objects on whichever machine happened to have built them.
#
# An unrecognised glob shape throws rather than being silently dropped: a
# `files` entry this cannot expand must fail loudly, since silently skipping
# it is precisely the bug being fixed.
#
# FILE entries are kept alongside directory entries, because "files" names
# some shipped sources individually: `android/cpp-adapter.cpp` is a shipped
# C++ translation unit that no directory entry reaches. `find` takes a file as
# a root perfectly well, so both kinds go into one list.
SHIPPED_ROOTS=$(node -e '
  const fs = require("fs");
  const dir = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(dir + "/package.json", "utf8"));
  const IS_BINARY_ENTRY = /\.(aar|xcframework)$/;
  for (const entry of pkg.files || []) {
    if (entry.startsWith("!")) continue;
    if (IS_BINARY_ENTRY.test(entry)) continue;
    if (entry.includes("*")) {
      const m = /^\*(\.[A-Za-z0-9]+)$/.exec(entry);
      if (!m) {
        console.error("FAIL: this gate cannot expand the \"files\" entry " + entry + ".");
        console.error("      It would then scan nothing under it while reporting a pass.");
        console.error("      Teach the expansion this shape, or exclude it deliberately");
        console.error("      the way .aar and .xcframework entries are excluded above.");
        process.exit(1);
      }
      for (const f of fs.readdirSync(dir)) {
        if (f.endsWith(m[1])) console.log(dir + "/" + f);
      }
      continue;
    }
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

# `console.log` was the whole rule until 2026-08-28, so every other way of
# reaching the same object passed: `const sink = console; sink.log(x)` and
# `console["error"](x)` were both constructed and both accepted.
#
# What is matched now: a property access with a real identifier after the dot,
# a bracket index, and the object being handed to something -- assigned,
# passed as an argument, or used as an object value. The identifier
# requirement after the dot is what keeps English prose out of it:
# interop/crypto-suite.ts's JSDoc ends a sentence with "the simulator
# console.", and a bare `console\.` would fail this gate on a comment. This
# gate scans raw lines, so prose is inside its scan; gate:agility solves the
# same problem by emitting declarations with --removeComments.
#
# WHAT IS STILL OPEN, and deliberately, because closing it costs a TypeScript
# parser and buys little: a reference laundered through something this regex
# cannot see -- `globalThis["con" + "sole"]`, a property read off an object
# built at runtime, or a native module a consumer injects. The rule this gate
# enforces is that the bridge's own source does not reach for the console,
# not that a determined author cannot.
FORBIDDEN_TS='console[[:space:]]*\.[A-Za-z_$]|console[[:space:]]*\[|[=(,:][[:space:]]*console([^A-Za-z0-9_$]|$)'

# The file-write half of the README's promise, in the language where it is
# cheapest to state and hardest to do by accident. React Native has no `fs`,
# so any of these in the bridge means someone reached for a filesystem module
# on purpose.
FORBIDDEN_TS_WRITE='require\([[:space:]]*['"'"'"](node:)?fs['"'"'"]|from[[:space:]]*['"'"'"](node:)?fs['"'"'"]|react-native-fs|(writeFile|appendFile|createWriteStream)[[:space:]]*\('

TS_HITS=$(grep -nE "$FORBIDDEN_TS|$FORBIDDEN_TS_WRITE" $TS_FILES 2>/dev/null || true)

# ---------------------------------------------------------------------------
# C++ and Objective-C++: the shipped native surface
# ---------------------------------------------------------------------------
#
# This section did not exist until 2026-08-28. The gate had never read a line
# of C++, and every write to a stream anywhere in the shipped bridge is in
# C++: eight `std::cout` calls in cpp/generated/matrix_crypto.cpp, one per
# UniFFI callback trampoline, each on a `catch (const jsi::JSError &error)`
# path.
#
# THE `strings` EVIDENCE BELOW WAS TAKEN AGAINST FIVE, AND HAS NOT BEEN
# RETAKEN. When there were five, `strings` on the release AAR's
# libreact-native-matrix-crypto.so found four of the literals plus an
# undefined `_ZNSt6__ndk14coutE`, so they were in the shipped binary and not
# merely in the shipped source; the fifth
# (UniffiForeignFutureDroppedCallback) was dropped by the linker only because
# nothing referenced it today. That measurement stands for those five and
# says nothing about the three that M3's `CryptoObserver` added.
#
# It is not a re-run of anything. No committed script produces
# libreact-native-matrix-crypto.so -- scripts/ builds and measures the AAR's
# libmatrix_crypto_ffi.so, which is the Rust library, not this translation
# unit's. Retaking it means a full Android *release* build through gradle
# with the NDK toolchain and then `strings ... | grep "Error in callback"`,
# which is tens of minutes and no gate's job. What the eight sites' presence
# in the shipped source does not depend on is that measurement: it is read
# out of the committed file by this gate, on every run.
#
# The count went from five to eight on 2026-08-29, when a second callback
# interface was added. A second interface costs three trampolines rather
# than one: its own method, plus the UniffiCallbackInterfaceFree and
# UniffiCallbackInterfaceClone every vtable carries. All three were read
# before the number was raised, and all three pass the structural check
# below rather than merely resembling the original five.
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
#     eight try blocks does, while ubrn's other JSError constructions all sit
#     outside them. Re-established across all eight on 2026-08-29, when the
#     count rose from five -- and this gate re-establishes it structurally on
#     every run rather than resting on that reading, which is the whole
#     point of checking the shape rather than counting the sites.
#
# If the try block cannot be found at all, the site is NOT tolerated. A write
# whose provenance this gate cannot read is a write it cannot justify.
#
# A callback interface added in M2 generates this same shape and passes
# without anyone editing this file, EXCEPT for the count below, which is
# deliberate. A CHANGED shape does not, which is the point: if a ubrn upgrade
# starts printing an argument rather than a fixed literal, this gate fails and
# someone re-reads the template.
# Five more write forms were constructed against the previous list and all
# five passed: `fwrite(k, 1, 4, stdout)`, `write(1, k, 4)`, `std::ofstream`,
# `std::wclog` (the list had wcout and wcerr but not wclog) and `putchar`.
# Added, along with the file-opening forms, since the README promises no file
# writes and that was enforced nowhere. None of these appears in any shipped
# native source today, so every one of them is a tripwire rather than a
# cleanup.
# Bare `open(` is deliberately NOT in the list. A descriptor is useless
# without the `write(` that is, and `open(` is a common enough word in
# generated C++ (`store.open(...)`) to make this gate cry wolf, which is how
# a gate ends up disabled.
FORBIDDEN_NATIVE='std::(cout|cerr|clog|wcout|wcerr|wclog)|(^|[^_[:alnum:]])(printf|fprintf|vprintf|vfprintf|dprintf|puts|fputs|fputc|putchar|putc|fwrite|perror|syslog|NSLog|RCTLog|fopen|freopen|write)[[:space:]]*[(]|__android_log|os_log|(^|[^_[:alnum:]])ALOG[A-Z]*[[:space:]]*[(]|(std::)?(w?ofstream|w?fstream)|<fstream>'

# The number of tolerated sites, pinned rather than printed.
#
# It was printed and not asserted until 2026-08-28, with a comment saying the
# count exists so it "moves in the CI log" -- i.e. it depended on a human
# reading a PASSING job's log and noticing a digit. The forgery above moved it
# from 5 to 6 and the gate still exited 0. Twelve lines of
# scripts/run-probe-on-emulator.sh hardcode `PROBE_SUMMARY 12/12` and say why:
# "CI failing until you do is the point". Same rule here.
#
# Eight sites, all in cpp/generated/matrix_crypto.cpp, one per UniFFI callback
# trampoline. If you add a callback interface to the Rust surface this number
# goes up, and CI fails until you come here, read the new site, and change it
# on purpose. That is the whole mechanism.
#
# It went from five to eight on 2026-08-29, when `CryptoObserver` was added
# alongside `ProbeObserver` so the crypto signal channel could have a native
# producer. A second callback interface costs three trampolines, not one: its
# own `on_signal`, plus the `UniffiCallbackInterfaceFree` and
# `UniffiCallbackInterfaceClone` that every vtable carries. All three were
# read before this number was raised, and all three have the shape the
# paragraph above requires -- a fixed literal, then `jsi::JSError::what()`,
# then a rethrow, with nothing else interpolated.
EXPECTED_NATIVE_ALLOWED=8

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

# ---------------------------------------------------------------------------
# Kotlin: the fourth shipped language, which this gate had never opened
# ---------------------------------------------------------------------------
#
# `android/src/main` is in package.json's "files" and ships two Kotlin
# sources: the turbo module and the ReactPackage that registers it. Both are
# generated, both are compiled into every Android consumer's app, and until
# 2026-08-28 this gate read neither. A planted `android.util.Log.d("tag",
# plaintext)` and a planted `println(plaintext)` in MatrixCryptoModule.kt both
# passed. Reproduced.
#
# Being generated does NOT exempt them: there is no tolerated shape here, and
# ubrn's Kotlin templates write nothing to any log today, which is why this
# section adds no allowlist. If a ubrn upgrade starts logging from Kotlin,
# this gate fails and someone reads the template -- which is exactly what the
# C++ section had to do.
#
# `System.` is matched only as System.out/System.err, because
# MatrixCryptoModule.kt legitimately calls System.loadLibrary.
FORBIDDEN_KOTLIN='android\.util\.Log|(^|[^_[:alnum:]])Log[[:space:]]*\.[a-z]+[[:space:]]*\(|(^|[^_[:alnum:]])(println|print)[[:space:]]*\(|System\.(out|err)|(^|[^_[:alnum:]])Timber[[:space:]]*\.|printStackTrace[[:space:]]*\(|(FileOutputStream|FileWriter|BufferedWriter|java\.io\.File)'

KOTLIN_FILES=$(find $SHIPPED_ROOTS -type f \( -name '*.kt' -o -name '*.java' \) | sort)

# Same discipline as the other three. This package ships an Android turbo
# module; zero Kotlin means the derivation broke, not that the Kotlin is
# clean.
if [ -z "${KOTLIN_FILES//[[:space:]]/}" ]; then
  echo "FAIL: no Kotlin or Java source was found under: $(echo $SHIPPED_ROOTS | tr '\n' ' ')"
  echo "      This package ships an Android turbo module and its ReactPackage;"
  echo "      zero JVM sources means the scan broke. Refusing to pass having"
  echo "      scanned nothing."
  exit 1
fi

KOTLIN_HITS=$(grep -nE "$FORBIDDEN_KOTLIN" $KOTLIN_FILES 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Swift: scanned before the first Swift file exists, deliberately
# ---------------------------------------------------------------------------
#
# `ios` is in package.json's "files" and MatrixCrypto.podspec compiles
# `ios/**/*.{h,m,mm,swift}` into every iOS consumer's app -- the `swift` in
# that glob is ubrn's, not ours. Today `ios/` holds only MatrixCrypto.h and
# MatrixCrypto.mm, so this scan finds nothing, and the M2 final review named
# that as a hole rather than a violation: a `.swift` file added by a ubrn
# upgrade would have shipped, compiled, and never been read by this gate.
#
# No "refuse to pass having scanned nothing" guard here, and that is the one
# deliberate exception to the rule the other four sections follow. Those four
# guard a count that is structurally guaranteed to be non-zero: this package
# cannot ship without TypeScript, without a JSI translation unit, or without
# an Android turbo module. Zero Swift files is the correct answer today, so a
# guard would have to fail on a clean tree. What stands in for it is that the
# Swift scan shares its roots with the native scan, which does carry the
# guard and does read `ios/` -- so a broken derivation fails there first, and
# a zero here means there is no Swift rather than that nothing was looked at.
# The count is printed at the end for the same reason.
FORBIDDEN_SWIFT='(^|[^_[:alnum:].])(print|debugPrint|dump)[[:space:]]*\(|NSLog[[:space:]]*\(|(^|[^_[:alnum:]])os_log|OSLog|(^|[^_[:alnum:].])Logger[[:space:]]*\(|FileHandle\.standard(Output|Error)|\.write[[:space:]]*\((to|toFile):|FileManager\.default\.createFile'

SWIFT_FILES=$(find $SHIPPED_ROOTS -type f -name '*.swift' | sort)
SWIFT_COUNT=$(printf '%s' "$SWIFT_FILES" | grep -c . || true)

SWIFT_HITS=""
if [ -n "${SWIFT_FILES//[[:space:]]/}" ]; then
  SWIFT_HITS=$(grep -HnE "$FORBIDDEN_SWIFT" $SWIFT_FILES 2>/dev/null || true)
fi

# ---------------------------------------------------------------------------
# Ruby: the podspec, which decides what compiles and can run shell
# ---------------------------------------------------------------------------
#
# `*.podspec` was skipped by the root derivation above as though it named a
# binary. It does not: CocoaPods evaluates it as Ruby on a consumer's machine
# during `pod install`, and CocoaPods lets a podspec declare a
# `script_phase` -- arbitrary shell that runs inside the consumer's Xcode
# build, with its output going straight to their build log. Neither
# `script_phase` nor `prepare_command` appears in ours, and both are rejected
# here so that adding one is a decision someone makes on purpose rather than
# a shell script that arrives with a ubrn upgrade and prints into a log this
# repository promises not to write to.
#
# `File.read` is explicitly NOT forbidden: line 4 of the podspec reads
# package.json to get the version, which is what a podspec is supposed to do.
# It is writing, and printing, that this gate is about.
FORBIDDEN_RUBY='(^|[^_[:alnum:].])(puts|pp|warn|print|p)[[:space:]]*[("'"'"']|\$stdout|\$stderr|STDOUT|STDERR|(File|IO)\.(write|open|new)|\.write[[:space:]]*\(|script_phase|prepare_command|Kernel\.(system|exec)|%x[({[]'

RUBY_FILES=$(find $SHIPPED_ROOTS -type f -name '*.podspec' -o -type f -name '*.rb' | sort)

# Same discipline as the TypeScript, native and Kotlin halves. This package
# ships an iOS pod: `*.podspec` is in "files" and the podspec is what makes
# the iOS half installable at all. Zero means the derivation broke.
if [ -z "${RUBY_FILES//[[:space:]]/}" ]; then
  echo "FAIL: no podspec was found under: $(echo $SHIPPED_ROOTS | tr '\n' ' ')"
  echo "      This package ships an iOS pod, and package.json's \"files\""
  echo "      names *.podspec. Zero podspecs means the scan broke. Refusing"
  echo "      to pass having scanned nothing."
  exit 1
fi

RUBY_HITS=$(grep -HnE "$FORBIDDEN_RUBY" $RUBY_FILES 2>/dev/null || true)

if [ -n "${RUST_HITS}${TS_HITS}${NATIVE_HITS}${KOTLIN_HITS}${SWIFT_HITS}${RUBY_HITS}" ]; then
  echo "FAIL: the bridge must not log. Spec section 7.2."
  [ -n "$RUST_HITS" ] && echo "$RUST_HITS"
  [ -n "$TS_HITS" ] && echo "$TS_HITS"
  [ -n "$NATIVE_HITS" ] && printf '%s' "$NATIVE_HITS"
  [ -n "$KOTLIN_HITS" ] && echo "$KOTLIN_HITS"
  [ -n "$SWIFT_HITS" ] && echo "$SWIFT_HITS"
  [ -n "$RUBY_HITS" ] && echo "$RUBY_HITS"
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
echo "      Scanned for writes to a stream: Rust crate sources and integration"
echo "      tests, shipped TypeScript, shipped C/C++/Objective-C, shipped"
echo "      Kotlin, shipped Swift ($SWIFT_COUNT files), the shipped podspec."
echo "      Scanned for file writes: the same, minus the Rust integration tests,"
echo "      which may write a fixture but may not print."
echo "      Tolerated: $NATIVE_ALLOWED ubrn callback-error std::cout sites in generated C++,"
echo "      documented in README.md and design spec section 7.2."
