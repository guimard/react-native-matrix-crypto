#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3: any drift between the Rust surface and the committed
# generated code is a blocking defect. Regenerate and require an empty diff.
#
# WARNING: do not install `prettier` or `clang-format` as devDependencies
# without checking this gate first. ubrn formats its output with them when it
# finds them -- adding one where there was none would reformat every
# generated file's bytes and fail this gate, for a reason nobody would
# connect to a devDependency bump.
#
# This comment used to say neither is installed. That is no longer true of
# prettier: `node_modules/.bin/prettier` exists in this workspace today,
# hoisted in from a transitive dependency rather than declared here, and ubrn
# resolves prettier from node_modules rather than from PATH. Observed
# 2026-08-28: a hand-written, deliberately unformatted `.ts` file dropped into
# src/generated came back from a codegen run rewritten in prettier's style,
# double quotes and semicolons and all. The committed TypeScript is
# prettier-formatted for the same reason. clang-format is still shimmed away
# by scripts/codegen.sh, which is what keeps the C++ reproducible across
# hosts.
#
# The list is read BEFORE codegen runs, so a missing or empty list fails in a
# second instead of after a full rebuild, and so the marker below can be
# planted at the last possible moment.
#
# What counts as generated is scripts/generated-paths.txt, NOT a list inlined
# here. scripts/assert-no-logger.sh reads the same file to decide which files
# it may exempt from the no-logger rule, and M1's final review (item C9)
# found the two scripts answering that question differently -- this one by
# path, that one by sniffing a header out of the first three lines. A file
# the logger gate called generated but that this gate never regenerated was
# watched by neither. One list, read twice, is the fix.
GENERATED_PATHS_FILE="scripts/generated-paths.txt"

if [ ! -f "$GENERATED_PATHS_FILE" ]; then
  echo "FAIL: $GENERATED_PATHS_FILE is missing."
  echo "      It is the list of what this gate regenerates; without it this"
  echo "      gate would diff nothing and pass."
  exit 1
fi

GENERATED_PATHS=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(printf '%s' "$line" | tr -d '[:space:]')"
  [ -n "$line" ] || continue
  GENERATED_PATHS+=("$line")
done < "$GENERATED_PATHS_FILE"

# Refuse to pass having diffed nothing. An empty or all-comments list would
# make both git invocations below inspect the whole tree's worth of nothing
# in particular and report success.
if [ "${#GENERATED_PATHS[@]}" -eq 0 ]; then
  echo "FAIL: $GENERATED_PATHS_FILE lists no paths."
  echo "      Refusing to pass having diffed nothing."
  exit 1
fi

# The marker is planted immediately before codegen so that "codegen wrote
# this file" becomes an observable fact: every file the run emits ends up
# newer than it. Used by the WHAT CODEGEN ACTUALLY EMITS section below.
#
# The sleep buys one clock tick. APFS and ext4 both timestamp to the
# nanosecond and would not need it, but a filesystem with one-second
# granularity (a mounted volume, some container overlays) could stamp the
# marker and the first generated file in the same second, and `-nt` would
# then read as "not newer" and fail a clean tree. One second, once, on a gate
# whose codegen step is seven, is the cheap side of that trade.
CODEGEN_MARKER="$(mktemp)"
trap 'rm -f "$CODEGEN_MARKER"' EXIT
sleep 1

yarn --cwd packages/react-native-matrix-crypto codegen

# A listed path that does not exist is a moved or deleted generation target,
# not a clean tree: `git diff -- missing/path` is silent and exits 0.
for path in "${GENERATED_PATHS[@]}"; do
  if [ ! -e "$path" ]; then
    echo "FAIL: generated path '$path' does not exist."
    echo "      Codegen did not produce it, or it moved. Either way this gate"
    echo "      cannot diff it, and neither can assert-no-logger.sh exempt it."
    exit 1
  fi
done

# `git diff` is blind to brand-new untracked files: if a future change to the
# Rust surface makes ubrn emit a file under one of these paths that has never
# been committed before, `git diff --exit-code` below sees nothing to compare
# against and would report PASS. Catch that case explicitly and first, with
# its own message, so it isn't mistaken for the (different) drift case below.
UNTRACKED=$(git status --porcelain -- "${GENERATED_PATHS[@]}" | grep '^??' || true)
if [ -n "$UNTRACKED" ]; then
  echo "FAIL: codegen produced a new file that git isn't tracking yet:"
  echo "$UNTRACKED"
  echo "      git add it and commit, so future drift checks can see it."
  exit 1
fi

# --- WHAT CODEGEN ACTUALLY EMITS --------------------------------------------
#
# An empty diff is not the same claim as "every committed file here is
# generated code". `git diff` compares a file against its own committed
# version; a file the generator never writes compares equal to itself
# forever. Codegen does not delete what it does not emit, so a hand-written
# file committed under a listed directory is invisible here -- and both
# gate:logger and gate:stubs then treat it as generated because of where it
# sits. Reproduced 2026-08-28: a tracked, prettier-formatted
# src/generated/review-helper.ts calling `console.log` on a plaintext
# parameter passed all three gates and would have shipped under
# `files: ["src"]`.
#
# This job is the only one that runs the generator, so it is the only place
# that can answer the question directly rather than by proxy: the marker was
# planted immediately before the run, so a file this run wrote is newer than
# it, and a file it did not write is not.
#
# TWO COMMITTED FILES ARE LEGITIMATELY OLDER, and they are named rather than
# pattern-matched, because an exception nobody can enumerate is an amnesty.
# `ubrn generate jsi turbo-module` scaffolds android/proguard-rules.pro and
# android/README.md ONCE, when they are absent, and never rewrites them.
# Verified 2026-08-28 from both sides: a repeat codegen run leaves both
# untouched while rewriting the other seventeen, and DELETING both and
# running codegen again does not bring either back. They remain covered by
# every other check here -- they are in the diff set, and
# scripts/generated-file-set.sh still requires each to carry the generator's
# header -- so this exception is narrow: it excuses them from being rewritten,
# not from being generated code.
SCAFFOLD_ONCE=(
  "packages/react-native-matrix-crypto/android/proguard-rules.pro"
  "packages/react-native-matrix-crypto/android/README.md"
)

# Command substitution rather than a pipe or a process substitution, so that
# `set -e` aborts here if the cross-check itself fails: a loop reading from a
# failed producer reads nothing and swallows its exit code.
GENERATED_FILES=$(./scripts/generated-file-set.sh)

NOT_EMITTED=""
EMITTED_COUNT=0
TOTAL_COUNT=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  if [ "$f" -nt "$CODEGEN_MARKER" ]; then
    EMITTED_COUNT=$((EMITTED_COUNT + 1))
    continue
  fi
  skip=0
  for s in "${SCAFFOLD_ONCE[@]}"; do
    if [ "$f" = "$s" ]; then skip=1; break; fi
  done
  if [ "$skip" -eq 1 ]; then continue; fi
  NOT_EMITTED="${NOT_EMITTED:+$NOT_EMITTED
}$f"
done <<< "$GENERATED_FILES"

if [ -n "$NOT_EMITTED" ]; then
  echo "FAIL: a committed file sits under a generated path but this codegen"
  echo "      run did not write it:"
  echo "$NOT_EMITTED"
  echo "      An empty diff says nothing about such a file: codegen never"
  echo "      deletes what it does not emit, so a hand-written file committed"
  echo "      here is invisible to the diff above and is treated as generated"
  echo "      by gate:logger and gate:stubs because of where it sits."
  echo "      Move it out of the generated directory. If the generator really"
  echo "      does emit it and simply stopped, say so deliberately by adding"
  echo "      it to SCAFFOLD_ONCE in this script, with the evidence."
  exit 1
fi

# Refuse to pass having watched nothing be written. If a future ubrn wrote
# its output somewhere else entirely, or the codegen step silently became a
# no-op, every listed file would be older than the marker, NOT_EMITTED would
# name them all and this would already have failed -- unless the set itself
# had also collapsed to the two scaffolded files, which this catches.
if [ "$EMITTED_COUNT" -eq 0 ]; then
  echo "FAIL: refusing to pass having watched codegen write nothing."
  echo "      No committed generated file is newer than the marker planted"
  echo "      immediately before the codegen step, which means the generator"
  echo "      did not run, or no longer writes where it is expected to."
  exit 1
fi

if ! git diff --exit-code -- "${GENERATED_PATHS[@]}"; then
  echo "FAIL: generated code is out of date. Run codegen and commit the result."
  echo "      Never hand-edit generated files."
  exit 1
fi

echo "PASS: no codegen drift (${#GENERATED_PATHS[@]} paths regenerated and diffed;"
echo "      $EMITTED_COUNT of $TOTAL_COUNT committed generated files rewritten by this run,"
echo "      the rest scaffolded once and named in SCAFFOLD_ONCE)"
