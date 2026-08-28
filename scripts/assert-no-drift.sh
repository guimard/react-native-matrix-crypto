#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3: any drift between the Rust surface and the committed
# generated code is a blocking defect. Regenerate and require an empty diff.
#
# WARNING: do not install `prettier` or `clang-format` as devDependencies
# without checking this gate first. ubrn formats its output with them when
# present ("Skipping formatting C++. Is clang-format installed?" / "No
# prettier found." are printed on every run in this repo today because
# neither is installed) -- adding either would reformat every generated
# file's bytes and fail this gate, for a reason nobody would connect to a
# devDependency bump.
yarn --cwd packages/react-native-matrix-crypto codegen

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

if ! git diff --exit-code -- "${GENERATED_PATHS[@]}"; then
  echo "FAIL: generated code is out of date. Run codegen and commit the result."
  echo "      Never hand-edit generated files."
  exit 1
fi

echo "PASS: no codegen drift (${#GENERATED_PATHS[@]} paths regenerated and diffed)"
