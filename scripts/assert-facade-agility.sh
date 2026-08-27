#!/usr/bin/env bash
set -euo pipefail

PKG=packages/react-native-matrix-crypto
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# Emit declarations for the public surface only, by compiling from the single
# entry point src/index.ts and following only what it imports.
#
# Two things make this invocation less obvious than it looks:
#
# - `yarn --cwd "$PKG" exec tsc -- ...` does not change the child process's
#   working directory in this yarn install (verified empirically: `yarn --cwd
#   "$PKG" exec -- pwd` prints the workspace root, not "$PKG"). A `cd` in a
#   subshell is used instead, so `src/index.ts` below resolves correctly.
# - Passing a file argument to tsc makes it ignore tsconfig.json entirely
#   (documented tsc behaviour: "When input files are specified on the command
#   line, tsconfig.json files are ignored"). Without an explicit --target,
#   the default is ES3, and signals.ts's `for...of` over a Set fails to
#   compile. The flags below mirror packages/react-native-matrix-crypto/
#   tsconfig.json's compilerOptions; keep them in sync if that file changes.
# --removeComments strips JSDoc prose from the emitted declarations. Without
# it, types.ts's legitimate comment "Today this wraps a Matrix room id."
# would survive into the .d.ts and false-positive against the room check
# below -- comments are prose, not identifiers, and were never meant to be
# scanned.
(
  cd "$PKG"
  yarn exec -- tsc \
    --target ES2022 --module ESNext --moduleResolution bundler --strict --skipLibCheck \
    --declaration --emitDeclarationOnly --noEmit false --removeComments \
    --outDir "$OUT" src/index.ts
) 2>/dev/null

# Concatenate the public .d.ts, excluding anything generated.
DTS=$(find "$OUT" -name '*.d.ts' -not -path '*/generated/*' -exec cat {} +)

# Strip string literals: 'megolm' as a VALUE is allowed and expected,
# because the union is open. A Megolm-specific IDENTIFIER is not.
IDENTIFIERS=$(printf '%s' "$DTS" | sed "s/'[^']*'//g; s/\"[^\"]*\"//g")

if printf '%s' "$IDENTIFIERS" | grep -nEi '\b(megolm|olm)\b|[Rr]oom[A-Za-z]*'; then
  echo "FAIL: a Megolm-, Olm-, or room-specific identifier reached the public API."
  echo "      Spec section 6 requires the facade stay algorithm-agnostic."
  exit 1
fi

echo "PASS: facade agility"
