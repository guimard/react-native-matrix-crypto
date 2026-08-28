#!/usr/bin/env bash
set -euo pipefail

# Install a real, built tarball on a machine with no Rust toolchain reachable,
# and load the module out of the installed package.
#
#   ./scripts/cold-consume-tarball.sh <tarball.tgz>
#
# WHAT THIS ADDS TO ci.yml's `cold-consume`, AND WHY IT IS A DIFFERENT CLAIM.
#
# `cold-consume` runs on a pull request, on a source checkout. The binaries are
# build outputs, all of them gitignored, so the tarball it packs has none of
# them -- 68 KB, measured -- and its job comment now says so plainly. What it
# establishes is real and worth having: with cargo and rustc unreachable the
# package installs, it declares no preinstall/install/postinstall/prepare
# script, it ships no binding.gyp, and its entry point resolves to a non-empty
# file inside the installed package. Nothing in it can reach for a compiler on
# a consumer's machine.
#
# It cannot establish the other half, because it never has an artifact with
# binaries in it. This script does, because the release workflow hands it the
# tarball it is about to publish. So this is the only place where the README's
# actual promise -- "the published package ships prebuilt binaries, so
# `yarn add` is all a consumer needs" -- is exercised against a package that
# has them.
#
# WHAT "LOAD THE MODULE" MEANS HERE, precisely, because the obvious reading is
# not available. `require('react-native-matrix-crypto')` in plain node throws
# ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING: `main` is src/index.ts and node
# refuses to strip types inside node_modules. Copying the tree out of
# node_modules does not rescue it either -- measured 2026-08-28, node's ESM and
# CJS resolvers both reject the extensionless relative imports the shipped
# source uses (`from './types'`), and node cannot load a .tsx file at all, at
# any path, which is what src/index.tsx is. A React Native consumer does not
# hit any of this because it has Metro, which resolves extensionless TypeScript
# and transforms JSX.
#
# So the module is loaded the way a consumer's bundler loads it: bundled from
# the installed package with `react-native` replaced by a stand-in, then
# executed. That gets all the way to the native boundary and stops there, which
# is the honest ceiling in a process with no JSI host object -- and the
# assertion is written to pin exactly that, rather than to tolerate a failure:
#
#   * the whole shipped module graph resolves and parses (a missing
#     src/generated/, a truncated file, a dangling import all fail here);
#   * the public entry point's exports include the functions the README
#     documents, read out of the real graph rather than out of a source file;
#   * executing it calls installRustCrate() on the turbo module named
#     MatrixCrypto -- so the bootstrap in the shipped tree really runs;
#   * and the first thing it then reaches for is a symbol on the JSI host
#     object, which is absent in node by construction. That, and nothing
#     earlier, is where it stops.
#
# What remains unproven here is the same thing that has always been unprovable
# off a device: that the native code behind those symbols works. probe-android
# runs the shipped chain end to end on an emulator, and interop-level-two runs
# it against a real homeserver. This script proves the artifact a consumer
# downloads contains and loads.
#
# PATH is scrubbed rather than deleting the toolchain from disk, for the reason
# ci.yml's cold-consume gives at length: deletion would wreck a self-hosted
# runner or a local run, and PATH manipulation proves the identical property.

if [ $# -lt 1 ]; then
  echo "usage: $0 <tarball.tgz>" >&2
  exit 2
fi

TARBALL=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [ ! -s "$TARBALL" ]; then
  echo "FAIL: no tarball at $TARBALL (missing or empty)."
  echo "      Refusing to pass having installed nothing."
  exit 1
fi

# esbuild stands in for Metro: it is the smallest thing that resolves
# extensionless TypeScript imports and .tsx the way a React Native bundler
# does. It is taken from this repository's own node_modules so the version
# comes from yarn.lock rather than from whatever the network serves today.
ESBUILD_DIR="$REPO_ROOT/node_modules/esbuild"
if [ ! -d "$ESBUILD_DIR" ]; then
  echo "FAIL: no esbuild at $ESBUILD_DIR."
  echo "      Run 'yarn install --frozen-lockfile' at the repository root."
  echo "      If esbuild has genuinely left the dependency tree, add it as an"
  echo "      explicit devDependency rather than weakening this check: without"
  echo "      a bundler nothing can load this package's TypeScript entry point,"
  echo "      and a release would go out with its JS never once loaded."
  exit 1
fi
ESBUILD_VERSION=$(node -p "require('$ESBUILD_DIR/package.json').version")

CONSUMER=$(mktemp -d)
trap 'rm -rf "$CONSUMER"' EXIT

echo "== 1/4  Making cargo and rustc unreachable"
NEW_PATH=""
IFS=':' read -ra DIRS <<< "$PATH"
for d in "${DIRS[@]}"; do
  if [ -x "$d/cargo" ] || [ -x "$d/rustc" ]; then
    echo "   scrubbing $d from PATH (carries cargo/rustc)"
    continue
  fi
  NEW_PATH="${NEW_PATH:+$NEW_PATH:}$d"
done
export PATH="$NEW_PATH"

# An `if`, not `! command -v cargo`: under errexit a `!`-negated command is
# documented as exempt from exit-on-failure, so the negated form would silently
# do nothing in exactly the case this check exists to catch.
if command -v cargo >/dev/null 2>&1; then
  echo "FAIL: cargo is still reachable at $(command -v cargo)"
  exit 1
fi
if command -v rustc >/dev/null 2>&1; then
  echo "FAIL: rustc is still reachable at $(command -v rustc)"
  exit 1
fi
echo "   confirmed: cargo and rustc are unreachable"

echo
echo "== 2/4  Installing the tarball as a consumer would"
cd "$CONSUMER"
printf '{"name":"cold-consumer","version":"1.0.0","private":true}\n' > package.json
npm install --no-audit --no-fund "$TARBALL"

INSTALLED="$CONSUMER/node_modules/react-native-matrix-crypto"
if [ ! -d "$INSTALLED" ]; then
  echo "FAIL: nothing was installed at $INSTALLED."
  exit 1
fi

echo
echo "== 3/4  Reading the installed package"
node -e '
  const fs = require("fs");
  const path = require("path");
  const dir = process.argv[1];
  const problems = [];

  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const forbidden = ["preinstall", "install", "postinstall", "prepare"];
  const found = forbidden.filter((s) => (pkg.scripts || {})[s]);
  if (found.length) {
    problems.push("the installed package declares install-time scripts: " + found.join(", ") +
                  "\n      Any of them can invoke a compiler on a consumer machine.");
  }
  if (fs.existsSync(path.join(dir, "binding.gyp"))) {
    problems.push("the installed package ships a binding.gyp, so npm would run node-gyp against it at install time.");
  }

  // The binaries survived installation. assert-tarball-ships-binaries.sh has
  // already checked these same bytes exhaustively inside the tarball; what is
  // asked here is the narrower question that only an install can answer --
  // that what npm unpacked onto a consumer machine still has them.
  const MIN = 1024 * 1024;
  const big = (p) => { try { return fs.statSync(p).size >= MIN } catch { return false } };

  const jniRoot = path.join(dir, "android/src/main/jniLibs");
  const abis = fs.existsSync(jniRoot) ? fs.readdirSync(jniRoot) : [];
  const goodAbis = abis.filter((a) => big(path.join(jniRoot, a, "libmatrix_crypto_ffi.so")));
  if (goodAbis.length === 0) {
    problems.push("the installed package carries no android/src/main/jniLibs/<abi>/libmatrix_crypto_ffi.so." +
                  "\n      android/CMakeLists.txt links exactly that path; without it every" +
                  "\n      consumer Gradle build fails at configureCMakeRelease.");
  }

  const xcRoot = path.join(dir, "MatrixCryptoFramework.xcframework");
  const slices = fs.existsSync(xcRoot)
    ? fs.readdirSync(xcRoot).filter((e) => fs.statSync(path.join(xcRoot, e)).isDirectory())
    : [];
  const goodSlices = slices.filter((s) =>
    fs.readdirSync(path.join(xcRoot, s)).some((f) => big(path.join(xcRoot, s, f))));
  if (goodSlices.length === 0) {
    problems.push("the installed package carries no non-trivial binary in MatrixCryptoFramework.xcframework.");
  }

  const aar = fs.readdirSync(dir).filter((f) => f.endsWith(".aar") && big(path.join(dir, f)));
  if (aar.length === 0) {
    problems.push("the installed package carries no non-trivial .aar.");
  }

  if (problems.length) {
    for (const p of problems) console.error("FAIL: " + p);
    process.exit(1);
  }
  console.log("   no install-time script, no binding.gyp");
  console.log("   android jniLibs ABIs with a real .so: " + goodAbis.join(", "));
  console.log("   xcframework slices with a real binary: " + goodSlices.join(", "));
  console.log("   prebuilt aar: " + aar.join(", "));
' "$INSTALLED"

echo
echo "== 4/4  Loading the module out of the installed package (esbuild $ESBUILD_VERSION)"

mkdir -p "$CONSUMER/stub"
cat > "$CONSUMER/stub/react-native.js" <<'STUB'
// Stands in for the react-native runtime, which is a peer dependency a real
// consumer supplies. It records what the package asked for so the assertions
// below can require that the bootstrap actually ran, rather than infer it
// from nothing having thrown.
exports.TurboModuleRegistry = {
  getEnforcing(name) {
    globalThis.__askedForTurboModule = name;
    return {
      installRustCrate() { globalThis.__installRustCrateCalled = true; return true },
      cleanupRustCrate() { return true },
    };
  },
};
STUB

cat > "$CONSUMER/bundle.js" <<'BUNDLER'
const esbuild = require(process.argv[2]);
const path = require('path');
const consumer = process.argv[3];
const entry = path.join(consumer, 'node_modules/react-native-matrix-crypto/src/index.ts');

const stubReactNative = {
  name: 'stub-react-native',
  setup(build) {
    build.onResolve({ filter: /^react-native$/ }, () => ({
      path: path.join(consumer, 'stub/react-native.js'),
    }));
  },
};

(async () => {
  // ESM once, for the static export list. esbuild's metafile reports the
  // entry point's real exports, derived from the module graph rather than
  // from reading a source file, and without executing anything.
  const esm = await esbuild.build({
    entryPoints: [entry],
    bundle: true, platform: 'node', format: 'esm',
    outfile: path.join(consumer, 'bundle.mjs'),
    plugins: [stubReactNative], metafile: true, logLevel: 'warning',
  });
  const out = Object.values(esm.metafile.outputs).find((o) => Array.isArray(o.exports));
  require('fs').writeFileSync(
    path.join(consumer, 'exports.json'),
    JSON.stringify(out ? out.exports : [])
  );

  // CJS once, to execute.
  await esbuild.build({
    entryPoints: [entry],
    bundle: true, platform: 'node', format: 'cjs',
    outfile: path.join(consumer, 'bundle.cjs'),
    plugins: [stubReactNative], logLevel: 'warning',
  });
})().catch((e) => {
  console.error('FAIL: the installed package could not be bundled.');
  console.error('      A consumer\'s Metro build would fail the same way.');
  console.error(String(e && e.message ? e.message : e));
  process.exit(1);
});
BUNDLER

node "$CONSUMER/bundle.js" "$ESBUILD_DIR" "$CONSUMER"

cat > "$CONSUMER/load.cjs" <<'LOADER'
const fs = require('fs');
const consumer = __dirname;

// The JSI host object a React Native runtime installs. Here it is a recorder:
// the first property the module reaches for is remembered, and touching it
// throws a value only this file could have produced. That turns "the load
// stopped at the native boundary" into something asserted rather than
// something inferred from an error message that happened to look right.
const SENTINEL = '__cold_consume_sentinel__';
let firstNativeSymbol = null;
globalThis.NativeMatrixCrypto = new Proxy({}, {
  get(_target, prop) {
    if (firstNativeSymbol === null) firstNativeSymbol = String(prop);
    return () => { const e = new Error(SENTINEL); e.__sentinel = true; throw e };
  },
});

let error = null;
try {
  require(consumer + '/bundle.cjs');
} catch (e) {
  error = e;
}

const exportsList = JSON.parse(fs.readFileSync(consumer + '/exports.json', 'utf8'));

// A representative set of what the README's Usage section tells a consumer to
// import. Deliberately not the whole list: this is a floor that a hollowed-out
// or half-generated build cannot clear, not a second copy of the public API
// that has to be edited whenever the API grows.
const MUST_EXPORT = [
  'createCryptoMachine', 'decryptEvent', 'encryptEvent', 'getDeviceIdentityKeys',
  'markRequestSent', 'onCryptoSignal', 'openCryptoStore', 'receiveSyncChanges',
  'shareScopeKey', 'takeOutgoingRequests',
];

const problems = [];
const missing = MUST_EXPORT.filter((n) => !exportsList.includes(n));
if (missing.length) {
  problems.push('the installed package\'s entry point does not export: ' + missing.join(', ') +
                '\n      It exported: ' + (exportsList.join(', ') || '(nothing)'));
}
if (globalThis.__installRustCrateCalled !== true) {
  problems.push('loading the entry point never called installRustCrate().' +
                '\n      The turbo-module bootstrap in src/index.tsx did not run, so on a' +
                '\n      real device nothing would register with JSI and every native call' +
                '\n      would fail with "Cannot read property ... of undefined".');
}
if (globalThis.__askedForTurboModule !== 'MatrixCrypto') {
  problems.push('the package asked react-native for turbo module ' +
                JSON.stringify(globalThis.__askedForTurboModule) + ', expected "MatrixCrypto".');
}
if (firstNativeSymbol === null) {
  problems.push('the module never reached the native boundary.' +
                '\n      It should have called into the JSI host object; it did not touch it' +
                '\n      at all, which means the generated bindings were not exercised.');
} else if (!/^ubrn_/.test(firstNativeSymbol)) {
  problems.push('the first native symbol reached for was ' + firstNativeSymbol +
                ', which is not a uniffi-bindgen-react-native symbol.');
}
if (!error || error.__sentinel !== true) {
  problems.push('loading did not stop at the native boundary as expected.' +
                '\n      ' + (error ? 'It failed with: ' + error.message : 'It completed, which cannot happen without a JSI host object.'));
}

if (problems.length) {
  for (const p of problems) console.error('FAIL: ' + p);
  process.exit(1);
}

console.log('   entry point exports ' + exportsList.length + ' names, including all of:');
console.log('     ' + MUST_EXPORT.join(', '));
console.log('   executing it called installRustCrate() on turbo module "' + globalThis.__askedForTurboModule + '"');
console.log('   and stopped at the first native symbol, ' + firstNativeSymbol + ',');
console.log('   which no process without a JSI host object can provide.');
LOADER

node "$CONSUMER/load.cjs"

echo
echo "PASS: the published tarball installs with cargo and rustc unreachable,"
echo "      carries the prebuilt binaries into the installed tree, and its"
echo "      entry point loads and runs as far as the native boundary."
echo "      What happens beyond that boundary is probe-android's and"
echo "      interop-level-two's business, on a device and against a homeserver."
