// ESLint for the whole workspace, in one flat config.
//
// It replaces packages/example-app/.eslintrc.js, which was the only lint
// configuration this repository had: the published library, the interop suite
// and the Node scripts under scripts/ were linted by nothing at all.
//
// The rules come from @react-native/eslint-config -- the same shareable config
// the example app already extended -- through its `./flat` entry point, which
// 0.87.1 ships and which is what makes ESLint 9 usable here. Everything in this
// repository is React Native code or tooling around it, so one config for the
// workspace is the honest shape; two configs would drift apart with nothing
// checking that they had not, which is a failure mode this repository has
// already paid for elsewhere.
import reactNative from '@react-native/eslint-config/flat'
import prettier from 'eslint-config-prettier'

// @react-native/eslint-config parses `**/*.js` with @babel/eslint-parser and
// runs eslint-plugin-ft-flow over the result, because the React Native
// template's .js files are Flow. This repository has no Flow: it is TypeScript
// throughout, and its four .js files are CommonJS tool configs.
//
// That entry has to go rather than merely be quietened, for two reasons that
// each stand alone. eslint-plugin-ft-flow 2.0.3 declares a peer of eslint
// ^8.1.0 and means it -- under ESLint 9 it crashes on the first .js file with
// `TypeError: context.getAllComments is not a function`, a hard stop rather
// than a finding. And @babel/eslint-parser refuses to run without a Babel
// config it can find, which from the repository root it cannot: `yarn lint`
// runs here, Babel resolves a root config against the working directory, and
// packages/example-app/babel.config.js is invisible from this one. Dropping
// the entry answers both: the .js files are then parsed by ESLint's own
// parser, which is all a CommonJS config file has ever needed.
//
// Matched on the plugin rather than on an array index, so that a React Native
// upgrade reordering its config does not silently reinstate this.
const withoutFlow = reactNative.filter(entry => !entry.plugins?.['ft-flow'])

export default [
  {
    // A config object carrying `ignores` and nothing else sets the global
    // ignore list. Anything else in the object would make it an ordinary
    // per-file override instead, and the paths below would still be linted.
    ignores: [
      'node_modules/',
      '**/node_modules/',

      // GENERATED BINDINGS -- every entry in scripts/generated-paths.txt that
      // ESLint has a parser for. That file is this repository's single
      // definition of "generated", and gate:drift regenerates each entry and
      // requires a byte-for-byte empty diff against what is committed. So a
      // `--fix` landing in one of them is not a lint improvement: it is a red
      // gate on the next run, whose only remedy is to revert the file.
      //
      // Listed by hand because ESLint loads this config before anything here
      // could read that list, and a config that reads a file at load time
      // fails as a config error rather than as the missing file it is. The
      // four entries omitted (cpp/generated, android, ios, MatrixCrypto.podspec)
      // hold nothing ESLint parses.
      'packages/react-native-matrix-crypto/src/generated/',
      'packages/react-native-matrix-crypto/src/index.tsx',
      'packages/react-native-matrix-crypto/src/NativeMatrixCrypto.ts',

      // The React Native template's native projects, plus build outputs and
      // vendored trees -- all already in .gitignore. Naming them keeps
      // `yarn lint` off a working copy that has actually built something.
      'packages/example-app/ios/',
      'packages/example-app/android/',
      'rust/target/',
      '**/build/',
      '**/Pods/',
      'api-docs/',
    ],
  },

  ...withoutFlow,

  {
    // @react-native/eslint-config parses `**/*.js` with @babel/eslint-parser,
    // which by default refuses to run without a Babel config it can find for
    // the file. `yarn lint` runs from the repository root, and Babel resolves
    // a root config against the process's working directory -- so
    // packages/example-app/babel.config.js is invisible from here and all four
    // .js files in this repository fail to parse rather than to lint.
    //
    // Turning the requirement off is the right fix rather than pointing Babel
    // at that config: these files are CommonJS with no syntax needing a
    // transform, and the example app's Babel config exists for Metro, not for
    // a linter.
    files: ['**/*.js'],
    languageOptions: { parserOptions: { requireConfigFile: false } },
  },

  {
    // scripts/*.mjs run under Node, not on a device, and the React Native
    // config brings only a device's globals. Without this, every `process` and
    // `console` in scripts/assert-doc-links.mjs reads as no-undef.
    files: ['scripts/**/*.mjs', '*.mjs'],
    languageOptions: {
      sourceType: 'module',
      globals: { console: 'readonly', process: 'readonly', URL: 'readonly' },
    },
  },

  {
    // Two of the shareable config's rules describe a React Native app rather
    // than this library, and both fire on code that is doing exactly what it
    // means to. Left on, they are roughly eighty warnings that a reader learns
    // to scroll past -- which is how the ones worth reading get missed.
    rules: {
      // This is a cryptography binding. Bitwise operators here are QR-code
      // payload packing (interop/crypto-suite.ts), varint decoding
      // (example-app/src/levelTwoSuite.ts) and byte assembly -- the operation
      // meant, spelled the only way it is spelled.
      'no-bitwise': 'off',

      // `void somePromise()` is this codebase's marker for a deliberately
      // unawaited call, in React effect bodies and event handlers that cannot
      // be async. The rule reads it as a stylistic accident; here it is the
      // signal, and removing it would leave a floating promise looking like an
      // oversight.
      'no-void': 'off',
    },
  },

  // eslint-config-prettier last, deliberately. @react-native/eslint-config
  // applies it too -- but as the FIRST element of its array, so any stylistic
  // rule its own later entries switch back on is live again. Repeating it here
  // is what actually guarantees ESLint never reports on something `yarn format`
  // is about to rewrite, and that the two tools cannot disagree.
  prettier,
]
