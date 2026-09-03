// One Prettier configuration for the whole workspace.
//
// These three options are not a fresh opinion. They are what
// packages/example-app/.prettierrc.js held -- the React Native 0.87 template's
// defaults -- and the example app, the library's TypeScript and the Markdown
// are all already written that way. Changing any of them would turn a
// formatting gate into a repository-wide rewrite, which is the opposite of
// what a formatter is for.
//
// `trailingComma: 'all'` is Prettier 3's default and could be dropped. It is
// kept because it was stated before, and a reader comparing this file against
// the one it replaces should see the same three answers rather than have to
// know which of them the version bump silently absorbed.
//
// The version matters and is pinned EXACTLY in package.json, not to a range,
// because Prettier disagrees with itself in two different sizes.
//
// Across majors: Prettier 2 and 3 disagree about Markdown, and the docs in this
// repository are formatted by 3. Measured 2026-09-02 -- `prettier@2.8.8 --check
// README.md` reports the file as unformatted, 3.x accepts it. So a contributor
// running the 2.8.8 that packages/example-app used to pin would have
// reformatted every README on their first save.
//
// Inside a minor, which is why the `^3.6.2` this line used to carry was not
// enough. That range resolved to 3.9.6, so the lockfile was doing all of the
// pinning and the manifest claimed something weaker than what was running.
// Measured 2026-09-03 -- against the tree 3.9.6 calls clean, `prettier@3.6.2
// --check .` rejects three files: levelTwoSuite.ts, crypto-suite.ts and
// facade.ts, over the space in `for (let i = 0; i < n; )` and over where a
// wrapped union type breaks. Both versions satisfy `^3.6.2`, so a lockfile
// refresh could have swapped one for the other and turned `format:check` red
// on a tree nobody had touched -- a check that reads its own toolchain instead
// of the source. `yarn format:check` holds this source to one shape, and the
// shape has to belong to one version.
module.exports = {
  arrowParens: 'avoid',
  semi: false,
  singleQuote: true,
  trailingComma: 'all',

  // THE GENERATED BINDINGS ARE FORMATTED BY THE GENERATOR, NOT BY `yarn
  // format`, and this override is what keeps that reproducible.
  //
  // ubrn formats its own TypeScript output. It resolves
  // `node_modules/.bin/prettier` by walking up from the directory it is
  // writing into (ubrn_common/src/files.rs), then runs it with `--write` and
  // without `--no-config`. So the four options above reach the generated files
  // through the generator even though .prettierignore keeps `yarn format` off
  // them -- and `gate:drift`, which regenerates and requires a byte-for-byte
  // empty diff, fails on the difference. Watched happening in CI on this
  // branch, run 33669506296: semicolons stripped and trailing commas added
  // across src/generated, with not a line of Rust changed.
  //
  // The four values below are Prettier's own defaults, which is what the
  // committed bindings are written in. Restored rather than adopted
  // repository-wide: the bindings are the tool's output, matching the tool
  // costs nothing, and reformatting them instead would put thousands of lines
  // of machine-written code into a human's diff and buy nothing.
  //
  // Of the four globs, only src/generated is reached by ubrn today -- it runs
  // Prettier over the `bindings.ts` directory from ubrn.config.yaml and no
  // wider. src/NativeMatrixCrypto.ts is the evidence: it is committed with
  // single quotes and no trailing newline, which is raw template output and
  // not something Prettier has ever seen. The other three are listed anyway,
  // because the cost is a line each and the alternative is that a change to
  // ubrn's output directory reformats a generated file with nothing saying
  // why.
  //
  // The pinned `prettier: 2.8.8` in packages/react-native-matrix-crypto's
  // devDependencies is the other half, and it is not optional: Prettier 3
  // formats these files differently from Prettier 2 under every combination of
  // the options above, so the version has to be pinned as well. Measured
  // 2026-09-02 -- `prettier@2.8.8 --no-config` reports
  // src/generated/matrix_crypto.ts as already formatted, and 3.x does not,
  // with or without `--trailing-comma es5`. That 2.8.8 used to arrive by
  // accident, hoisted out of the example app's devDependencies into the
  // workspace root where ubrn happened to find it. It is declared now, in the
  // package that owns the output, which is what codegen.sh's header has been
  // asking for all along.
  overrides: [
    {
      files: [
        'packages/react-native-matrix-crypto/src/generated/**',
        'packages/react-native-matrix-crypto/cpp/generated/**',
        'packages/react-native-matrix-crypto/src/index.tsx',
        'packages/react-native-matrix-crypto/src/NativeMatrixCrypto.ts',
      ],
      options: {
        arrowParens: 'always',
        semi: true,
        singleQuote: false,
        trailingComma: 'es5',
      },
    },
  ],
}
