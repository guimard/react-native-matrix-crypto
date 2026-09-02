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
// The version matters and is pinned to a major in package.json: Prettier 2 and
// 3 disagree about Markdown, and the docs in this repository are formatted by
// 3. Measured 2026-09-02 -- `prettier@2.8.8 --check README.md` reports the file
// as unformatted, `prettier@3.6.2 --check` accepts it. So a contributor running
// the 2.8.8 that packages/example-app used to pin would have reformatted every
// README on their first save.
module.exports = {
  arrowParens: 'avoid',
  semi: false,
  singleQuote: true,
  trailingComma: 'all',
}
