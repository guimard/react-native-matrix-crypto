#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Prettier and ESLint both refuse to touch every generated path, and both are
# asked rather than read.
#
# `scripts/generated-paths.txt` is this repository's single definition of
# "generated", and `gate:drift` regenerates every entry there and requires a
# byte-for-byte empty diff. A formatter or a `--fix` landing inside one of
# those paths therefore does not produce a formatting improvement; it produces
# a red gate on the next run, whose only remedy is to revert the file. The
# ignore lists in `.prettierignore` and `eslint.config.mjs` are what stop that,
# and both are maintained by hand: neither file has an include mechanism, and
# ESLint loads its config before anything here could read a list off disk.
#
# A hand-maintained mirror with nothing checking it is the shape of defect this
# repository keeps paying for, and this one had already drifted before it
# landed. Both lists were written as the parseable SUBSET of generated-paths,
# under a comment asserting that the omitted entries held nothing either tool
# could parse. That was false as written: `android/README.md` is Markdown, and
# `packages/react-native-matrix-crypto/android` is one of the omitted entries.
# The lists mirror generated-paths.txt whole now, and this is the check.
#
# IT ASKS THE TOOLS. `prettier.getFileInfo()` and `ESLint#isPathIgnored()` are
# the same code paths `yarn format` and `yarn lint` take, so this cannot pass
# on a pattern that looks right and matches nothing -- a trailing slash, a
# missing `**/`, a path relative to the wrong directory. Comparing strings
# against the list would have re-asked the question the list already answers.

PATHS_FILE=scripts/generated-paths.txt

if [ ! -s "$PATHS_FILE" ]; then
  echo "FAIL: $PATHS_FILE is missing or empty, so there is no definition of"
  echo "      'generated' to hold the ignore lists to."
  exit 1
fi

node -e '
  const fs = require("fs")
  const path = require("path")
  const prettier = require("prettier")
  const { ESLint } = require("eslint")

  const entries = fs
    .readFileSync(process.argv[1], "utf8")
    .split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"))

  if (entries.length === 0) {
    console.error("FAIL: refusing to pass having checked nothing.")
    console.error(`      ${process.argv[1]} lists no path, which means this check`)
    console.error("      broke rather than that every generated path is ignored.")
    process.exit(1)
  }

  // A directory entry is a promise about everything under it, so every file
  // under it is what gets asked about. A missing entry is a failure in itself:
  // generated-paths.txt naming a path that is not there means one of the two
  // files is wrong, and this gate is not the place to guess which.
  const files = []
  const walk = dir => {
    for (const d of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, d.name)
      if (d.isDirectory()) walk(p)
      else files.push(p)
    }
  }
  for (const entry of entries) {
    if (!fs.existsSync(entry)) {
      console.error(`FAIL: ${process.argv[1]} names ${entry}, which does not exist.`)
      console.error("      Either the path moved and that file did not follow, or")
      console.error("      the tree is incomplete; both are worth stopping for.")
      process.exit(1)
    }
    if (fs.statSync(entry).isDirectory()) walk(entry)
    else files.push(entry)
  }

  if (files.length === 0) {
    console.error("FAIL: refusing to pass having checked nothing.")
    console.error("      Every generated path resolved to an empty directory.")
    process.exit(1)
  }

  const eslint = new ESLint()
  const broken = []
  let prettierChecked = 0
  let eslintChecked = 0

  const run = async () => {
    for (const file of files) {
      // Two calls, and they are not redundant. `getFileInfo` reports
      // `inferredParser: null` for a file it is told to ignore -- so asking
      // once, with the ignore file, cannot tell "Prettier would never format
      // this" apart from "Prettier is being told not to", and a check built on
      // the single call passes on an empty ignore list. The first call asks
      // what Prettier could do; the second asks what it will do.
      const { inferredParser } = await prettier.getFileInfo(file)
      // A file Prettier has no parser for cannot be rewritten by it, so an
      // ignore entry is not what protects it and its absence is not a finding.
      // Counted separately so the summary cannot be read as more coverage than
      // there is.
      if (inferredParser !== null) {
        prettierChecked += 1
        const { ignored } = await prettier.getFileInfo(file, {
          ignorePath: ".prettierignore",
        })
        if (!ignored) broken.push(`prettier would format ${file}`)
      }
      // ESLint has the same distinction and no public way to ask it, so the
      // extensions it is configured for are named here.
      if (/\.(js|jsx|mjs|cjs|ts|tsx)$/.test(file)) {
        eslintChecked += 1
        if (!(await eslint.isPathIgnored(file))) {
          broken.push(`eslint would lint ${file}`)
        }
      }
    }

    if (broken.length > 0) {
      console.error("FAIL: a generated path is not ignored by one of the two")
      console.error("      formatters, so a `yarn format` or a `yarn lint --fix`")
      console.error("      would rewrite it and turn gate:drift red:")
      for (const b of broken) console.error(`        ${b}`)
      console.error("      Add it to .prettierignore or to eslint.config.mjs.")
      process.exit(1)
    }

    // Both counts have to be non-zero. Prettier alone reaching zero would mean
    // the walk found only files it has no parser for, which is not the tree
    // this repository has, and would leave the Prettier half asserting nothing.
    if (prettierChecked === 0 || eslintChecked === 0) {
      console.error("FAIL: refusing to pass having checked nothing.")
      console.error(`      ${prettierChecked} file(s) Prettier can parse and`)
      console.error(`      ${eslintChecked} file(s) ESLint can parse, under`)
      console.error(`      ${files.length} generated file(s). A zero here means the`)
      console.error("      walk or the extension list broke, not that the tree is clean.")
      process.exit(1)
    }

    console.log(
      `PASS: formatter ignores (${files.length} generated files; ` +
        `${prettierChecked} Prettier can parse, ${eslintChecked} ESLint can, ` +
        "all ignored by both)",
    )
  }

  run().catch(e => {
    console.error("FAIL: the check itself threw, which is not a pass.")
    console.error(e)
    process.exit(1)
  })
' "$PATHS_FILE"
