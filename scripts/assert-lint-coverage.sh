#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Every tracked file ESLint should lint, ESLint actually opened.
#
# `yarn lint` blocks on findings -- `eslint . --max-warnings 0` exits 1 on an
# error and on a warning, and it is the first step of the `gates` job. What it
# cannot do is tell you it linted the wrong set: `eslint .` exits 0 whether it
# found nothing wrong or found nothing at all, and a file it never opened
# produces exactly the same silence as a file that is clean.
#
# That is not hypothetical here. packages/example-app/vitest.config.mts sat
# unlinted through this milestone's lint work and through a green CI run:
# @react-native/eslint-config selects its TypeScript rules on `**/*.ts` and
# `**/*.tsx`, ESLint's own discovery adds only `.js`, `.cjs` and `.mjs`, and
# `.mts` fell between them. Nothing failed. A human reviewer found it, which is
# not a mechanism.
#
# IT ASKS ESLINT, twice, and compares the two answers:
#
#   - `lintFiles(['.'])` is precisely what `eslint .` runs, and its results
#     name every file that was actually opened.
#   - a SECOND, throwaway ESLint whose whole configuration is this repository's
#     `ignores` list plus one `files` entry naming every lintable extension.
#     Asked whether a path is ignored, it can only answer yes because an
#     `ignores` glob matched -- there is no other way to miss.
#
# THE SECOND ONE IS NOT AN ELABORATION, and the first draft of this gate got it
# wrong. It asked the real ESLint's `isPathIgnored()`, which answers `true` for
# two different things: "you told me to skip this" and "no configuration in
# this file matches it". Those are the exact two cases this gate exists to tell
# apart, so it counted the unlinted .mts as deliberately ignored and passed --
# watched doing it, on the very tree the defect was found in. A universal
# `files` entry removes the second reading: every path matches something, so
# `true` can only mean the ignore list.
#
# The extensions in that entry are spelled out rather than written `**/*`, and
# that is not a style choice: `**/*` is a universal pattern to ESLint and does
# NOT widen the set of extensions it will consider. Measured while writing this
# -- with the ignore list EMPTY and `files: ['**/*']`, the probe still called
# packages/example-app/App.tsx ignored, because `.tsx` is not one of the
# extensions ESLint discovers by default. A probe that answers "ignored" for
# everything makes this gate pass on any tree at all.
#
# What is left is the set that should have been linted and was not. Compared
# against `git ls-files` rather than a walk of the tree, so build outputs and
# anything else untracked cannot make this fail, and so a new source file is
# covered the moment it is added.

# shellcheck disable=SC2016  # The `${...}` below are JavaScript template
# literals read by node, not shell expansions.
node -e '
  const { execFileSync } = require("child_process")
  const path = require("path")
  const { ESLint } = require("eslint")

  // The extensions ESLint is configured for in this repository: its own
  // defaults plus what eslint.config.mjs adds. A file with an extension not
  // in this list is not a gap in coverage, it is out of scope.
  const LINTABLE = /\.(js|jsx|cjs|mjs|ts|tsx|mts|cts)$/

  const tracked = execFileSync("git", ["ls-files"], { encoding: "utf8" })
    .split("\n")
    .filter(f => f && LINTABLE.test(f))

  if (tracked.length === 0) {
    console.error("FAIL: refusing to pass having compared nothing.")
    console.error("      `git ls-files` names no file with a lintable extension,")
    console.error("      which means this check broke rather than that the tree")
    console.error("      is fully covered.")
    process.exit(1)
  }

  const run = async () => {
    const eslint = new ESLint()
    const results = await eslint.lintFiles(["."])
    const linted = new Set(results.map(r => r.filePath))

    // The ignore list this repository declares, read off the config rather
    // than copied here, so the two cannot drift apart.
    const config = (await import("./eslint.config.mjs")).default
    const ignores = config.flatMap(entry =>
      Object.keys(entry).length === 1 && entry.ignores ? entry.ignores : [],
    )
    if (ignores.length === 0) {
      console.error("FAIL: refusing to pass having compared nothing.")
      console.error("      eslint.config.mjs declares no global ignores, so this")
      console.error("      check cannot tell a deliberate exclusion from a file")
      console.error("      that simply matched no configuration.")
      process.exit(1)
    }
    const ignoreProbe = new ESLint({
      overrideConfigFile: true,
      overrideConfig: [
        { ignores },
        { files: ["**/*.{js,jsx,cjs,mjs,ts,tsx,mts,cts}"], rules: {} },
      ],
    })

    if (linted.size === 0) {
      console.error("FAIL: refusing to pass having compared nothing.")
      console.error("      `eslint .` opened no file at all. That is a broken")
      console.error("      configuration, not a clean tree -- and it is exactly")
      console.error("      the state `yarn lint` would report as success.")
      process.exit(1)
    }

    const missing = []
    let ignored = 0
    for (const file of tracked) {
      if (await ignoreProbe.isPathIgnored(file)) {
        ignored += 1
        continue
      }
      if (!linted.has(path.resolve(file))) missing.push(file)
    }

    if (missing.length > 0) {
      console.error("FAIL: tracked file(s) that ESLint neither linted nor was")
      console.error("      told to ignore:")
      for (const f of missing) console.error(`        ${f}`)
      console.error("      `yarn lint` is green on these because it never opened")
      console.error("      them. Give eslint.config.mjs a `files` entry that")
      console.error("      matches them, or an `ignores` entry that says so out")
      console.error("      loud.")
      process.exit(1)
    }

    const expected = tracked.length - ignored
    console.log(
      `PASS: lint coverage (${tracked.length} tracked lintable files; ` +
        `${ignored} ignored on purpose, ${expected} linted, none missed)`,
    )
  }

  run().catch(e => {
    console.error("FAIL: the check itself threw, which is not a pass.")
    console.error(e)
    process.exit(1)
  })
'
