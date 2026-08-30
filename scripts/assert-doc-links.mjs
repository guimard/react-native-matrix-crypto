// Every `{@link X}` in the published package's own sources resolves.
//
// See `assert-doc-links.sh` for why this exists and what it does not catch.
// The head of a dotted link is what has to be in scope, so `{@link A.b}`
// checks `A`.
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const SRC = 'packages/react-native-matrix-crypto/src'

const LINK = /\{@link\s+([A-Za-z_$][\w$]*)/g
const DECL =
  /^\s*(?:export\s+)?(?:declare\s+)?(?:async\s+)?(?:function|const|let|var|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/gm
const IMPORTS = /import\s+(?:type\s+)?\{([^}]*)\}\s+from/gs

const files = readdirSync(SRC).filter(
  (f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && !f.endsWith('.type-test.ts'),
)

// Refuse to pass having scanned nothing: a moved directory or a renamed
// suffix would otherwise leave this loop empty and trivially agree, which is
// the rule every other gate in this directory follows.
if (files.length === 0) {
  console.error('FAIL: refusing to pass having scanned nothing.')
  console.error(`      No hand-written .ts sources found under ${SRC}.`)
  process.exit(1)
}

let broken = 0
let checked = 0
for (const file of files.sort()) {
  const text = readFileSync(join(SRC, file), 'utf8')
  const scope = new Set()
  for (const m of text.matchAll(DECL)) scope.add(m[1])
  for (const m of text.matchAll(IMPORTS)) {
    for (const raw of m[1].split(',')) {
      const name = raw.trim().replace(/^type\s+/, '').split(/\s+as\s+/).pop()?.trim()
      if (name) scope.add(name)
    }
  }
  const missing = new Map()
  for (const m of text.matchAll(LINK)) {
    checked += 1
    if (scope.has(m[1])) continue
    const line = text.slice(0, m.index).split('\n').length
    if (!missing.has(m[1])) missing.set(m[1], [])
    missing.get(m[1]).push(line)
  }
  for (const [name, lines] of [...missing].sort()) {
    broken += 1
    console.error(`FAIL: ${file}:${lines.join(',')} {@link ${name}} resolves to nothing.`)
  }
}

if (broken > 0) {
  console.error('')
  console.error(`      ${broken} name(s) linked and not in scope. \`{@link}\` resolves`)
  console.error('      against the file it is written in, so add the name to that')
  console.error("      file's type-only import block. Those blocks exist for this.")
  process.exit(1)
}

console.log(`PASS: ${checked} {@link} references across ${files.length} files all resolve`)
