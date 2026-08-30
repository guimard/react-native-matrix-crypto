/**
 * What the walkthrough's cards claim about the library, checked against the
 * library.
 *
 * NOTHING IS MOCKED IN THIS FILE, on purpose. Every card here asserts
 * something about `react-native-matrix-crypto`, and a claim about the
 * library checked against a fake of the library is not checked at all. The
 * imports below are the published entry point, the same specifier the app
 * itself imports.
 *
 * THE DEFECT THIS EXISTS FOR. The `notYet` card said calling a named
 * function rejects with `not_implemented`. That was true when it was written and
 * stopped being true the moment the library implemented that function, and
 * because the claim lived in a screen with no test runner behind it, the
 * card went on reporting "unexpected" on every launch of a library that was
 * working correctly. It had already happened once before, with a different
 * function, and been fixed by editing the sentence.
 *
 * So the fix is not another edited sentence. A card that asserts an
 * implementation detail of a library under active development WILL rot; the
 * only question is whether it rots in CI or on a developer's phone. These
 * tests put it in CI.
 *
 * THIS FILE NAMED THE CARD BY ITS POSITION, "step 6", and the walkthrough
 * moved it. It is the ninth card's eighth title today, `notYet`, and the
 * package README already said 8 while every name in here said 6, so a
 * reader following one to the other landed on a contradiction. The card is
 * named by its id from here on, because an id does not renumber when a step
 * is inserted above it and a position does. Nothing failed when it did:
 * `NOT_YET_CARD` is looked up by id and always found the right card, so the
 * only thing that was ever wrong was what the test said it was doing.
 */
import { describe, expect, it } from 'vitest'
import * as lib from 'react-native-matrix-crypto'
import { isCryptoError } from 'react-native-matrix-crypto'
import { FLOW_STEPS, type FlowStep } from './steps'
import { runNotYet, type Outcome } from './flowRunners'

/**
 * The functions the facade still refuses in JavaScript, before any native
 * call, with a typed `not_implemented`.
 *
 * Pinned deliberately. When the library implements one of these, this list
 * goes red, and whoever is holding it has to look at the `notYet` card and
 * decide where it should point now. That is the whole mechanism: the list
 * is a tripwire on the library's progress, not a description anyone has to
 * remember to update.
 */
const NOT_IMPLEMENTED_TODAY = ['exportSecrets', 'importSecrets', 'restoreCryptoMachine']

/** The card that names one of them and asserts it rejects. */
const NOT_YET_CARD: FlowStep = FLOW_STEPS.find(step => step.id === 'notYet')!

/**
 * Calls one export with placeholder arguments and reports whether it
 * rejected with `not_implemented`.
 *
 * Every argument is a placeholder because none is read: a function that
 * rejects with `not_implemented` does so before looking at its input, and
 * every other function in this package reaches a native call that is not
 * there and fails on that instead. So the classification below is exact
 * without needing a correct call for each signature, which is what lets it
 * be a sweep rather than a hand-maintained table.
 */
async function rejectsNotImplemented(fn: (...args: unknown[]) => unknown): Promise<boolean> {
  const placeholders = ['placeholder', 'placeholder', 'placeholder'].slice(0, fn.length)
  try {
    await fn(...placeholders)
    return false
  } catch (e) {
    return isCryptoError(e) && e.kind === 'not_implemented'
  }
}

describe('the notYet card claims a call rejects, so the call must reject', () => {
  it('reports ok when the real facade is asked, with nothing mocked', async () => {
    // The defect, exactly. With the card pointing at `getDeviceStatuses`
    // this is the assertion that fails, and it fails with the same words
    // the card put on screen: "Unexpected error shape".
    let outcome: Outcome | undefined
    await runNotYet({ unsubscribe: null, probeSignals: [], storeDir: '' }, (_id, committed) => {
      outcome = committed
    })

    expect(outcome?.status, outcome?.headline).toBe('ok')
    expect(outcome?.headline).toContain('"not_implemented"')
  })

  it('names, in the code a reader is shown, the function the step actually calls', () => {
    // The card and the runner are two files. Nothing but this keeps them
    // pointing at the same function, and a card that demonstrates one
    // function while the row below it exercises another is a worse lie than
    // a stale one, because it looks right.
    const named = NOT_IMPLEMENTED_TODAY.filter(name => NOT_YET_CARD.call.includes(name))
    expect(named).toHaveLength(1)
  })
})

describe('the library surface the cards describe', () => {
  it('still refuses exactly the functions the notYet card is allowed to point at', async () => {
    const found: string[] = []
    for (const [name, value] of Object.entries(lib)) {
      if (typeof value !== 'function') continue
      if (await rejectsNotImplemented(value as (...args: unknown[]) => unknown)) found.push(name)
    }

    // Refuse to pass having swept nothing: an entry point that stopped
    // exporting functions would leave both sides empty and agree.
    expect(Object.values(lib).filter(v => typeof v === 'function').length).toBeGreaterThan(10)
    expect(found.sort()).toEqual([...NOT_IMPLEMENTED_TODAY].sort())
  })

  it('exports every function the cards tell a reader to import', () => {
    // A card shows the exact TypeScript a consumer would write. If the
    // library renames or drops one of those functions, the snippet on
    // screen becomes code that does not compile, and only a person reading
    // the card would ever find out.
    const imported = new Set<string>()
    for (const step of FLOW_STEPS) {
      const match = /import \{([^}]*)\} from 'react-native-matrix-crypto'/.exec(step.call)
      if (!match) continue
      for (const name of match[1].split(',')) {
        const trimmed = name.trim()
        if (trimmed) imported.add(trimmed)
      }
    }

    // Refuse to pass having parsed nothing.
    expect(imported.size).toBeGreaterThan(3)
    for (const name of imported) {
      expect(lib, `card imports ${name}`).toHaveProperty(name)
    }
  })
})

describe('the environment these claims are checked in', () => {
  it('has no native binding, so nothing here can be read as device coverage', () => {
    // Stated as an assertion rather than a comment. Every claim this file
    // checks is one the facade settles in JavaScript; the moment a native
    // module appears in this process, that is no longer obviously true and
    // the file's own description of itself needs rewriting.
    expect((globalThis as Record<string, unknown>).NativeMatrixCrypto).toBeUndefined()
  })
})
