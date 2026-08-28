/**
 * The contract every binding must satisfy.
 *
 * A future binding (wasm, N-API) implements this shape and runs the same
 * suite. Divergence between bindings is a blocking defect per spec
 * section 4bis.3.
 *
 * `runProbe`'s third argument, if given, is called with that one call's own
 * diagnostic signal only -- never anyone else's. It exists to let this
 * suite prove the Rust -> JS callback interface works (a UniFFI callback
 * crossing JSI in the reverse direction) without touching any broadcast
 * channel: `onCryptoSignal` (spec section 7.3, carrying `trust_changed`,
 * `unexpected_device`, `key_missing`) is deliberately not part of this
 * contract, because nothing this suite checks needs it -- proving it stays
 * with `src/signals.test.ts`, against the real public facade.
 */
export interface BridgeBinding {
  runProbe(
    input: string,
    payload: Uint8Array,
    onSignal?: (kind: string) => void,
  ): Promise<{ echoed: string; payload: Uint8Array; coreVersion: string }>
  isCryptoError(e: unknown): boolean
  errorKind(e: unknown): string | undefined
}

export interface InteropCheck {
  name: string
  ok: boolean
  detail: string
}

export interface InteropSuiteOptions {
  /**
   * How long the `signal` check waits for a callback that has not arrived
   * yet, in milliseconds. Defaults to {@link SIGNAL_WAIT_MS}.
   *
   * Only worth setting to exercise the "this binding never signals" branch
   * without paying the full budget for it. A real run should take the
   * default: the point of the wait is to be longer than any delivery this
   * chain has been seen to take.
   */
  signalWaitMs?: number
}

/**
 * How long the `signal` check waits for the observer callback, and how often
 * it looks while waiting.
 *
 * Not a performance claim, and deliberately far larger than a healthy
 * delivery: a run that gets its signal promptly stops waiting immediately, so
 * the budget costs nothing except when something is actually wrong.
 *
 * The number is measured. On a RELEASE build of the example app on
 * emulator-5554 (API 35, 2026-08-28), with a 2000 ms budget the check still
 * reported `signal FAIL (none)` on 1 launch in 8; with 15000 ms it passed 8
 * launches out of 8. So delivery can take seconds on a loaded emulator --
 * worth knowing about the callback path, and not something a check that only
 * asks "did it arrive at all" should be failing over.
 */
const SIGNAL_WAIT_MS = 15000
const SIGNAL_POLL_MS = 20

async function waitUntil(predicate: () => boolean, budgetMs: number): Promise<void> {
  const deadline = Date.now() + budgetMs
  while (!predicate() && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, SIGNAL_POLL_MS))
  }
}

/**
 * The five properties that must hold for any binding. Never throws: a
 * misbehaving binding produces a failing check, not an exception, so a
 * partial result is still reportable from a device.
 *
 * `signal` proves the Rust -> JS callback interface works in the reverse
 * direction -- a UniFFI callback crossing JSI from native back into JS --
 * using the observer `runProbe` already passes to `probeWithObserver`. The
 * callback given to the first `runProbe` call below is a fresh closure over
 * this run's own `signals` array, so it is scoped to this one suite run:
 * nothing another concurrent caller of the same binding does can add to it,
 * and nothing here can add to theirs. That is what keeps this contract free
 * of `onCryptoSignal` entirely -- there is no shared registry left to guard.
 *
 * One path is still worth naming: if `binding.errorKind` or
 * `binding.isCryptoError` throws while building the 'typed_error' check,
 * that throw escapes the inner catch and lands in the outer one, same as
 * any failure inside the main try block. The run still resolves with a
 * 'fatal' check rather than rejecting, but the 'typed_error' and 'signal'
 * checks that would otherwise have run are lost along with it. Safe, but
 * lossier than a clean run -- a known, acceptable limit, not a bug. The
 * same is true if `binding.runProbe` itself throws synchronously instead of
 * rejecting: the throw happens while evaluating the first `await`,
 * still inside the same try block, so it lands in the same 'fatal' catch --
 * no separate guard needed, unlike a persistent subscription that could
 * throw during registration before any check existed to record the fact.
 */
export async function runInteropSuite(
  binding: BridgeBinding,
  options: InteropSuiteOptions = {},
): Promise<InteropCheck[]> {
  const checks: InteropCheck[] = []
  const signals: string[] = []

  try {
    const report = await binding.runProbe('hello', new Uint8Array([1, 2, 3]), (kind) => {
      signals.push(kind)
    })

    checks.push({ name: 'record', ok: report.echoed === 'hello', detail: report.echoed })

    checks.push({
      name: 'bytes',
      ok:
        report.payload.length === 3 &&
        report.payload[0] === 3 &&
        report.payload[1] === 2 &&
        report.payload[2] === 1,
      detail: Array.from(report.payload).join(','),
    })

    checks.push({
      name: 'async',
      ok: typeof report.coreVersion === 'string' && report.coreVersion.length > 0,
      detail: report.coreVersion,
    })

    try {
      await binding.runProbe('', new Uint8Array())
      checks.push({
        name: 'typed_error',
        ok: false,
        detail: 'no error thrown - Rust should have rejected empty input',
      })
    } catch (e) {
      // This check exists to prove a typed error survives the FFI boundary
      // intact: 'rejected' is not a failure symptom, it is the one correct
      // value -- the check passes BECAUSE the error crossed as a typed
      // CryptoError with that kind. Read bare, though, a line ending in
      // the single word "rejected" reads like something broke (raised by
      // the repository owner from a device run). The detail is written as
      // a full sentence so it reads correctly on its own, in both the
      // on-screen list and the PROBE_CHECK line CI scrapes.
      //
      // "(expected)"/"(unexpected)" is chosen from `ok`, not hardcoded to
      // "(expected)": a self-describing detail must not claim the result
      // was expected on a run where it was not -- that would just move
      // this task's own failure mode into the fix for it.
      const kind = binding.errorKind(e)
      const ok = binding.isCryptoError(e) && kind === 'rejected'
      checks.push({
        name: 'typed_error',
        ok,
        detail: `error crossed as typed kind "${kind}" (${ok ? 'expected' : 'unexpected'})`,
      })
    }

    // The observer callback and the promise `runProbe` returns reach
    // JavaScript independently. Rust invokes the observer while the call is
    // still in flight, but which of the two lands on the JS thread first is a
    // dispatch detail of the binding, not part of the contract this suite
    // states -- and reading `signals` straight after the awaits above quietly
    // assumed the callback always won.
    //
    // Measured, not theorised: a RELEASE build of the example app on
    // emulator-5554 (API 35, 2026-08-28) reported `signal FAIL (none)` on 5 of
    // 8 launches and `signal PASS probe_started` on the other 3, with nothing
    // else different between them. The same code in a debug build passed every
    // time -- Hermes bytecode resolves the promise sooner relative to the
    // callback hop, so release loses the race that debug happened to win. The
    // callback was never lost: with a long enough wait it always arrived
    // (8 of 8). This line used to read the array before it got there.
    //
    // Bounded, so it cannot turn the check into a no-op: a binding that never
    // calls the observer still fails, it just takes the budget to say so.
    await waitUntil(() => signals.includes('probe_started'), options.signalWaitMs ?? SIGNAL_WAIT_MS)

    checks.push({
      name: 'signal',
      ok: signals.includes('probe_started'),
      detail: signals.join(',') || '(none)',
    })
  } catch (e) {
    checks.push({ name: 'fatal', ok: false, detail: String(e) })
  }

  return checks
}
