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
 * Not a performance claim: a run that gets its signal promptly stops waiting
 * immediately, so the budget costs nothing except when something is actually
 * wrong. But it is not free to oversize either. This check is the only
 * automated thing that watches the Rust-to-JavaScript callback path, and a
 * budget far above any delivery the path can produce stays green long after
 * the thing it measures has broken.
 *
 * WHAT THIS NUMBER IS MEASURED FROM
 *
 * 15000 came from a release build on emulator-5554 (API 35, 2026-08-28),
 * where a 2000 ms budget still reported `signal FAIL (none)` on 1 launch in 8
 * and 15000 ms passed 8 of 8 -- so delivery was thought to take seconds. That
 * was measured against `observer.rs`'s thread-per-signal emission, which M3
 * replaced with the runtime's blocking pool (spec section 5.1, B2).
 *
 * Re-measured on the same emulator, same API level, same release build, with
 * `PROBE_SIGNAL_MS` (see `ProbeHarness.tsx`) reporting the delivery in
 * milliseconds rather than only pass or fail. 46 launches, 23 on each side of
 * the change, interleaved launch by launch so host load fell on both arms
 * equally; 30 of the 46 with the host deliberately saturated:
 *
 *   before (thread per signal): median 3 ms, p90 14 ms, max 102 ms
 *   after  (blocking pool):     median 4 ms, p90 28 ms, max 38 ms
 *
 * Every one of the 46 passed. **The seconds did not reproduce, on either
 * arm.** What did reproduce is the race: the callback lands after the promise
 * in 28 of the 46, which is exactly why this bounded wait exists and why it
 * must stay. Its magnitude is milliseconds, not seconds.
 *
 * WHY 3000 AND NOT 100
 *
 * 3000 ms is roughly thirty times the worst of those 46 launches. The margin
 * is not measured, and saying so is the point: `probe-android` runs an
 * x86_64 emulator under a software GPU on a four-vCPU hosted runner, which is
 * a slower machine than the one measured above and could not be measured
 * here. The margin is for that, and it is deliberately large.
 *
 * It is still five times tighter than 15000, which is what makes it useful: a
 * regression that puts delivery back into seconds -- the condition B2 was
 * opened for -- now fails this check instead of passing quietly inside the
 * budget.
 *
 * IF THIS EVER GOES RED
 *
 * Read the `PROBE_SIGNAL_MS` line from the same launch before touching this
 * number. The callback keeps arriving after this check has given up, and the
 * harness keeps logging for another ten seconds or so, so a late delivery
 * still prints its own latency -- the line's absence means the callback was
 * lost, its presence means it was late, and the check alone cannot tell those
 * apart.
 */
const SIGNAL_WAIT_MS = 3000
const SIGNAL_POLL_MS = 20

async function waitUntil(predicate: () => boolean, budgetMs: number): Promise<void> {
  const deadline = Date.now() + budgetMs
  while (!predicate() && Date.now() < deadline) {
    // `setTimeout(resolve, ms)` is the idiomatic form and does not compile
    // here. React Native types `setTimeout`'s callback as `() => void`, while
    // `Promise`'s resolve is `(value: unknown) => void`, so passing it
    // directly is rejected under the example app's settings even though the
    // library's own typecheck accepts it: the two use different `lib` and
    // `types`. Wrapping keeps both happy.
    await new Promise<void>((resolve) => {
      setTimeout(() => resolve(), SIGNAL_POLL_MS)
    })
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
    // Re-measured after M3 changed the emission mechanism, and the race is
    // still here: the callback landed after the promise in 28 of 46 release
    // launches. Only its size changed -- see SIGNAL_WAIT_MS, which now says
    // milliseconds where it used to say seconds.
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
