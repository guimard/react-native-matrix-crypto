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
 * WHERE THE ORIGINAL NUMBER CAME FROM, AND WHAT IS STILL UNEXPLAINED
 *
 * 15000 came from a release build on emulator-5554 (API 35, 2026-08-28),
 * where a 2000 ms budget still reported `signal FAIL (none)` on 1 launch in 8
 * and 15000 ms passed 8 of 8.
 *
 * **That 1-in-8 has never been explained, and nothing since has reproduced
 * it.** It is stated here rather than left implicit because everything below
 * is sized against it. Two things in it are worth keeping apart:
 *
 * - It was taken with a pass/fail check and no latency instrument, so it
 *   cannot tell "the callback arrived after 2000 ms" from "the callback did
 *   not arrive". The 8-of-8 pass at 15000 ms is weaker than it looks: at a
 *   1-in-8 rate, eight clean launches happen 34% of the time.
 * - The emission mechanism has been ruled out, and nothing has been ruled in.
 *   M3 replaced `observer.rs`'s thread-per-signal emission with the runtime's
 *   blocking pool (spec section 5.1, B2), and the before arm of the
 *   measurement below *is* that thread-per-signal emission. Both arms are
 *   milliseconds, and the slower of the two is the new one. So the sentence
 *   this comment used to carry -- delivery was thought to take seconds, and
 *   that was measured against the emission M3 replaced -- invited a causal
 *   reading its own before arm refutes twice over.
 *
 * WHAT WAS MEASURED
 *
 * Re-measured on the same emulator, same API level, same release build, with
 * `PROBE_SIGNAL_MS` (see `ProbeHarness.tsx`) reporting the delivery in
 * milliseconds rather than only pass or fail. 40 launches, 20 on each side
 * of the change, interleaved launch by launch so host state fell on both arms
 * equally; 28 of them with the host deliberately saturated, 10 by CPU
 * and 18 by disk:
 *
 *   before (thread per signal): median 2 ms, p90 23.1 ms, max 37 ms
 *   after  (blocking pool):     median 9.5 ms, p90 32.6 ms, max 59 ms
 *
 * Every one of the 40 passed. **The seconds did not reproduce, on either
 * arm.** What did reproduce is the race: the callback lands after the promise
 * in 20 of the 40, which is exactly why this bounded wait exists and why it
 * must stay. Its magnitude is milliseconds, not seconds.
 *
 * WHICH WAY THE DIFFERENCE RUNS
 *
 * The blocking pool is the slower of the two on this measurement: median
 * 9.5 ms against 2 ms, and higher in every host condition separately. The
 * tails overlap -- p90 32.6 ms against 23.1 ms, worst 59 ms against 37 ms --
 * so the separation is in the body rather than the tail. It is real but it is
 * one-star: 12 of 20 interleaved pairs favour the new path being slower, 6
 * run the other way and 2 tie. A Wilcoxon signed-rank test puts that at
 * p ~ 0.04, a paired sign-flip permutation on the median at p ~ 0.03, and the
 * same permutation on the mean at p ~ 0.08 -- the mean being dragged by two
 * outlying pairs, a -35 ms and a +58 ms. The weakest of the three is quoted
 * here because it is the one a reader cannot recompute from the counts above.
 * Do not read any of it as more than one star.
 *
 * **Slower, and the cause is not established.** What is measured about the
 * cause, rather than argued: the excess is confined to the *first* signal of a
 * process -- a second signal in the same process makes the two paths
 * indistinguishable -- and it is not fixed work, because the two arms share a
 * floor while the gap grows with contention. A first draft of this note
 * attributed it confidently to building the tokio runtime; that is one
 * candidate among several first-use costs and this branch has not separated
 * them. `observer::emit` carries the detail. None of it bears on this budget,
 * which is milliseconds against ten seconds; what it does mean is that "the
 * measurement did not move" would be the wrong summary.
 *
 * The two arms were provably different binaries, which the first attempt at
 * this measurement could not establish: `coreVersion` now carries a
 * fingerprint of the emission path compiled into the running `.so`
 * (`observer.rs`'s `EMIT_BUILD`), every launch printed it, and the two arms
 * printed different values. The full record, procedure and every sample is
 * `docs/measurements/2026-08-29-signal-delivery-latency.md`.
 *
 * WHY 10000 AND NOT 3000
 *
 * Because the margin has to be measured against the phenomenon this budget
 * exists to absorb, and that phenomenon is not in the distribution above --
 * the distribution above is precisely the one that could not reproduce it.
 * "Thirty times the worst of those launches" is a true sentence about the
 * wrong distribution.
 *
 * The only hard facts available are that 2000 ms was observed to be
 * insufficient on this hardware, and that 15000 ms was observed sufficient
 * eight times out of eight, which as noted above is weak. 10000 interpolates
 * between them: five times above the one hard negative, below the one weak
 * positive. Nothing has ever been observed at 10000 itself, so being "below
 * the value never observed failing" is not evidence for it -- it is only the
 * absence of evidence against it, and this sentence used to blur the two. It
 * is not derived from the clean distribution at all, and it should not be: a
 * budget sized at 1.5x a number that was watched failing is sized against the
 * wrong evidence, and `probe-android` is the wrong job to be wrong in -- a
 * slower machine than the one measured (x86_64 emulator,
 * software GPU, four-vCPU hosted runner), taking most of an hour, gated on
 * the verbatim `PROBE_SUMMARY 12/12` line, so one late signal turns it red
 * with no partial credit.
 *
 * Tightening this number is also no longer how sensitivity is bought.
 * `PROBE_SIGNAL_MS` reports the actual delivery time on every launch, so a
 * regression that puts delivery back into seconds is visible in the log of
 * every run whether or not this check fails. What is left for the budget to
 * do is not turn an hour-long job red on a phenomenon nobody has bounded.
 *
 * WHAT THIS NUMBER DOES NOT COVER
 *
 * iOS. This constant lives in the binding-agnostic contract every binding
 * must satisfy, and it was derived from Android alone: `ci.yml` runs no iOS
 * end-to-end leg, so the JSI callback path this bounds on iOS has never been
 * measured and is not exercised by any job. The number is not known to be
 * right there; it is known to be generous on the one binding that was
 * measured.
 *
 * IF THIS EVER GOES RED
 *
 * Read the `PROBE_SIGNAL_MS` line from the same launch before touching this
 * number. The callback keeps arriving after this check has given up, and the
 * app keeps running, so a late delivery still prints its own latency, and the
 * check alone cannot tell "late" from "lost".
 *
 * Read the absence of the line for exactly what it bounds, which is less than
 * it looks. `scripts/run-probe-on-emulator.sh` waits
 * `PROBE_LATE_GRACE_SECONDS` (15 by default) after the summary before dumping
 * the `PROBE_` lines, so a missing line means the callback did not arrive
 * within roughly this budget plus that grace -- not that it never arrived.
 * Nothing bounds how late a lost-looking callback could be; that it is
 * unbounded is the open finding above. The grace window is still worth having:
 * the script used to read the log once, immediately, so a delivery landing one
 * second after the summary was absent from the artifact and read as lost.
 */
const SIGNAL_WAIT_MS = 10000
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
    // Re-measured after M3 changed the emission mechanism, against both the
    // old emission and the new one, and the race is still here: the callback
    // landed after the promise in 20 of 40 release launches. What changed is
    // not its size but what is known about it -- see SIGNAL_WAIT_MS, which
    // now says milliseconds where it used to say seconds, and says which of
    // the two emission paths each launch was running.
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
