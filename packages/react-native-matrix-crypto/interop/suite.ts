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
export async function runInteropSuite(binding: BridgeBinding): Promise<InteropCheck[]> {
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
