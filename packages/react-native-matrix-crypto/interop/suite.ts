/**
 * The contract every binding must satisfy.
 *
 * A future binding (wasm, N-API) implements this shape and runs the same
 * suite. Divergence between bindings is a blocking defect per spec
 * section 4bis.3.
 */
export interface BridgeBinding {
  runProbe(
    input: string,
    payload: Uint8Array,
  ): Promise<{ echoed: string; payload: Uint8Array; coreVersion: string }>
  onCryptoSignal(cb: (s: { kind: string }) => void): () => void
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
 * Two paths a single try/catch around the checks would miss:
 * - subscribing itself is guarded separately, and `unsubscribe` is seeded
 *   with a no-op before that runs. A binding whose `onCryptoSignal` throws
 *   synchronously when called would otherwise reject before a single check
 *   was recorded, and referencing `unsubscribe` in `finally` would hit an
 *   uninitialized binding on top of that. With the guard, signals just stay
 *   empty and the 'signal' check fails honestly instead.
 * - calling the binding-supplied `unsubscribe` is itself guarded. A `throw`
 *   from a `finally` block replaces whatever the try/catch was about to
 *   produce, discarding every check already collected -- exactly the
 *   all-or-nothing failure this function exists to avoid.
 *
 * A third path needs no separate guard, but is worth naming: if
 * `binding.errorKind` or `binding.isCryptoError` throws while building the
 * 'typed_error' check, that throw escapes the inner catch and lands in the
 * outer one, same as any failure inside the main try block. The run still
 * resolves with a 'fatal' check rather than rejecting, but the 'typed_error'
 * and 'signal' checks that would otherwise have run are lost along with it.
 * Safe, but lossier than the two paths above -- a known, acceptable limit,
 * not a bug.
 */
export async function runInteropSuite(binding: BridgeBinding): Promise<InteropCheck[]> {
  const checks: InteropCheck[] = []
  const signals: string[] = []

  let unsubscribe: () => void = () => {}
  try {
    unsubscribe = binding.onCryptoSignal((s) => signals.push(s.kind))
  } catch {
    // Leave signals empty and continue: the 'signal' check below will fail
    // honestly rather than the whole suite throwing.
  }

  try {
    const report = await binding.runProbe('hello', new Uint8Array([1, 2, 3]))

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
      checks.push({ name: 'typed_error', ok: false, detail: 'no error thrown' })
    } catch (e) {
      checks.push({
        name: 'typed_error',
        ok: binding.isCryptoError(e) && binding.errorKind(e) === 'rejected',
        detail: String(binding.errorKind(e)),
      })
    }

    checks.push({
      name: 'signal',
      ok: signals.includes('probe_started'),
      detail: signals.join(',') || '(none)',
    })
  } catch (e) {
    checks.push({ name: 'fatal', ok: false, detail: String(e) })
  } finally {
    try {
      unsubscribe()
    } catch {
      // Best-effort cleanup: a broken unsubscribe must not discard the
      // checks already collected above.
    }
  }

  return checks
}
