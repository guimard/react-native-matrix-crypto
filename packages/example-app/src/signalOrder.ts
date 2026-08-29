/**
 * A per-process count of observer callbacks this app has received.
 *
 * WHY THIS EXISTS
 *
 * `ProbeHarness` reports `PROBE_SIGNAL_MS` and B2 reads it as the cost of a
 * signal at start-up. For three review rounds that reading came with a claim
 * about *which* signal it was, and the claim was wrong: it said "the first
 * signal of a cold process", reasoning from the true fact that the interop
 * suite issues exactly one observed call. That establishes the harness times
 * only its own call. It does not establish that its call is the process's
 * first emission, and it is not, necessarily -- `App.tsx` renders `GuidedFlow`
 * before `ProbeHarness`, and `GuidedFlow`'s mount effect calls `runProbe` with
 * a non-empty input too, so every cold launch issues two racing calls in
 * sibling components.
 *
 * Rather than reason about which wins, every emission-carrying call site in
 * this app takes a number from here as its signal lands, and `ProbeHarness`
 * reports the number its timed callback drew. A row then says which delivery
 * in the process it measured, instead of a comment asserting it.
 *
 * Deliberately module scope and deliberately not reset. The question is about
 * the process, and every measured launch is its own fresh install; a counter
 * that could be reset would answer a different question.
 */
let delivered = 0

export function nthSignal(): number {
  delivered += 1
  return delivered
}
