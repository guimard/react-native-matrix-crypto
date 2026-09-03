import React, { useEffect, useState } from 'react'
import { Text, View } from 'react-native'
import type { InteropCheck } from 'react-native-matrix-crypto/interop/suite'
import { LEVEL_TWO_STEPS, runLevelTwoSuite } from './levelTwoSuite'
import type { LevelTwoPlan } from './levelTwoTransport'

/**
 * Runs the level 2 facade exchange once per launch and prints what CI, or a
 * person, reads back out of logcat.
 *
 * # The summary must not be able to lie
 *
 * Three things make that true, and each of them exists because this
 * milestone has already been fooled once:
 *
 * * **The denominator cannot shrink below the promised step list, and is
 *   pinned outside this file.** What is printed is `results.length`, and
 *   reconciliation against `LEVEL_TWO_STEPS` below makes that a floor rather
 *   than a ceiling: a step that could not run prints FAIL and never
 *   vanishes, while a harness-level throw *adds* a check and prints a larger
 *   denominator. So this file can over-count and cannot under-count. It
 *   cannot pin the number itself, because a summary the artifact under test
 *   both produces and validates is not pinned at all -- `EXPECTED_STEPS` in
 *   `level-two/run_level_two.py` is what asserts it is thirteen, from
 *   outside, the way `scripts/run-probe-on-emulator.sh` does for
 *   `PROBE_SUMMARY`.
 * * **A sabotaged run says so in its own summary line.** The suite carries
 *   its mutations permanently rather than being edited to add them, and a
 *   run with one prints `LEVEL2_MUTATED_SUMMARY`, never `LEVEL2_SUMMARY`.
 *   No mutation run can be mistaken for a clean one, in a log or by the
 *   runner.
 * * **An absent summary is a failed run, not a quiet one.** Nothing here can
 *   make that true on its own -- the runner on the host asserts that it
 *   *found* a summary, exactly as `scripts/run-probe-on-emulator.sh` does
 *   for `PROBE_SUMMARY`. An app that crashed on launch prints no FAIL line
 *   either, and reading that absence as success is the failure this
 *   repository keeps rediscovering.
 *
 * # What reaches the log
 *
 * Step names, PASS or FAIL, and details that carry counts, event types and
 * error kinds. Never a value: no access token, no user or device
 * identifier, no room id, no plaintext, no ciphertext, no passphrase. The
 * same rule the probe harness holds itself to, applied to a run that is
 * handed a real credential.
 */
const SUMMARY_PREFIX = 'LEVEL2_SUMMARY'
const MUTATED_SUMMARY_PREFIX = 'LEVEL2_MUTATED_SUMMARY'

/**
 * The one run this process performs, memoised at module scope.
 *
 * Meaningful exactly once per launch, and that is a property of the machine
 * rather than a shortcut: the crypto machine is process-wide and created
 * once, this run's device publishes its one-time keys once, and its access
 * token is revoked by its own teardown. A Metro fast refresh that remounted
 * this component would otherwise manufacture a second, misleading summary --
 * observed for real on the probe harness, which is why it does the same.
 */
let levelTwoRun: Promise<InteropCheck[]> | null = null

export function LevelTwoHarness({
  plan,
  storeDir,
}: {
  plan: LevelTwoPlan
  storeDir: string
}) {
  const [checks, setChecks] = useState<InteropCheck[]>([])

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      let results: InteropCheck[] = []
      try {
        results = await runLevelTwoSuite({ plan, storeDir })
      } catch (e) {
        // The suite is not supposed to be able to reach this: it reports
        // failing checks instead of throwing. If it ever does, the run must
        // still produce a summary -- a harness that throws prints none at
        // all, which reads as "the runner found nothing" rather than as
        // "everything failed".
        results = [
          {
            name: 'harness',
            ok: false,
            detail: `the harness itself failed with a ${
              e instanceof Error ? e.constructor.name : typeof e
            }`,
          },
        ]
      }

      // Reconciled against what was promised, not against what came back.
      for (const name of LEVEL_TWO_STEPS) {
        if (!results.some(check => check.name === name)) {
          results.push({
            name,
            ok: false,
            detail: 'not reported: the run ended before this step could report',
          })
        }
      }

      for (const check of results) {
        console.log(
          `LEVEL2_CHECK ${check.name} ${check.ok ? 'PASS' : 'FAIL'} ${check.detail}`,
        )
      }
      const passed = results.filter(check => check.ok).length
      if (plan.mutation === 'none') {
        console.log(`${SUMMARY_PREFIX} ${passed}/${results.length}`)
      } else {
        console.log(
          `${MUTATED_SUMMARY_PREFIX} ${passed}/${results.length} mutation=${plan.mutation}`,
        )
      }
      return results
    }

    if (levelTwoRun === null) levelTwoRun = run()
    void levelTwoRun.then(results => {
      // Only the on-screen list is gated on this component still being
      // mounted: the lines the runner scrapes were emitted by the run
      // itself, so an unmount can never swallow them.
      if (!cancelled) setChecks(results)
    })
    return () => {
      cancelled = true
    }
    // `[]` rather than `[plan, storeDir]`, matching the memo above: the
    // machine this run creates is process-wide and created once, so a later
    // plan could not be honoured even if this did re-run. A maintainer
    // reads the dependency array first, and it must not be the half of the
    // contradiction that wins.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <View>
      {checks.map(check => (
        <Text
          key={check.name}
        >{`${check.name}: ${check.ok ? 'PASS' : 'FAIL'} (${check.detail})`}</Text>
      ))}
    </View>
  )
}
