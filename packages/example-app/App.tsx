/**
 * Example app for react-native-matrix-crypto.
 *
 * Exercises the shipped JSI Turbo Module end to end by running the shared
 * interop suites (see src/ProbeHarness.tsx) against the real native binding.
 * Deliberately generic: this app has no product-specific configuration.
 *
 * `storeDir` is the one thing this app cannot get from JavaScript.
 * `createCryptoMachine` needs a directory the process may write to, the
 * library deliberately chooses none (a crypto library that picks its own
 * on-disk location writes somewhere the product did not agree to), and
 * React Native has no built-in path API. So this app's own native code
 * supplies it as an initial property of the root component: `filesDir` on
 * Android (MainActivity.kt), the app container's Documents directory on
 * iOS (AppDelegate.swift). No dependency was added to get it, and nothing
 * was added to the library.
 *
 * It is typed optional and defaults to the empty string rather than being
 * assumed present: a host that supplies nothing must make the probe report
 * a failing step, not crash before it can report anything at all.
 *
 * @format
 */

import React from 'react';
import { SafeAreaView, ScrollView, StatusBar, StyleSheet, Text, useColorScheme } from 'react-native';
import { GuidedFlow } from './src/GuidedFlow';
import { LevelTwoHarness } from './src/LevelTwoHarness';
import { ProbeHarness } from './src/ProbeHarness';
import { fetchLevelTwoPlan, type LevelTwoPlan } from './src/levelTwoTransport';

// Both GuidedFlow and ProbeHarness are rendered unconditionally, in the same
// tree, every time this component mounts -- neither lives behind a tab or
// any other interaction. ProbeHarness's mount effect is what CI scrapes
// (PROBE_CHECK / PROBE_SUMMARY); if it were only reachable by tapping into a
// secondary view, an app that never runs it would still look like a pass.
//
// THE ONE EXCEPTION, AND WHY IT IS NOT A TAB. The level 2 facade run needs a
// real homeserver and a real third-party client, so a conductor has to be
// running on the host before it can mean anything. It also creates the
// process's one crypto machine, with the identity that homeserver issued --
// and the library holds one machine per process, so it and the two screens
// below cannot both have one. The app therefore asks, once, whether a
// conductor is there:
//
//   * nothing answers (a plain launch, and every CI run of the probe): the
//     app is exactly what it was, and prints exactly what it printed. The
//     connection is refused in milliseconds, not waited out.
//   * a conductor answers: this launch is a level 2 run and nothing else,
//     and it prints LEVEL2_CHECK / LEVEL2_SUMMARY instead.
//
// The condition is a deliberate act by whoever started the conductor, never
// a tap, and a run that produces no summary at all is a failed run -- the
// host-side runner asserts it found one, the same way
// scripts/run-probe-on-emulator.sh does for PROBE_SUMMARY.
function App({ storeDir = '' }: { storeDir?: string }) {
  const isDarkMode = useColorScheme() === 'dark';
  // `undefined` while the question is still open; `null` once it is settled
  // as "no conductor". Rendering nothing in between is deliberate: starting
  // the probe and then discovering a plan would leave two machines racing
  // for a process that only has room for one.
  const [plan, setPlan] = React.useState<LevelTwoPlan | null | undefined>(undefined);

  React.useEffect(() => {
    let cancelled = false;
    void fetchLevelTwoPlan().then(found => {
      if (!cancelled) setPlan(found);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />
      <ScrollView contentInsetAdjustmentBehavior="automatic" style={styles.container}>
        <Text style={styles.heading}>react-native-matrix-crypto</Text>
        {plan === undefined ? null : plan === null ? (
          <>
            <GuidedFlow storeDir={storeDir} />
            <Text style={styles.heading}>Diagnostics</Text>
            <Text style={styles.subheading}>
              Two interop suites, run automatically on every app start and logged for CI: the probe suite the flow
              above exercises by hand, and a real encryption round trip -- create a machine, publish its keys, share a
              scope key, encrypt, decrypt -- driven entirely through the public API.
            </Text>
            <ProbeHarness storeDir={storeDir} />
          </>
        ) : (
          <>
            <Text style={styles.heading}>Level 2 interoperability</Text>
            <Text style={styles.subheading}>
              A conductor answered on the host, so this launch is a level 2 run: a real homeserver, a matrix-nio
              counterparty, and both directions of the exchange driven entirely through the published TypeScript
              surface.
            </Text>
            <LevelTwoHarness plan={plan} storeDir={storeDir} />
          </>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  heading: {
    fontSize: 18,
    fontWeight: '600',
    margin: 16,
  },
  subheading: {
    fontSize: 13,
    marginHorizontal: 16,
    marginBottom: 8,
    opacity: 0.7,
  },
});

export default App;
