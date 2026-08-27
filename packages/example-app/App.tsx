/**
 * Example app for react-native-matrix-crypto.
 *
 * Exercises the shipped JSI Turbo Module end to end by running the shared
 * interop suite (see src/ProbeHarness.tsx) against the real native binding.
 * Deliberately generic: this app has no product-specific configuration.
 *
 * @format
 */

import React from 'react';
import { SafeAreaView, ScrollView, StatusBar, StyleSheet, Text, useColorScheme } from 'react-native';
import { ProbeHarness } from './src/ProbeHarness';

function App() {
  const isDarkMode = useColorScheme() === 'dark';

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />
      <ScrollView contentInsetAdjustmentBehavior="automatic" style={styles.container}>
        <Text style={styles.heading}>react-native-matrix-crypto probe</Text>
        <ProbeHarness />
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
});

export default App;
