import { defineConfig } from 'vitest/config'

/**
 * Vitest, because `packages/react-native-matrix-crypto` already runs vitest
 * and a contributor should meet one convention in this repository, not two.
 * `yarn --cwd packages/example-app test` is the sibling of
 * `yarn --cwd packages/react-native-matrix-crypto test`, and both are
 * `vitest run`.
 *
 * THE ONE THING THIS FILE DOES, and why the library needs no config file
 * while this app does.
 *
 * `react-native-matrix-crypto`'s entry point imports `./index.tsx` purely
 * for its side effect: it is the bootstrap `uniffi-bindgen-react-native`
 * generates, and it calls `installRustCrate()` and then a checksum handshake
 * against the JSI host object. In Node there is no host object and no
 * `react-native` runtime to ask for one, so importing the published entry
 * point throws before a single test can run. The library's own tests never
 * meet this because they import `./facade` and friends directly, from
 * inside the package.
 *
 * This app cannot do that. It imports `react-native-matrix-crypto` and
 * nothing else, which is the property that makes it worth reading, so its
 * tests import the same specifier. The plugin below replaces exactly one
 * module in the graph, the bootstrap, and leaves every other line of the
 * library real: the facade, the error normalisation, the generated bindings
 * and the interop suite are all the shipped ones.
 *
 * IT CANNOT FAIL QUIETLY. If the library renames or moves that file, the
 * match below stops firing, the real bootstrap loads, and every test in the
 * package fails at import. There is no path where this stub silently stops
 * applying and the suite still reports success.
 */
const BOOTSTRAP_STUB = '\0react-native-matrix-crypto/ubrn-bootstrap-stub'
const BOOTSTRAP_IMPORTER = 'react-native-matrix-crypto/src/index.ts'

export default defineConfig({
  plugins: [
    {
      name: 'stub-ubrn-bootstrap',
      enforce: 'pre',
      resolveId(source: string, importer: string | undefined) {
        const from = (importer ?? '').replace(/\\/g, '/')
        return source === './index.tsx' && from.endsWith(BOOTSTRAP_IMPORTER)
          ? BOOTSTRAP_STUB
          : null
      },
      load(id: string) {
        return id === BOOTSTRAP_STUB ? 'export {}' : null
      },
    },
  ],
  test: {
    include: ['src/**/*.test.ts'],
  },
})
