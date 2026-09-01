# Copilot review instructions — react-native-matrix-crypto

## What this repository is

Monorepo for a React Native cryptographic module. The Rust core is the single
source of truth for all cryptography; everything else is binding or test code.

- `rust/matrix-crypto-core/` — cryptographic core (Rust). Must stay pure: no
  I/O, no platform APIs, no logging (enforced by `gate:logger` and
  `gate:boundary` scripts).
- `packages/react-native-matrix-crypto/src/` — public TypeScript facade
  (`facade.ts`, `errors.ts`, `types.ts`, `index.ts`). This is the public API
  surface (enforced by `gate:surface`).
- `packages/react-native-matrix-crypto/cpp/`, `android/cpp-adapter.cpp`,
  `ios/MatrixCrypto.mm` — native JSI/JNI bridges (C++ / Objective-C++).
- `packages/react-native-matrix-crypto/interop/` — interop test suites.
- `packages/example-app/` — demo app only. Nothing outside it may import it.

## Generated code — never edit by hand

`src/generated/` and `cpp/generated/` are codegen outputs (see
`scripts/codegen.sh`). If a diff touches them, check consistency, but suggest
regenerating rather than hand-editing. The CI gates `gate:drift` and
`gate:stubs` enforce this.

## Review priorities (in order)

1. **Cryptographic safety**
   - No key material, seeds, or secrets in code, comments, logs, or error
     messages.
   - Secret buffers must be zeroized after use; no copies left in long-lived
     structures.
   - Comparisons of secrets/MACs/tags must be constant-time.
   - No new dependencies without a strong justification; crypto dependencies
     are especially sensitive.

2. **FFI / bridge boundary**
   - Rust panics and exceptions must never cross the FFI boundary into
     JS/Java — check error mapping into the typed error hierarchy in
     `src/errors.ts`.
   - Check memory ownership at the JSI/JNI edges (allocated vs. borrowed,
     release on all paths, no leaks on error paths).
   - Verify type conversions at the boundary match `src/types.ts`.

3. **Repository gates and conventions**
   - The repo is guarded by gate scripts (`gate:*` in root `package.json`):
     boundary, drift, logger, facade agility, readme sync, measure guards,
     artifact provenance. Flag changes that would break them rather than
     assuming CI will catch it.
   - Rust core must remain free of logging and platform dependencies.
   - Example-app code must not be referenced from the library packages.

4. **Tests**
   - Behavior changes need tests next to the code (`*.test.ts`,
     `*.type-test.ts` for type-level assertions; Rust tests in-module).
   - Interop changes should extend the suites in `interop/`.

## Style

Match the existing code: strict TypeScript, explicit error types over
exceptions in the facade, small focused modules. Comments and docs in
English, JSDoc on the public facade API.
