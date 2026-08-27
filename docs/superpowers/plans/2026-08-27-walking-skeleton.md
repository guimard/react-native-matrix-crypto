# react-native-matrix-crypto Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove a call travels Rust to UniFFI to JSI to TypeScript on real iOS and Android hardware, then prove it still does with `matrix-sdk-crypto` linked.

**Architecture:** Two Rust crates (`matrix-crypto-core` holds all logic and knows no UniFFI; `matrix-crypto-ffi` holds only `#[uniffi::export]` type translation), code-generated into a JSI Turbo Module by `uniffi-bindgen-react-native`, wrapped by a thin hand-written TypeScript shim that adds branded types and error normalization. Sequencing is chain-first (M1a, no crypto dependency) then dependency (M1b), so a build failure is always attributable to one of the two risks rather than both.

**Tech Stack:** Rust 1.97.1, uniffi 0.31, uniffi-bindgen-react-native 0.31.0-5, React Native 0.87.1 (New Architecture), TypeScript, Vitest, yarn 1.22 workspaces, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-27-react-native-matrix-crypto-design.md`

## Global Constraints

Every task's requirements implicitly include this section.

- **License:** Apache-2.0. Every `Cargo.toml` and `package.json` sets it.
- **npm package name:** `react-native-matrix-crypto` (unscoped). Never `@messagr/bridge-native`.
- **Rust crate names:** `matrix-crypto-core`, `matrix-crypto-ffi`. Never `messagr-bridge-*`.
- **Pins, exact:** `uniffi-bindgen-react-native@0.31.0-5`; `uniffi = "0.31"` (must exclude 0.32.0, which exists and breaks ubrn); `matrix-sdk-crypto = "0.18.0"` (M1b only); Rust `1.97.1`; React Native `0.87.1`; Node `22.22.3`.
- **The bridge has no logger.** No `println!`, `eprintln!`, `dbg!`, `log::`, `tracing::`, or `console.*` anywhere in `rust/` or `packages/react-native-matrix-crypto/src/`. Enforced by Task 10. The example app is exempt: it is not the bridge.
- **`matrix-crypto-core` must never list `uniffi` as a direct dependency.** Enforced by Task 3.
- **No Megolm-specific or Olm-specific identifier may appear in the public `.d.ts`.** Enforced by Task 9.
- **`uniffi-bindgen-react-native` is a `devDependency` only.** It compiles its own binary from Rust source on first run; if it ever reached `dependencies`, consumers would need a Rust toolchain and Task 13's `cold-consume` gate would fail.
- **Generated code is committed and never hand-edited.** Enforced by Task 5.
- **Every core-to-FFI type conversion destructures its source.** Write
  `let Core::T { a, b } = src;` then rebuild, never `Self { a: src.a, b: src.b }`.
  Field-access construction is not exhaustiveness-checked, so a field added to a core
  type later would be silently dropped from the FFI-exported record instead of failing
  the build. Enum conversions use a real `match` with no wildcard arm, for the same reason.
- **A manifest change and its lockfile update go in the SAME commit.** Changing
  `package.json` or a `Cargo.toml` in one commit and updating `yarn.lock` or `Cargo.lock`
  in a later one leaves every commit in between unbuildable under
  `yarn install --frozen-lockfile` or an `--immutable` CI install, and makes `git bisect`
  across the range misbehave. This is the one case where two files with different
  "subjects" belong together: the lockfile is not a separate concern, it is the
  manifest change's consequence.
- **Commits follow Conventional Commits**, subject in imperative mood with an uppercase first letter, one subject per commit.

## Deviations from the spec, decided during planning

These were discovered by inspecting ubrn 0.31.0-5 directly. Spec §3 and §5.1 are amended accordingly.

1. Spec §3 shows a single `generated/` directory. ubrn's real defaults are `src/generated` for TypeScript and `cpp/generated` for C++. The plan uses ubrn's defaults rather than fighting the tool.
2. Spec §4bis.2 of the source document names `ubrn generate all`. **That command does not exist.** The real surface is `ubrn generate jsi turbo-module` and `ubrn generate jsi bindings`.
3. Spec §5.1 states the FFI crate re-exports under `#[uniffi::export(async_runtime = "tokio")]`. For a plain `async fn` with no runtime-bound I/O, plain `#[uniffi::export]` is sufficient; UniFFI maps the future to a Promise itself. Whether `async_runtime = "tokio"` is required is an M1b question, resolved in Task 14.

## File Structure

| File | Responsibility |
|---|---|
| `LICENSE`, `.nvmrc`, `.gitignore` | Repository hygiene |
| `package.json` (root) | yarn workspaces root, private, scripts that fan out to gates |
| `rust-toolchain.toml` | Pins 1.97.1 and the seven targets |
| `ubrn.config.yaml` | Single source of truth for codegen |
| `rust/Cargo.toml` | Cargo workspace: core + ffi |
| `rust/matrix-crypto-core/src/lib.rs` | Re-exports the crate's public surface only |
| `rust/matrix-crypto-core/src/probe.rs` | `probe()` and `ProbeReport` |
| `rust/matrix-crypto-core/src/error.rs` | `ProbeError` |
| `rust/matrix-crypto-core/src/observer.rs` | `ProbeObserver` trait, `ProbeSignal` |
| `rust/matrix-crypto-ffi/src/lib.rs` | `#[uniffi::export]` surface and the observer adapter. Translation only. |
| `packages/react-native-matrix-crypto/src/types.ts` | `CryptoScopeId`, `CryptoAlgorithm`, `EventEnvelope`, `TrustState` |
| `packages/react-native-matrix-crypto/src/errors.ts` | `CryptoError`, `CryptoErrorKind`, `toCryptoError` |
| `packages/react-native-matrix-crypto/src/signals.ts` | `CryptoSignal`, `onCryptoSignal` |
| `packages/react-native-matrix-crypto/src/probe.ts` | Shim over the generated probe |
| `packages/react-native-matrix-crypto/src/facade.ts` | Spec §5's surface, `NotImplemented` at runtime |
| `packages/react-native-matrix-crypto/src/index.ts` | The public API. The only file consumers import. |
| `packages/react-native-matrix-crypto/src/generated/` | ubrn TypeScript output. Committed, never edited. |
| `packages/react-native-matrix-crypto/cpp/generated/` | ubrn C++ output. Committed, never edited. |
| `scripts/assert-core-boundary.sh` | Task 3 gate |
| `scripts/assert-no-drift.sh` | Task 5 gate |
| `scripts/assert-no-logger.sh` | Task 10 gate |
| `scripts/assert-facade-agility.sh` | Task 9 gate |
| `scripts/measure-artifacts.sh` | Records xcframework and aar sizes |
| `packages/example-app/` | Neutral RN 0.87.1 demo that runs the probe assertions on device |
| `.github/workflows/ci.yml` | All gates |

---

### Task 1: Repository scaffolding

**Files:**
- Create: `LICENSE`, `.nvmrc`, `.gitignore`, `package.json`, `rust-toolchain.toml`, `rust/Cargo.toml`
- Create: `rust/matrix-crypto-core/Cargo.toml`, `rust/matrix-crypto-core/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: a yarn workspace root and a Cargo workspace containing the crate `matrix-crypto-core` version `0.1.0`.

- [ ] **Step 1: Write the failing test**

Create `scripts/assert-workspaces.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Cargo workspace resolves and contains the core crate.
cargo metadata --format-version 1 --no-deps --manifest-path rust/Cargo.toml \
  | grep -q '"name":"matrix-crypto-core"' \
  || { echo "FAIL: matrix-crypto-core not in cargo workspace"; exit 1; }

# yarn workspace root is declared and private.
node -e '
  const p = require("./package.json");
  if (p.private !== true) { console.error("FAIL: root package.json must be private"); process.exit(1); }
  if (!Array.isArray(p.workspaces)) { console.error("FAIL: root package.json must declare workspaces"); process.exit(1); }
'

echo "PASS: workspaces"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `chmod +x scripts/assert-workspaces.sh && ./scripts/assert-workspaces.sh`
Expected: FAIL, because `rust/Cargo.toml` and `package.json` do not exist yet.

- [ ] **Step 3: Create the root files**

`.nvmrc`:
```
22.22.3
```

`.gitignore`:
```
node_modules/
target/
build/
Pods/
*.xcframework
*.aar
.DS_Store
artifact-sizes.json
```

`package.json`:
```json
{
  "name": "react-native-matrix-crypto-workspace",
  "version": "0.1.0",
  "private": true,
  "license": "Apache-2.0",
  "workspaces": ["packages/*"],
  "engines": { "node": ">=22.22.3" },
  "scripts": {
    "gate:workspaces": "./scripts/assert-workspaces.sh",
    "gate:boundary": "./scripts/assert-core-boundary.sh",
    "gate:drift": "./scripts/assert-no-drift.sh",
    "gate:logger": "./scripts/assert-no-logger.sh",
    "gate:agility": "./scripts/assert-facade-agility.sh"
  }
}
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "1.97.1"
components = ["rustfmt", "clippy"]
targets = [
  "aarch64-apple-ios",
  "aarch64-apple-ios-sim",
  "x86_64-apple-ios",
  "aarch64-linux-android",
  "armv7-linux-androideabi",
  "x86_64-linux-android",
  "aarch64-apple-darwin",
]
```

`rust/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["matrix-crypto-core"]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.93"
license = "Apache-2.0"
repository = "https://github.com/linagora/react-native-matrix-crypto"
```

`rust/matrix-crypto-core/Cargo.toml`:
```toml
[package]
name = "matrix-crypto-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
thiserror = "2"

[dev-dependencies]
tokio = { version = "1", features = ["rt", "macros"] }
```

`rust/matrix-crypto-core/src/lib.rs`:
```rust
//! Core logic for the Matrix crypto bridge.
//!
//! This crate knows nothing about UniFFI, JSI, or React Native. It must never
//! take a direct dependency on `uniffi`; `scripts/assert-core-boundary.sh`
//! enforces that in CI.
```

Fetch the Apache-2.0 text into `LICENSE`:
```bash
curl -sSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./scripts/assert-workspaces.sh`
Expected: `PASS: workspaces`

- [ ] **Step 5: Commit**

```bash
git add LICENSE .nvmrc .gitignore package.json rust-toolchain.toml rust/ scripts/
git commit -m "chore: Add workspace scaffolding for the crypto bridge"
```

---

### Task 2: The probe in `matrix-crypto-core`

The probe deliberately exercises the four things that break across an FFI boundary: records, byte arrays, async, and typed errors. An integer probe would prove nothing, because integers never break.

**Files:**
- Create: `rust/matrix-crypto-core/src/error.rs`, `rust/matrix-crypto-core/src/probe.rs`
- Modify: `rust/matrix-crypto-core/src/lib.rs`

**Interfaces:**
- Consumes: the crate from Task 1.
- Produces: `matrix_crypto_core::probe(input: String, payload: Vec<u8>) -> Result<ProbeReport, ProbeError>`, an `async fn`; `ProbeReport { echoed: String, payload: Vec<u8>, core_version: String }`; `ProbeError::Rejected { reason: String }`.

- [ ] **Step 1: Write the failing test**

Append to `rust/matrix-crypto-core/src/probe.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echoes_input_and_reports_version() {
        let report = probe("hello".to_string(), vec![1, 2, 3]).await.unwrap();
        assert_eq!(report.echoed, "hello");
        assert_eq!(report.core_version, env!("CARGO_PKG_VERSION"));
    }

    // Reversal proves the bytes actually crossed and were read, rather than
    // being passed through by reference or silently dropped.
    #[tokio::test]
    async fn reverses_payload_bytes() {
        let report = probe("x".to_string(), vec![1, 2, 3]).await.unwrap();
        assert_eq!(report.payload, vec![3, 2, 1]);
    }

    #[tokio::test]
    async fn preserves_non_utf8_bytes() {
        let report = probe("x".to_string(), vec![0x00, 0xff, 0xfe]).await.unwrap();
        assert_eq!(report.payload, vec![0xfe, 0xff, 0x00]);
    }

    #[tokio::test]
    async fn rejects_empty_input() {
        let err = probe(String::new(), vec![]).await.unwrap_err();
        assert_eq!(err, ProbeError::Rejected { reason: "input must not be empty".to_string() });
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml`
Expected: FAIL to compile, `cannot find function 'probe'`.

- [ ] **Step 3: Write the minimal implementation**

`rust/matrix-crypto-core/src/error.rs`:
```rust
/// Errors the core can return.
///
/// Carries no payload content and no device identifier. See spec section 7.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    #[error("probe rejected: {reason}")]
    Rejected { reason: String },
}
```

`rust/matrix-crypto-core/src/probe.rs` (above the test module):
```rust
use crate::error::ProbeError;

/// Result of a successful probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub echoed: String,
    pub payload: Vec<u8>,
    pub core_version: String,
}

/// Round-trips a string and a byte array through the core.
///
/// Exists to prove the binding chain carries records, bytes, futures and
/// typed errors. It has no cryptographic meaning.
pub async fn probe(input: String, payload: Vec<u8>) -> Result<ProbeReport, ProbeError> {
    if input.is_empty() {
        return Err(ProbeError::Rejected {
            reason: "input must not be empty".to_string(),
        });
    }

    let mut reversed = payload;
    reversed.reverse();

    Ok(ProbeReport {
        echoed: input,
        payload: reversed,
        core_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
```

Replace `rust/matrix-crypto-core/src/lib.rs` body with:
```rust
//! Core logic for the Matrix crypto bridge.
//!
//! This crate knows nothing about UniFFI, JSI, or React Native. It must never
//! take a direct dependency on `uniffi`; `scripts/assert-core-boundary.sh`
//! enforces that in CI.

mod error;
mod probe;

pub use error::ProbeError;
pub use probe::{probe, ProbeReport};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add rust/matrix-crypto-core/src/
git commit -m "feat(core): Add probe exercising records, bytes, async and errors"
```

---

### Task 3: Guardrail for the core / FFI boundary

Spec §4bis.3 requires all logic to live in the core. This makes that a property of the repository rather than a promise in a document.

**Files:**
- Create: `scripts/assert-core-boundary.sh`

**Interfaces:**
- Consumes: the Cargo workspace from Task 1.
- Produces: `yarn gate:boundary`, exit 0 when clean.

- [ ] **Step 1: Write the guardrail**

`scripts/assert-core-boundary.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3: all logic lives in matrix-crypto-core, which must
# therefore never depend on uniffi directly. A transitive uniffi is fine;
# a direct one means FFI concerns have leaked into the core.
DIRECT_DEPS=$(cargo metadata --format-version 1 --no-deps \
  --manifest-path rust/Cargo.toml \
  | node -e '
      const m = JSON.parse(require("fs").readFileSync(0, "utf8"));
      const core = m.packages.find(p => p.name === "matrix-crypto-core");
      if (!core) { console.error("matrix-crypto-core not found"); process.exit(2); }
      console.log(core.dependencies.map(d => d.name).join("\n"));
    ')

if echo "$DIRECT_DEPS" | grep -qx 'uniffi'; then
  echo "FAIL: matrix-crypto-core has a direct dependency on uniffi."
  echo "      FFI concerns belong in matrix-crypto-ffi. See spec section 4bis.3."
  exit 1
fi

# The core must also be testable with no Node, no simulator, no Turbo Module.
cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml --quiet

echo "PASS: core boundary"
```

- [ ] **Step 2: Verify it passes on the clean tree**

Run: `chmod +x scripts/assert-core-boundary.sh && ./scripts/assert-core-boundary.sh`
Expected: `PASS: core boundary`

- [ ] **Step 3: Verify it actually catches a violation**

A guardrail nobody has seen fail is not a guardrail. Temporarily add a direct dependency:

```bash
cargo add uniffi@0.31 --manifest-path rust/matrix-crypto-core/Cargo.toml
./scripts/assert-core-boundary.sh || echo "guardrail correctly rejected the violation"
```
Expected: `FAIL: matrix-crypto-core has a direct dependency on uniffi.` followed by the confirmation line.

- [ ] **Step 4: Revert the violation and confirm green**

```bash
cargo remove uniffi --manifest-path rust/matrix-crypto-core/Cargo.toml
git diff --exit-code rust/matrix-crypto-core/Cargo.toml
./scripts/assert-core-boundary.sh
```
Expected: no diff, then `PASS: core boundary`.

- [ ] **Step 5: Commit**

```bash
git add scripts/assert-core-boundary.sh
git commit -m "test: Add guardrail rejecting uniffi in the core crate"
```

---

### Task 4: The `matrix-crypto-ffi` crate

**Files:**
- Create: `rust/matrix-crypto-ffi/Cargo.toml`, `rust/matrix-crypto-ffi/src/lib.rs`
- Modify: `rust/Cargo.toml`

**Interfaces:**
- Consumes: `matrix_crypto_core::{probe, ProbeReport, ProbeError}` from Task 2.
- Produces: a `cdylib`/`staticlib` named `matrix_crypto_ffi` exporting an async `probe(input: String, payload: Vec<u8>) -> Result<ProbeReport, ProbeError>` over UniFFI, with the UniFFI namespace `matrix_crypto`.

- [ ] **Step 1: Write the failing test**

Create `rust/matrix-crypto-ffi/tests/exports.rs`:

```rust
// The FFI crate must expose the core's probe unchanged. This test does not
// cross the FFI boundary; it only proves the re-export compiles and delegates.
#[tokio::test]
async fn ffi_probe_delegates_to_core() {
    let report = matrix_crypto_ffi::probe("hi".to_string(), vec![9, 8]).await.unwrap();
    assert_eq!(report.echoed, "hi");
    assert_eq!(report.payload, vec![8, 9]);
}

#[tokio::test]
async fn ffi_probe_propagates_typed_error() {
    let err = matrix_crypto_ffi::probe(String::new(), vec![]).await.unwrap_err();
    assert!(matches!(err, matrix_crypto_core::ProbeError::Rejected { .. }));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p matrix-crypto-ffi --manifest-path rust/Cargo.toml`
Expected: FAIL, `error: package ID specification 'matrix-crypto-ffi' did not match any packages`.

- [ ] **Step 3: Write the minimal implementation**

Add `"matrix-crypto-ffi"` to `members` in `rust/Cargo.toml`.

`rust/matrix-crypto-ffi/Cargo.toml`:
```toml
[package]
name = "matrix-crypto-ffi"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lib]
crate-type = ["cdylib", "staticlib", "lib"]
name = "matrix_crypto_ffi"

[dependencies]
matrix-crypto-core = { path = "../matrix-crypto-core" }
# Must stay within 0.31.x: uniffi 0.32.0 exists and breaks ubrn 0.31.0-5.
uniffi = { version = "0.31", features = ["cli"] }

[dev-dependencies]
tokio = { version = "1", features = ["rt", "macros"] }

[build-dependencies]
uniffi = { version = "0.31", features = ["build"] }
```

`rust/matrix-crypto-ffi/src/lib.rs`:
```rust
//! UniFFI surface for the Matrix crypto bridge.
//!
//! This crate contains type translation and nothing else. All logic lives in
//! `matrix-crypto-core`. If you are tempted to add a branch here, it belongs
//! in the core.

use matrix_crypto_core::{ProbeError, ProbeReport as CoreProbeReport};

uniffi::setup_scaffolding!("matrix_crypto");

/// Mirror of the core's report, carrying the UniFFI record derive.
#[derive(uniffi::Record)]
pub struct ProbeReport {
    pub echoed: String,
    pub payload: Vec<u8>,
    pub core_version: String,
}

impl From<CoreProbeReport> for ProbeReport {
    fn from(r: CoreProbeReport) -> Self {
        Self { echoed: r.echoed, payload: r.payload, core_version: r.core_version }
    }
}

/// Mirror of the core's error, carrying the UniFFI error derive.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum ProbeFfiError {
    #[error("probe rejected: {reason}")]
    Rejected { reason: String },
}

impl From<ProbeError> for ProbeFfiError {
    fn from(e: ProbeError) -> Self {
        match e {
            ProbeError::Rejected { reason } => Self::Rejected { reason },
        }
    }
}

/// A plain `async fn`. UniFFI maps this to a JavaScript Promise on its own;
/// no `async_runtime` attribute is needed until the core's futures require a
/// specific reactor. See the M1b task.
#[uniffi::export]
pub async fn probe(input: String, payload: Vec<u8>) -> Result<ProbeReport, ProbeFfiError> {
    matrix_crypto_core::probe(input, payload)
        .await
        .map(Into::into)
        .map_err(Into::into)
}
```

Add `thiserror = "2"` to the FFI crate's `[dependencies]`.

Note that `tests/exports.rs` from Step 1 references `matrix_crypto_core::ProbeError`; add `matrix-crypto-core` to `[dev-dependencies]` as well, or change the test to match on `ProbeFfiError`. Use the latter, since it keeps the test inside this crate's own surface:

```rust
#[tokio::test]
async fn ffi_probe_propagates_typed_error() {
    let err = matrix_crypto_ffi::probe(String::new(), vec![]).await.unwrap_err();
    assert!(matches!(err, matrix_crypto_ffi::ProbeFfiError::Rejected { .. }));
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p matrix-crypto-ffi --manifest-path rust/Cargo.toml`
Expected: PASS, 2 tests.

- [ ] **Step 5: Confirm the boundary guardrail is still green**

Run: `./scripts/assert-core-boundary.sh`
Expected: `PASS: core boundary`. The core gained no uniffi dependency; only the FFI crate did.

- [ ] **Step 6: Commit**

```bash
git add rust/Cargo.toml rust/matrix-crypto-ffi/
git commit -m "feat(ffi): Add UniFFI export surface for the probe"
```

---

### Task 5: Codegen and the drift guardrail

**Files:**
- Create: `ubrn.config.yaml`, `packages/react-native-matrix-crypto/package.json`, `scripts/assert-no-drift.sh`
- Create (generated, committed): `packages/react-native-matrix-crypto/src/generated/`, `packages/react-native-matrix-crypto/cpp/generated/`

**Interfaces:**
- Consumes: the FFI crate from Task 4.
- Produces: generated TypeScript exposing `probe(input: string, payload: Uint8Array): Promise<ProbeReport>`, importable from `./generated/matrix_crypto`.

- [ ] **Step 1: Create the package and the ubrn config**

`packages/react-native-matrix-crypto/package.json`:
```json
{
  "name": "react-native-matrix-crypto",
  "version": "0.1.0",
  "description": "A React Native bridge for Matrix cryptography",
  "license": "Apache-2.0",
  "repository": "https://github.com/linagora/react-native-matrix-crypto",
  "main": "src/index.ts",
  "files": ["src", "cpp", "interop", "android", "ios", "*.podspec", "LICENSE"],
  "devDependencies": {
    "uniffi-bindgen-react-native": "0.31.0-5",
    "typescript": "^5.6.0",
    "vitest": "^2.1.0"
  },
  "scripts": {
    "codegen": "ubrn generate jsi turbo-module --config ../../ubrn.config.yaml",
    "test": "vitest run",
    "typecheck": "tsc --noEmit"
  }
}
```

`ubrn.config.yaml` at the repository root:
```yaml
name: react-native-matrix-crypto
rust:
  directory: rust
  manifestPath: matrix-crypto-ffi/Cargo.toml
bindings:
  ts: packages/react-native-matrix-crypto/src/generated
  cpp: packages/react-native-matrix-crypto/cpp/generated
```

- [ ] **Step 2: Run codegen**

```bash
yarn install
cd packages/react-native-matrix-crypto && yarn codegen
```
Expected: ubrn compiles its own binary on first run (this takes several minutes and is normal), then writes `.ts` files under `src/generated/` and `.cpp`/`.h` files under `cpp/generated/`.

- [ ] **Step 3: Write the drift guardrail**

`scripts/assert-no-drift.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Spec section 4bis.3: any drift between the Rust surface and the committed
# generated code is a blocking defect. Regenerate and require an empty diff.
yarn --cwd packages/react-native-matrix-crypto codegen

if ! git diff --exit-code -- \
     packages/react-native-matrix-crypto/src/generated \
     packages/react-native-matrix-crypto/cpp/generated; then
  echo "FAIL: generated code is out of date. Run codegen and commit the result."
  echo "      Never hand-edit generated files."
  exit 1
fi

echo "PASS: no codegen drift"
```

- [ ] **Step 4: Verify the guardrail passes, then verify it catches drift**

```bash
chmod +x scripts/assert-no-drift.sh
git add -A && git commit -m "chore: Add generated bindings" --no-verify
./scripts/assert-no-drift.sh
```
Expected: `PASS: no codegen drift`.

Now prove it catches a real drift:
```bash
echo '// hand-edited' >> packages/react-native-matrix-crypto/src/generated/matrix_crypto.ts
./scripts/assert-no-drift.sh || echo "guardrail correctly rejected the drift"
git checkout -- packages/react-native-matrix-crypto/src/generated
```
Expected: FAIL message, then the confirmation line.

- [ ] **Step 5: Commit**

```bash
git add ubrn.config.yaml scripts/assert-no-drift.sh packages/
git commit -m "feat: Add ubrn codegen configuration and drift guardrail"
```

---

### Task 6: TypeScript types and brands

UniFFI cannot emit branded types, so the brand, the open algorithm union, and the envelope are hand-written. This is what spec §6 means by making agility structural rather than conventional.

**Files:**
- Create: `packages/react-native-matrix-crypto/src/types.ts`
- Create: `packages/react-native-matrix-crypto/src/types.type-test.ts`
- Create: `packages/react-native-matrix-crypto/tsconfig.json`

**Interfaces:**
- Consumes: nothing.
- Produces: `CryptoScopeId`, `asCryptoScopeId(raw: string): CryptoScopeId`, `CryptoAlgorithm`, `EventEnvelope`, `TrustState`.

- [ ] **Step 1: Write the failing type test**

`@ts-expect-error` is the assertion. If a bare string ever becomes assignable to `CryptoScopeId`, the directive becomes unused and `tsc` fails the build. That is the test.

`packages/react-native-matrix-crypto/src/types.type-test.ts`:
```ts
import { asCryptoScopeId } from './types'
import type { CryptoAlgorithm, CryptoScopeId, EventEnvelope } from './types'

// A bare string must NOT be assignable to CryptoScopeId.
// @ts-expect-error bare strings must go through asCryptoScopeId
const bad: CryptoScopeId = '!room:example.org'

// The branded constructor is the only way in.
const good: CryptoScopeId = asCryptoScopeId('!room:example.org')

// The algorithm union must stay open: an unknown algorithm is assignable,
// so adding MLS later is an additive change, not a breaking one.
const known: CryptoAlgorithm = 'megolm'
const future: CryptoAlgorithm = 'mls'
const fabricated: CryptoAlgorithm = 'x-fabricated-suite'

const envelope: EventEnvelope = {
  scope: good,
  algorithm: fabricated,
  eventType: 'm.room.message',
  ciphertext: new Uint8Array([1, 2, 3]),
  sender: '@a:server1',
}

void bad; void known; void future; void envelope
```

`packages/react-native-matrix-crypto/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUnusedLocals": false,
    "skipLibCheck": true,
    "declaration": true,
    "noEmit": true
  },
  "include": ["src"]
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `yarn --cwd packages/react-native-matrix-crypto typecheck`
Expected: FAIL, `Cannot find module './types'`.

- [ ] **Step 3: Write the minimal implementation**

`packages/react-native-matrix-crypto/src/types.ts`:
```ts
/**
 * Opaque identifier for a cryptographic scope.
 *
 * Today this wraps a Matrix room id. Tomorrow it may wrap an MLS group id.
 * Nothing in the public API says "room", so spec section 6's agility
 * requirement holds by construction rather than by convention.
 */
export type CryptoScopeId = string & { readonly __brand: unique symbol }

/** The only way to construct a CryptoScopeId. */
export function asCryptoScopeId(raw: string): CryptoScopeId {
  return raw as CryptoScopeId
}

/**
 * Deliberately open. Adding 'mls' is an additive change and therefore a minor
 * version bump, per spec section 4bis.4. Consumers must handle unknown values.
 */
export type CryptoAlgorithm = 'megolm' | 'olm' | (string & {})

/** Product-facing trust signal. Only 'verified' has cryptographic value. */
export type TrustState = 'unverified' | 'recognized' | 'verified'

/** Typed envelope for an encrypted or decrypted event. */
export interface EventEnvelope {
  scope: CryptoScopeId
  algorithm: CryptoAlgorithm
  eventType: string
  ciphertext: Uint8Array
  /** Fully qualified `@user:server`, verbatim. Spec section 10. */
  sender: string
}
```

- [ ] **Step 4: Run the typecheck to verify it passes**

Run: `yarn --cwd packages/react-native-matrix-crypto typecheck`
Expected: PASS with no errors. If it reports "Unused '@ts-expect-error' directive", the brand is broken and is not preventing bare-string assignment.

- [ ] **Step 5: Commit**

```bash
git add packages/react-native-matrix-crypto/src/types.ts \
        packages/react-native-matrix-crypto/src/types.type-test.ts \
        packages/react-native-matrix-crypto/tsconfig.json
git commit -m "feat(ts): Add branded scope id and open algorithm union"
```

---

### Task 7: Error normalization

**Files:**
- Create: `packages/react-native-matrix-crypto/src/errors.ts`, `packages/react-native-matrix-crypto/src/errors.test.ts`

**Interfaces:**
- Consumes: `CryptoScopeId` from Task 6.
- Produces: `CryptoErrorKind`, `CryptoError`, `isCryptoError(e: unknown): e is CryptoError`, `toCryptoError(raw: unknown): CryptoError`.

- [ ] **Step 1: Write the failing test**

`packages/react-native-matrix-crypto/src/errors.test.ts`:
```ts
import { describe, expect, it } from 'vitest'
import { isCryptoError, toCryptoError } from './errors'

describe('toCryptoError', () => {
  it('maps a generated Rejected error to a typed CryptoError', () => {
    const raw = { name: 'Rejected', reason: 'input must not be empty' }
    const err = toCryptoError(raw)
    expect(err.kind).toBe('rejected')
    expect(err.message).toContain('input must not be empty')
    expect(err.retriable).toBe(false)
  })

  it('maps an unknown error to a stable unknown kind rather than throwing', () => {
    const err = toCryptoError(new Error('something else'))
    expect(err.kind).toBe('unknown')
    expect(err.retriable).toBe(false)
  })

  // Names that collide with Object.prototype members. An object-literal lookup
  // would return an inherited function here instead of undefined, so `kind`
  // would stop being a string. These cases fail loudly if anyone refactors
  // KIND_BY_NAME back to an object literal.
  it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty'])(
    'maps the prototype-colliding name %s to unknown',
    (name) => {
      const err = toCryptoError({ name })
      expect(err.kind).toBe('unknown')
      expect(typeof err.kind).toBe('string')
    },
  )

  it('carries the sender verbatim when present, per spec section 10', () => {
    const err = toCryptoError({ name: 'MissingKey', sender: '@b:server2' })
    expect(err.kind).toBe('missing_key')
    expect(err.sender).toBe('@b:server2')
  })

  it('never places payload content in the message, per spec section 7', () => {
    const err = toCryptoError({ name: 'Undecryptable', ciphertext: 'SECRET' })
    expect(err.message).not.toContain('SECRET')
  })

  it('recognises its own errors', () => {
    expect(isCryptoError(toCryptoError(new Error('x')))).toBe(true)
    expect(isCryptoError(new Error('x'))).toBe(false)
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `yarn --cwd packages/react-native-matrix-crypto test`
Expected: FAIL, `Failed to resolve import "./errors"`.

- [ ] **Step 3: Write the minimal implementation**

`packages/react-native-matrix-crypto/src/errors.ts`:
```ts
import type { CryptoScopeId } from './types'

/**
 * Deliberately open, per spec section 4bis.4: a new variant is a minor bump,
 * so every consumer must have a default branch.
 */
export type CryptoErrorKind =
  | 'missing_key'
  | 'unshared_session'
  | 'unknown_device'
  | 'revoked_device'
  | 'undecryptable'
  | 'store_corrupt'
  | 'rejected'
  | 'not_implemented'
  | 'unknown'
  | (string & {})

export interface CryptoError extends Error {
  kind: CryptoErrorKind
  scope?: CryptoScopeId
  /** Fully qualified `@user:server`, verbatim. Spec section 10. */
  sender?: string
  /** The bridge reports transience. The product layer decides what to do. */
  retriable: boolean
}

const BRAND = Symbol.for('react-native-matrix-crypto.CryptoError')

// A Map, not an object literal. An object literal's prototype is
// Object.prototype, so `KIND_BY_NAME['constructor']` would resolve through the
// prototype chain and return a function rather than undefined, defeating the
// `?? 'unknown'` fallback and putting a non-string into `kind`. A Map has no
// prototype-chain lookup, which removes the class of bug rather than guarding
// one instance of it. It also matches RETRIABLE, which is already a Set.
const KIND_BY_NAME = new Map<string, CryptoErrorKind>([
  ['Rejected', 'rejected'],
  ['NotImplemented', 'not_implemented'],
  ['MissingKey', 'missing_key'],
  ['UnsharedSession', 'unshared_session'],
  ['UnknownDevice', 'unknown_device'],
  ['RevokedDevice', 'revoked_device'],
  ['Undecryptable', 'undecryptable'],
  ['StoreCorrupt', 'store_corrupt'],
])

const RETRIABLE: ReadonlySet<CryptoErrorKind> = new Set(['missing_key', 'unshared_session'])

export function isCryptoError(e: unknown): e is CryptoError {
  return e instanceof Error && BRAND in e
}

/**
 * Normalizes anything thrown by the generated layer into a CryptoError.
 *
 * Only `reason` is ever copied into the message. Payload content and
 * ciphertext are never read, so they cannot reach a crash report.
 */
export function toCryptoError(raw: unknown): CryptoError {
  const source = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  const name = typeof source.name === 'string' ? source.name : ''
  const kind = KIND_BY_NAME.get(name) ?? 'unknown'
  const reason = typeof source.reason === 'string' ? source.reason : undefined

  const err = new Error(reason ?? `crypto error: ${kind}`) as CryptoError
  err.name = 'CryptoError'
  err.kind = kind
  err.retriable = RETRIABLE.has(kind)
  if (typeof source.sender === 'string') err.sender = source.sender
  if (typeof source.scope === 'string') err.scope = source.scope as CryptoScopeId
  Object.defineProperty(err, BRAND, { value: true, enumerable: false })
  return err
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `yarn --cwd packages/react-native-matrix-crypto test`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add packages/react-native-matrix-crypto/src/errors.ts \
        packages/react-native-matrix-crypto/src/errors.test.ts
git commit -m "feat(ts): Add error normalization that never carries payload content"
```

---

### Task 8: The signal channel, end to end

Spec §7.3 requires a second channel for state changes that belong to no call. It rides a UniFFI callback interface, which has its own threading rules across JSI. Exercising it in M1a is deliberate: callback plumbing discovered broken in M3 is expensive.

The core defines a plain trait. The FFI crate defines the UniFFI callback trait and an adapter that delegates. That adapter is exactly what "type translation only" means.

**Files:**
- Create: `rust/matrix-crypto-core/src/observer.rs`
- Modify: `rust/matrix-crypto-core/src/lib.rs`, `rust/matrix-crypto-ffi/src/lib.rs`
- Create: `packages/react-native-matrix-crypto/src/signals.ts`

**Interfaces:**
- Consumes: `probe` from Task 2, the FFI crate from Task 4.
- Produces: `matrix_crypto_core::{ProbeObserver, ProbeSignal, probe_with_observer}`; the exported `probe_with_observer(input, payload, observer)`; TypeScript `CryptoSignal` and `onCryptoSignal`.

- [ ] **Step 1: Write the failing test**

Append to `rust/matrix-crypto-core/src/observer.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<ProbeSignal>>,
    }

    impl ProbeObserver for Recorder {
        fn on_signal(&self, signal: ProbeSignal) {
            self.seen.lock().unwrap().push(signal);
        }
    }

    #[tokio::test]
    async fn emits_one_signal_before_returning() {
        let recorder = Arc::new(Recorder::default());
        let report = probe_with_observer("hi".to_string(), vec![1, 2], recorder.clone())
            .await
            .unwrap();

        assert_eq!(report.echoed, "hi");
        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].kind, "probe_started");
        assert_eq!(seen[0].detail, "hi");
    }

    #[tokio::test]
    async fn emits_no_signal_when_input_is_rejected() {
        let recorder = Arc::new(Recorder::default());
        let err = probe_with_observer(String::new(), vec![], recorder.clone())
            .await
            .unwrap_err();

        assert_eq!(err, ProbeError::Rejected { reason: "input must not be empty".to_string() });
        assert!(recorder.seen.lock().unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml`
Expected: FAIL to compile, `cannot find function 'probe_with_observer'`.

- [ ] **Step 3: Write the minimal implementation**

`rust/matrix-crypto-core/src/observer.rs` (above the test module):
```rust
use std::sync::Arc;

use crate::error::ProbeError;
use crate::probe::{probe, ProbeReport};

/// A state change that belongs to no call in flight. Spec sections 7 and 11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSignal {
    pub kind: String,
    pub detail: String,
}

/// Implemented by the FFI layer's adapter, and through it by JavaScript.
pub trait ProbeObserver: Send + Sync {
    fn on_signal(&self, signal: ProbeSignal);
}

/// Runs the probe, emitting one signal on the way through.
pub async fn probe_with_observer(
    input: String,
    payload: Vec<u8>,
    observer: Arc<dyn ProbeObserver>,
) -> Result<ProbeReport, ProbeError> {
    if input.is_empty() {
        return Err(ProbeError::Rejected {
            reason: "input must not be empty".to_string(),
        });
    }

    observer.on_signal(ProbeSignal {
        kind: "probe_started".to_string(),
        detail: input.clone(),
    });

    probe(input, payload).await
}
```

Add to `rust/matrix-crypto-core/src/lib.rs`:
```rust
mod observer;
pub use observer::{probe_with_observer, ProbeObserver, ProbeSignal};
```

Add to `rust/matrix-crypto-ffi/src/lib.rs`:
```rust
use std::sync::Arc;

/// Mirror of the core's signal, carrying the UniFFI record derive.
#[derive(uniffi::Record)]
pub struct ProbeSignal {
    pub kind: String,
    pub detail: String,
}

/// `with_foreign` makes this implementable from JavaScript.
#[uniffi::export(with_foreign)]
pub trait ProbeObserver: Send + Sync {
    fn on_signal(&self, signal: ProbeSignal);
}

/// Translation only: adapts the foreign observer to the core's trait.
struct ObserverAdapter(Arc<dyn ProbeObserver>);

impl matrix_crypto_core::ProbeObserver for ObserverAdapter {
    fn on_signal(&self, signal: matrix_crypto_core::ProbeSignal) {
        // Destructured, not field-accessed: a new core field must fail to
        // compile here rather than be silently dropped. See Global Constraints.
        let matrix_crypto_core::ProbeSignal { kind, detail } = signal;
        self.0.on_signal(ProbeSignal { kind, detail });
    }
}

#[uniffi::export]
pub async fn probe_with_observer(
    input: String,
    payload: Vec<u8>,
    observer: Arc<dyn ProbeObserver>,
) -> Result<ProbeReport, ProbeFfiError> {
    let adapter = Arc::new(ObserverAdapter(observer));
    matrix_crypto_core::probe_with_observer(input, payload, adapter)
        .await
        .map(Into::into)
        .map_err(Into::into)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --manifest-path rust/Cargo.toml`
Expected: PASS, all core and ffi tests.

- [ ] **Step 5: Regenerate bindings and confirm the drift gate**

Run: `./scripts/assert-no-drift.sh`
Expected: the generated files change (new callback interface), so the first run FAILS. Inspect the diff, confirm it contains `ProbeObserver`, then commit the regenerated output and re-run until it reports `PASS: no codegen drift`.

- [ ] **Step 6: Add the TypeScript signal surface**

`packages/react-native-matrix-crypto/src/signals.ts`:
```ts
import type { CryptoScopeId, TrustState } from './types'

/** Typed, silent by default. Takes no product decision. Spec sections 7, 11. */
export type CryptoSignal =
  | { kind: 'trust_changed'; user: string; state: TrustState }
  | { kind: 'unexpected_device'; scope: CryptoScopeId; user: string }
  | { kind: 'key_missing'; scope: CryptoScopeId }
  | { kind: 'probe_started'; detail: string }

export type Unsubscribe = () => void

const listeners = new Set<(s: CryptoSignal) => void>()

export function onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe {
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}

/** Internal. Called by the shim when the native observer fires. */
export function emitCryptoSignal(signal: CryptoSignal): void {
  // Snapshot before dispatch: a listener that subscribes while we are
  // iterating must not receive the signal that triggered its own
  // registration. Unsubscribing mid-dispatch is safe either way.
  for (const listener of [...listeners]) {
    try {
      listener(signal)
    } catch {
      // Isolate. One throwing listener must never starve the others: this
      // channel carries trust_changed, unexpected_device and key_missing, and
      // a buggy UI listener must not be able to suppress them. Deliberately
      // silent, because the bridge has no logger (see Global Constraints) --
      // do not reach for console.error here.
    }
  }
}
```

- [ ] **Step 7: Commit**

```bash
git add rust/ packages/react-native-matrix-crypto/src/ 
git commit -m "feat: Add signal channel from core through UniFFI callback to TypeScript"
```

---

### Task 9: The public facade and the agility guardrail

**Files:**
- Create: `packages/react-native-matrix-crypto/src/probe.ts`, `packages/react-native-matrix-crypto/src/facade.ts`, `packages/react-native-matrix-crypto/src/index.ts`
- Create: `packages/react-native-matrix-crypto/src/facade.test.ts`, `scripts/assert-facade-agility.sh`

**Interfaces:**
- Consumes: everything from Tasks 5 through 8.
- Produces: the public API. `runProbe(input, payload)`, `onCryptoSignal`, and spec §5's surface throwing `CryptoError` with `kind: 'not_implemented'`.

- [ ] **Step 1: Write the failing test**

`packages/react-native-matrix-crypto/src/facade.test.ts`:
```ts
import { describe, expect, it } from 'vitest'
import { asCryptoScopeId } from './types'
import { isCryptoError } from './errors'
import { encryptEvent, decryptEvent, exportSecrets } from './facade'

const scope = asCryptoScopeId('!scope:example.org')

describe('facade before implementation', () => {
  it('rejects with a typed not_implemented error rather than undefined', async () => {
    await expect(encryptEvent(scope, 'm.room.message', { body: 'hi' }))
      .rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'not_implemented')
  })

  it('rejects decryptEvent the same way', async () => {
    await expect(decryptEvent({})).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'not_implemented',
    )
  })

  it('rejects exportSecrets the same way', async () => {
    await expect(exportSecrets('passphrase')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'not_implemented',
    )
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `yarn --cwd packages/react-native-matrix-crypto test`
Expected: FAIL, `Failed to resolve import "./facade"`.

- [ ] **Step 3: Write the minimal implementation**

`packages/react-native-matrix-crypto/src/facade.ts`:
```ts
import type { CryptoAlgorithm, CryptoScopeId, EventEnvelope, TrustState } from './types'
import { toCryptoError } from './errors'

function notImplemented(name: string): Promise<never> {
  return Promise.reject(toCryptoError({ name: 'NotImplemented', reason: `${name} is not implemented yet` }))
}

// Spec section 5's surface, re-typed onto the branded scope and the open
// algorithm tag. Types are real so consumers can compile today; runtime
// arrives in M2.

export interface CryptoMachineConfig {
  userId: string
  deviceId: string
  storePath: string
}

export interface DeviceStatus {
  deviceId: string
  trust: TrustState
}

export function createCryptoMachine(_config: CryptoMachineConfig): Promise<void> {
  return notImplemented('createCryptoMachine')
}

export function openCryptoStore(_config: CryptoMachineConfig): Promise<void> {
  return notImplemented('openCryptoStore')
}

export function restoreCryptoMachine(_bundle: Uint8Array): Promise<void> {
  return notImplemented('restoreCryptoMachine')
}

export function receiveSyncChanges(_syncDelta: unknown): Promise<void> {
  return notImplemented('receiveSyncChanges')
}

export function encryptEvent(
  _scope: CryptoScopeId,
  _eventType: string,
  _payload: unknown,
): Promise<EventEnvelope> {
  return notImplemented('encryptEvent')
}

export function decryptEvent(_rawEvent: unknown): Promise<EventEnvelope> {
  return notImplemented('decryptEvent')
}

export function getDeviceStatuses(_userId: string): Promise<DeviceStatus[]> {
  return notImplemented('getDeviceStatuses')
}

export function requestVerification(_userId: string, _deviceId: string): Promise<string> {
  return notImplemented('requestVerification')
}

export function confirmVerification(_verificationId: string, _data: unknown): Promise<void> {
  return notImplemented('confirmVerification')
}

export function exportSecrets(_passphrase: string): Promise<Uint8Array> {
  return notImplemented('exportSecrets')
}

export function importSecrets(_bundle: Uint8Array, _passphrase: string): Promise<void> {
  return notImplemented('importSecrets')
}

/** Algorithms this build can carry. Open by design; see spec section 6. */
export function getSupportedAlgorithms(): CryptoAlgorithm[] {
  return ['megolm', 'olm']
}
```

`packages/react-native-matrix-crypto/src/probe.ts`:
```ts
import { probeWithObserver } from './generated/matrix_crypto'
import { toCryptoError } from './errors'
import { emitCryptoSignal } from './signals'

export interface ProbeResult {
  echoed: string
  payload: Uint8Array
  coreVersion: string
}

/**
 * Round-trips a string and bytes through the whole chain, emitting one signal.
 * Exists to prove the binding chain works. It has no cryptographic meaning.
 */
/**
 * The generated binding speaks `ArrayBuffer`; the public API speaks
 * `Uint8Array`, which is the idiomatic React Native shape for binary data and
 * what `EventEnvelope.ciphertext` uses. The shim converts in both directions.
 *
 * Slicing when the view is not the whole buffer is load-bearing: a bare
 * `.buffer` would hand the native side the entire backing store rather than
 * the caller's window onto it.
 */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const isWholeBuffer =
    view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
  return isWholeBuffer ? (view.buffer as ArrayBuffer) : view.slice().buffer
}

export async function runProbe(input: string, payload: Uint8Array): Promise<ProbeResult> {
  try {
    const report = await probeWithObserver(input, toArrayBuffer(payload), {
      onSignal(signal: { kind: string; detail: string }) {
        emitCryptoSignal({ kind: 'probe_started', detail: signal.detail })
      },
    })
    return {
      echoed: report.echoed,
      payload: new Uint8Array(report.payload),
      coreVersion: report.coreVersion,
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}
```

`packages/react-native-matrix-crypto/src/index.ts`:

Note that ubrn has already generated `src/index.tsx` alongside this file. That
generated file re-exports the raw bindings and is NOT the package entry point:
`package.json`'s `main` is the explicit path `src/index.ts`, so resolution stays
unambiguous. Do not delete `index.tsx` (the drift guardrail owns it) and do not
import from it.

```ts
// The public API. Consumers import from here and nowhere else.
// Nothing from ./generated is re-exported: spec section 5 forbids leaking
// internal Rust structure.

export type { CryptoAlgorithm, CryptoScopeId, EventEnvelope, TrustState } from './types'
export { asCryptoScopeId } from './types'

export type { CryptoError, CryptoErrorKind } from './errors'
export { isCryptoError } from './errors'

export type { CryptoSignal, Unsubscribe } from './signals'
export { onCryptoSignal } from './signals'

export type { ProbeResult } from './probe'
export { runProbe } from './probe'

export type { CryptoMachineConfig, DeviceStatus } from './facade'
export {
  confirmVerification,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  exportSecrets,
  getDeviceStatuses,
  getSupportedAlgorithms,
  importSecrets,
  openCryptoStore,
  receiveSyncChanges,
  requestVerification,
  restoreCryptoMachine,
} from './facade'
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `yarn --cwd packages/react-native-matrix-crypto test`
Expected: PASS.

- [ ] **Step 5: Write the agility guardrail**

Note the subtlety: `CryptoAlgorithm` legitimately contains the *string literal* `'megolm'`. What spec §6 forbids is a Megolm-specific **identifier** — a type name, function name, or parameter name. So the check strips string literals before grepping.

`scripts/assert-facade-agility.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

PKG=packages/react-native-matrix-crypto
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# Emit declarations for the public surface only.
yarn --cwd "$PKG" exec tsc -- \
  --declaration --emitDeclarationOnly --noEmit false \
  --outDir "$OUT" src/index.ts 2>/dev/null

# Concatenate the public .d.ts, excluding anything generated.
DTS=$(find "$OUT" -name '*.d.ts' -not -path '*/generated/*' -exec cat {} +)

# Strip string literals: 'megolm' as a VALUE is allowed and expected,
# because the union is open. A Megolm-specific IDENTIFIER is not.
IDENTIFIERS=$(printf '%s' "$DTS" | sed "s/'[^']*'//g; s/\"[^\"]*\"//g")

# Split identifiers into components on case transitions and underscores, then
# reject any component that IS a forbidden word.
#
# Do NOT use a word-boundary regex here. `\bmegolm\b` never fires inside a
# camelCase or PascalCase identifier, because there is no word-character to
# non-word-character transition: `MegolmSession`, `encryptMegolmEvent` and
# `MegolmSessionInternal` all slip straight through. That is the normal way
# TypeScript names things, so such a gate passes for the wrong reason and gives
# false assurance indefinitely.
#
# Dropping the anchors instead is equally wrong in the other direction: bare
# `olm` matches inside Holmes, volume, column and solmization. Component
# splitting resolves both directions at once.
VIOLATIONS=$(printf '%s' "$IDENTIFIERS" | python3 -c '
import re, sys
FORBIDDEN = {"megolm", "olm", "room"}
bad = []
for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sys.stdin.read()):
    parts = re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", ident)
    if any(p.lower() in FORBIDDEN for p in parts):
        bad.append(ident)
print("\n".join(sorted(set(bad))))
')

if [ -n "$VIOLATIONS" ]; then
  echo "FAIL: a Megolm-, Olm-, or room-specific identifier reached the public API."
  echo "$VIOLATIONS"
  echo "      Spec section 6 requires the facade stay algorithm-agnostic."
  exit 1
fi

echo "PASS: facade agility"
```

- [ ] **Step 6: Verify the guardrail passes, then verify it catches a violation**

```bash
chmod +x scripts/assert-facade-agility.sh
./scripts/assert-facade-agility.sh
```
Expected: `PASS: facade agility`.

Prove it bites, and prove it does not over-fire. Both directions matter: a gate
that flags `getColumnCount` gets switched off within a week, which is a worse
outcome than the bug it was meant to catch.

```bash
# Must FAIL -- each of these is a camelCase case the old word-boundary regex missed.
for violation in \
  'export interface MegolmSession { id: string }' \
  'export function encryptMegolmEvent(): void {}' \
  'export type OlmHandle = string'
do
  printf '\n%s\n' "$violation" >> packages/react-native-matrix-crypto/src/facade.ts
  ./scripts/assert-facade-agility.sh && echo "GATE FAILED TO CATCH: $violation"
  git checkout -- packages/react-native-matrix-crypto/src/facade.ts
done

# Must PASS -- legitimate names that merely contain the letters.
printf '\nexport type MlsGroupId = string\nexport function getColumnCount(): number { return 0 }\n' \
  >> packages/react-native-matrix-crypto/src/facade.ts
./scripts/assert-facade-agility.sh || echo "GATE OVER-FIRED on a legitimate identifier"
git checkout -- packages/react-native-matrix-crypto/src/facade.ts
```
Expected: a FAIL naming the offending identifier for each of the three violations,
no "GATE FAILED TO CATCH" line, then `PASS: facade agility` with the legitimate
names present and no "GATE OVER-FIRED" line.

- [ ] **Step 7: Commit**

```bash
git add packages/react-native-matrix-crypto/src/ scripts/assert-facade-agility.sh
git commit -m "feat(ts): Add public facade with agility guardrail on the declaration surface"
```

---

### Task 9b: The shared binding-interop suite

Spec §8 requires the shared JS suite to exist from day one, so a second binding drops into it rather than growing its own divergent tests. Today there is one binding (JSI, device-only). The suite is therefore written binding-agnostic and run twice: against a reference implementation in Node CI, which proves the suite is executable and its expectations self-consistent, and against the real JSI binding on device in Task 11, which is the actual gate.

**Files:**
- Create: `packages/react-native-matrix-crypto/interop/suite.ts`
- Create: `packages/react-native-matrix-crypto/interop/reference.ts`
- Create: `packages/react-native-matrix-crypto/interop/suite.test.ts`
- Modify: `packages/react-native-matrix-crypto/tsconfig.json` — widen `include` to
  `["src", "interop"]`. Without this the typecheck gate does not cover a single file
  this task creates, and would report green over completely untypechecked code. Nothing
  under `src/` imports `interop/*`, so the directory is otherwise invisible to `tsc`.
  This does not affect `scripts/assert-facade-agility.sh`, which passes a file argument
  to `tsc` and therefore ignores `tsconfig.json` entirely.

**Interfaces:**
- Consumes: `runProbe` and `onCryptoSignal` from Task 9.
- Produces: `runInteropSuite(binding: BridgeBinding): Promise<InteropCheck[]>` and the `BridgeBinding` shape every future binding must satisfy.

- [ ] **Step 1: Write the failing test**

`packages/react-native-matrix-crypto/interop/suite.test.ts`:
```ts
import { describe, expect, it } from 'vitest'
import { runInteropSuite } from './suite'
import { referenceBinding } from './reference'

describe('interop suite', () => {
  it('passes every check against the reference binding', async () => {
    const checks = await runInteropSuite(referenceBinding())
    const failed = checks.filter((c) => !c.ok)
    expect(failed, `failed: ${failed.map((c) => c.name).join(', ')}`).toHaveLength(0)
    expect(checks).toHaveLength(5)
  })

  it('reports a failure rather than throwing when a binding misbehaves', async () => {
    const broken = referenceBinding()
    broken.runProbe = async () => ({ echoed: 'wrong', payload: new Uint8Array(), coreVersion: '' })

    const checks = await runInteropSuite(broken)
    expect(checks.find((c) => c.name === 'record')?.ok).toBe(false)
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `yarn --cwd packages/react-native-matrix-crypto test`
Expected: FAIL, `Failed to resolve import "./suite"`.

- [ ] **Step 3: Write the minimal implementation**

`packages/react-native-matrix-crypto/interop/suite.ts`:
```ts
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
 */
export async function runInteropSuite(binding: BridgeBinding): Promise<InteropCheck[]> {
  const checks: InteropCheck[] = []
  const signals: string[] = []

  // Subscribing is itself a call into the binding, so it can throw. Seeding a
  // no-op and guarding the call keeps that inside the contract: a binding whose
  // onCryptoSignal throws must produce a failing check, not reject the suite
  // before a single check has been pushed.
  let unsubscribe: () => void = () => {}
  try {
    unsubscribe = binding.onCryptoSignal((s) => signals.push(s.kind))
  } catch {
    // Left to fail at the `signal` check below.
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
    // A throw from `finally` REPLACES whatever the try was about to return, so
    // an unguarded unsubscribe() here would discard an already-complete set of
    // checks. On a device that turns a useful partial result into nothing.
    try {
      unsubscribe()
    } catch {
      // Teardown failure must not destroy the results.
    }
  }

  return checks
}
```

`packages/react-native-matrix-crypto/interop/reference.ts`:
```ts
import type { BridgeBinding } from './suite'
import { isCryptoError, toCryptoError } from '../src/errors'

/**
 * Pure-TypeScript restatement of the contract, used to exercise the suite in
 * Node where the JSI module cannot load. It doubles as executable
 * documentation of what a binding must do.
 */
export function referenceBinding(): BridgeBinding {
  const listeners = new Set<(s: { kind: string }) => void>()

  return {
    async runProbe(input, payload) {
      if (input === '') {
        throw toCryptoError({ name: 'Rejected', reason: 'input must not be empty' })
      }
      for (const l of listeners) l({ kind: 'probe_started' })
      return {
        echoed: input,
        payload: new Uint8Array(Array.from(payload).reverse()),
        coreVersion: '0.1.0',
      }
    },
    onCryptoSignal(cb) {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    isCryptoError,
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `yarn --cwd packages/react-native-matrix-crypto test`
Expected: PASS, 2 tests, the suite reporting 5 checks.

- [ ] **Step 5: Commit**

```bash
git add packages/react-native-matrix-crypto/interop/
git commit -m "test: Add shared binding-interop suite with a reference binding"
```

---

### Task 10: The no-logger guardrail

Spec §7.2: a crypto library that logs by default is how cleartext reaches a crash report.

**Files:**
- Create: `scripts/assert-no-logger.sh`

**Interfaces:**
- Consumes: all source written so far.
- Produces: `yarn gate:logger`.

- [ ] **Step 1: Write the guardrail**

`scripts/assert-no-logger.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Spec section 7.2: the bridge has no logger. Generated code is excluded
# because we do not control it; the example app is excluded because it is
# not the bridge.
RUST_HITS=$(grep -rnE '(println!|eprintln!|dbg!|\blog::|\btracing::)' \
  rust/matrix-crypto-core/src rust/matrix-crypto-ffi/src 2>/dev/null || true)

# ubrn also generates src/index.tsx and src/NativeMatrixCrypto.ts, which sit
# directly under src/ rather than inside src/generated/. They must be excluded
# too: a guardrail that fires on tool output nobody controls would block every
# later task. Selected by the absence of the "Generated by
# uniffi-bindgen-react-native" header rather than a hardcoded name list, so any
# future generated file is excluded automatically.
TS_FILES=$(grep -rLE 'Generated by uniffi-bindgen-react-native' \
  --include='*.ts' --include='*.tsx' \
  -r packages/react-native-matrix-crypto/src \
  --exclude-dir=generated 2>/dev/null || true)

TS_HITS=""
if [ -n "$TS_FILES" ]; then
  TS_HITS=$(echo "$TS_FILES" | xargs grep -nE '\bconsole\.[a-z]+' 2>/dev/null || true)
fi

if [ -n "$RUST_HITS$TS_HITS" ]; then
  echo "FAIL: the bridge must not log. Spec section 7.2."
  [ -n "$RUST_HITS" ] && echo "$RUST_HITS"
  [ -n "$TS_HITS" ] && echo "$TS_HITS"
  echo "      Diagnostics belong in a sink the product injects and owns."
  exit 1
fi

echo "PASS: no logger"
```

- [ ] **Step 2: Verify it passes**

Run: `chmod +x scripts/assert-no-logger.sh && ./scripts/assert-no-logger.sh`
Expected: `PASS: no logger`

- [ ] **Step 3: Verify it catches a violation**

```bash
printf '\n// probe\nfn _leak() { println!("secret"); }\n' >> rust/matrix-crypto-core/src/probe.rs
./scripts/assert-no-logger.sh || echo "guardrail correctly rejected the logger"
git checkout -- rust/matrix-crypto-core/src/probe.rs
```
Expected: FAIL message naming the file and line, then the confirmation line.

- [ ] **Step 4: Commit**

```bash
git add scripts/assert-no-logger.sh
git commit -m "test: Add guardrail rejecting any logger in the bridge"
```

---

### Task 11: iOS build, on-device probe, and the size baseline

**Files:**
- Create: `packages/example-app/` (React Native 0.87.1)
- Create: `packages/example-app/src/ProbeHarness.tsx`
- Create: `scripts/measure-artifacts.sh`

**Interfaces:**
- Consumes: `runProbe`, `onCryptoSignal` from Task 9; `runInteropSuite`, `BridgeBinding` from Task 9b.
- Produces: an `.xcframework`, a recorded baseline size, and five passing on-device assertions.

- [ ] **Step 1: Create the example app**

```bash
cd packages
npx @react-native-community/cli@latest init ExampleApp --version 0.87.1 --directory example-app --skip-install
cd example-app
yarn add file:../react-native-matrix-crypto
```

The app must remain neutral: nothing Messagr-specific, per spec §12.

- [ ] **Step 2: Write the on-device assertion harness**

The bridge does not log. The example app may, and does: CI scrapes these lines.

`packages/example-app/src/ProbeHarness.tsx`:
```tsx
import React, { useEffect, useState } from 'react'
import { Text, View } from 'react-native'
import { isCryptoError, onCryptoSignal, runProbe } from 'react-native-matrix-crypto'
import {
  runInteropSuite,
  type BridgeBinding,
  type InteropCheck,
} from 'react-native-matrix-crypto/interop/suite'

/**
 * Adapts the shipped JSI binding to the shared contract from Task 9b.
 * The checks themselves live in the suite, so the device run and the Node
 * run cannot drift apart.
 */
function jsiBinding(): BridgeBinding {
  return {
    runProbe,
    onCryptoSignal: (cb) => onCryptoSignal((s) => cb({ kind: s.kind })),
    isCryptoError,
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}

export function ProbeHarness() {
  const [checks, setChecks] = useState<InteropCheck[]>([])

  useEffect(() => {
    runInteropSuite(jsiBinding()).then((results) => {
      setChecks(results)
      for (const c of results) {
        // Machine-readable line scraped by CI. The example app is not the
        // bridge, so it may log; the bridge itself never does.
        console.log(`PROBE_CHECK ${c.name} ${c.ok ? 'PASS' : 'FAIL'} ${c.detail}`)
      }
      console.log(`PROBE_SUMMARY ${results.filter((c) => c.ok).length}/${results.length}`)
    })
  }, [])

  return (
    <View>
      {checks.map((c) => (
        <Text key={c.name}>{`${c.name}: ${c.ok ? 'PASS' : 'FAIL'} (${c.detail})`}</Text>
      ))}
    </View>
  )
}
```

Render `<ProbeHarness />` from `App.tsx`.

- [ ] **Step 3: Build the iOS artifact**

```bash
yarn --cwd packages/react-native-matrix-crypto exec ubrn -- build ios \
  --config ../../ubrn.config.yaml \
  --targets aarch64-apple-ios,aarch64-apple-ios-sim,x86_64-apple-ios \
  --release \
  --and-generate
```
Expected: an `.xcframework` is produced. First run also compiles ubrn itself, which takes several minutes.

- [ ] **Step 4: Write the size measurement script**

`scripts/measure-artifacts.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Spec section 10: artifact size decides whether binaries can ship inside the
# npm tarball at all. Record it rather than guess at it.
size_of() {
  [ -e "$1" ] && du -sk "$1" | cut -f1 || echo 0
}

XC=$(find packages -name '*.xcframework' -maxdepth 4 | head -1)
AAR=$(find packages -name '*.aar' -maxdepth 5 | head -1)

XC_KB=$(size_of "${XC:-/nonexistent}")
AAR_KB=$(size_of "${AAR:-/nonexistent}")

TARBALL_KB=$(cd packages/react-native-matrix-crypto && npm pack --dry-run --json 2>/dev/null \
  | node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8")); console.log(Math.round((j[0]?.size??0)/1024))')

node -e "
  const fs = require('fs');
  const row = {
    label: process.argv[1],
    xcframeworkKB: Number(process.argv[2]),
    aarKB: Number(process.argv[3]),
    tarballKB: Number(process.argv[4]),
  };
  const path = 'artifact-sizes.json';
  const all = fs.existsSync(path) ? JSON.parse(fs.readFileSync(path,'utf8')) : [];
  all.push(row);
  fs.writeFileSync(path, JSON.stringify(all, null, 2));
  console.log(JSON.stringify(row));
" "${1:-unlabelled}" "$XC_KB" "$AAR_KB" "$TARBALL_KB"
```

- [ ] **Step 5: Record the M1a baseline**

```bash
chmod +x scripts/measure-artifacts.sh
./scripts/measure-artifacts.sh m1a-baseline
```
Expected: a JSON line with the three sizes, appended to `artifact-sizes.json`.

- [ ] **Step 6: Run the app on a physical iOS device and confirm all five checks**

```bash
yarn --cwd packages/example-app ios --device
```
Expected in the console: five `PROBE_CHECK ... PASS` lines and `PROBE_SUMMARY 5/5`.

A physical device is required, not only the simulator: the simulator does not exercise the device architecture slice of the xcframework.

- [ ] **Step 7: Commit**

```bash
git add packages/example-app scripts/measure-artifacts.sh artifact-sizes.json
git commit -m "feat(example): Add on-device probe harness and record iOS baseline size"
```

---

### Task 12: Android build and emulator run

**Files:**
- Modify: `packages/example-app/android/`
- Modify: `artifact-sizes.json`

**Interfaces:**
- Consumes: everything from Task 11.
- Produces: an `.aar`, a recorded baseline size, five passing checks on an emulator.

- [ ] **Step 1: Add the missing Rust target**

```bash
rustup target add armv7-linux-androideabi
rustup target list --installed | grep armv7
```
Expected: `armv7-linux-androideabi` listed. It is absent from a default install, and spec §4 requires it.

- [ ] **Step 2: Build the Android artifact**

```bash
yarn --cwd packages/react-native-matrix-crypto exec ubrn -- build android \
  --config ../../ubrn.config.yaml \
  --targets aarch64-linux-android,armv7-linux-androideabi,x86_64-linux-android \
  --release \
  --and-generate
```
Expected: an `.aar` is produced containing all three ABIs.

- [ ] **Step 3: Run on an emulator and confirm all five checks**

```bash
yarn --cwd packages/example-app android
adb logcat -d | grep -E 'PROBE_CHECK|PROBE_SUMMARY'
```
Expected: five `PROBE_CHECK ... PASS` lines and `PROBE_SUMMARY 5/5`.

- [ ] **Step 4: Record the size and confirm the drift gate**

```bash
./scripts/measure-artifacts.sh m1a-baseline-android
./scripts/assert-no-drift.sh
```
Expected: a JSON line, then `PASS: no codegen drift`.

- [ ] **Step 5: Commit**

```bash
git add artifact-sizes.json packages/
git commit -m "feat(example): Run the probe on Android and record the baseline size"
```

---

### Task 13: CI with every gate, including cold-consume

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: every guardrail script.
- Produces: a CI pipeline where each gate blocks.

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:
```yaml
name: ci

on:
  pull_request:
  push:
    branches: [main]

jobs:
  gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version-file: '.nvmrc', cache: yarn }
      - run: yarn install --frozen-lockfile
      - run: yarn gate:workspaces
      - run: yarn gate:boundary
      - run: yarn gate:drift
      - run: yarn gate:logger
      - run: yarn gate:agility
      - run: cargo fmt --manifest-path rust/Cargo.toml --all -- --check
      - run: cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
      - run: yarn --cwd packages/react-native-matrix-crypto typecheck
      - run: yarn --cwd packages/react-native-matrix-crypto test

  cold-consume:
    # The only real proof of spec section 4bis.2: the consumer installs no
    # Rust toolchain. This runner deliberately has no cargo on PATH.
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version-file: '.nvmrc' }
      - name: Confirm the runner has no Rust
        run: |
          if command -v cargo >/dev/null 2>&1; then
            echo "Removing cargo from PATH so the test is honest"
            sudo rm -f "$(command -v cargo)" "$(command -v rustc)"
          fi
          ! command -v cargo
      - name: Pack and install into a fresh project
        run: |
          TARBALL=$(cd packages/react-native-matrix-crypto && npm pack --silent)
          mkdir -p /tmp/consumer && cd /tmp/consumer
          npm init -y >/dev/null
          npm install "$GITHUB_WORKSPACE/packages/react-native-matrix-crypto/$TARBALL"
          node -e "require.resolve('react-native-matrix-crypto'); console.log('resolved with no Rust toolchain')"

  build-ios:
    runs-on: macos-15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version-file: '.nvmrc', cache: yarn }
      - run: yarn install --frozen-lockfile
      - run: |
          yarn --cwd packages/react-native-matrix-crypto exec ubrn -- build ios \
            --config ../../ubrn.config.yaml \
            --targets aarch64-apple-ios-sim \
            --release --and-generate
      - run: ./scripts/measure-artifacts.sh ci-ios
      - uses: actions/upload-artifact@v4
        with: { name: artifact-sizes-ios, path: artifact-sizes.json }

  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version-file: '.nvmrc', cache: yarn }
      - run: yarn install --frozen-lockfile
      - run: |
          yarn --cwd packages/react-native-matrix-crypto exec ubrn -- build android \
            --config ../../ubrn.config.yaml \
            --targets x86_64-linux-android \
            --release --and-generate
      - run: ./scripts/measure-artifacts.sh ci-android
```

On pull requests the iOS leg builds only the simulator slice, because macOS runners are the cost centre. The full cross-compile matrix belongs in the release workflow, on tag.

- [ ] **Step 2: Verify every gate runs green locally first**

```bash
yarn gate:workspaces && yarn gate:boundary && yarn gate:drift \
  && yarn gate:logger && yarn gate:agility \
  && cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings \
  && yarn --cwd packages/react-native-matrix-crypto typecheck \
  && yarn --cwd packages/react-native-matrix-crypto test
```
Expected: every command exits 0.

- [ ] **Step 3: Push and confirm CI is green**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: Add gates for boundary, drift, logger, agility and cold consumption"
git push -u origin main
gh run watch
```
Expected: all five jobs pass. If `cold-consume` fails, check that `uniffi-bindgen-react-native` is in `devDependencies` and not `dependencies`.

**M1a is complete when this workflow is green and `artifact-sizes.json` holds the baseline.**

---

### Task 14: M1b, add `matrix-sdk-crypto`

The chain is proven. Now prove it survives the real dependency.

**Files:**
- Modify: `rust/matrix-crypto-core/Cargo.toml`, `rust/matrix-crypto-core/src/lib.rs`
- Create: `rust/matrix-crypto-core/src/identity.rs`
- Modify: `rust/matrix-crypto-ffi/src/lib.rs`, `packages/react-native-matrix-crypto/src/facade.ts`

**Interfaces:**
- Consumes: everything from M1a.
- Produces: `matrix_crypto_core::device_identity_keys(user_id, device_id) -> Result<IdentityKeys, IdentityError>` where `IdentityKeys { curve25519: String, ed25519: String }`; the same exported over UniFFI and surfaced as `getDeviceIdentityKeys` in the facade.

- [ ] **Step 1: Write the failing test**

`rust/matrix-crypto-core/src/identity.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_well_formed_identity_keys() {
        let keys = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();

        // Curve25519 and Ed25519 public keys are 32 bytes, unpadded base64 = 43 chars.
        assert_eq!(keys.curve25519.len(), 43);
        assert_eq!(keys.ed25519.len(), 43);
        assert_ne!(keys.curve25519, keys.ed25519);
    }

    #[tokio::test]
    async fn distinct_devices_get_distinct_keys() {
        let a = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();
        let b = device_identity_keys("@a:server1", "DEVICE2").await.unwrap();
        assert_ne!(a.ed25519, b.ed25519);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml`
Expected: FAIL to compile, `cannot find function 'device_identity_keys'`.

- [ ] **Step 3: Add the dependency and implement**

Add to `rust/matrix-crypto-core/Cargo.toml`:
```toml
matrix-sdk-crypto = "0.18.0"
```
and to `[dev-dependencies]`, add `"rt-multi-thread"` to the tokio features, since `matrix-sdk-crypto` may require a multi-threaded reactor:
```toml
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
```

`rust/matrix-crypto-core/src/identity.rs` (above the test module):
```rust
use matrix_sdk_crypto::OlmMachine;
use ruma::{OwnedDeviceId, OwnedUserId};

/// The device's own public identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
}

/// Creates an in-memory crypto machine and returns its identity keys.
///
/// This is the first genuine cryptographic value to cross the binding chain.
pub async fn device_identity_keys(
    user_id: &str,
    device_id: &str,
) -> Result<IdentityKeys, IdentityError> {
    let user: OwnedUserId = user_id
        .parse()
        .map_err(|_| IdentityError::MalformedIdentifier { detail: "user id".to_string() })?;
    let device: OwnedDeviceId = device_id.into();

    let machine = OlmMachine::new(&user, &device).await;
    let keys = machine.identity_keys();

    Ok(IdentityKeys {
        curve25519: keys.curve25519.to_base64(),
        ed25519: keys.ed25519.to_base64(),
    })
}
```

Add `mod identity;` and `pub use identity::{device_identity_keys, IdentityError, IdentityKeys};` to `lib.rs`.

If the compiler reports that `ruma` is not a dependency, add the version `matrix-sdk-crypto` re-exports rather than picking one independently: use `matrix_sdk_crypto::ruma::{OwnedDeviceId, OwnedUserId}` in the import instead of a direct `ruma` dependency. Prefer the re-export; a second, independently versioned `ruma` in the tree is a known source of type mismatches.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml`
Expected: PASS. This may take several minutes on the first build; `matrix-sdk-crypto` pulls a large tree.

- [ ] **Step 5: Confirm the core boundary still holds**

Run: `./scripts/assert-core-boundary.sh`
Expected: `PASS: core boundary`. `matrix-sdk-crypto` is a legitimate core dependency; `uniffi` still must not be.

- [ ] **Step 6: Export it and resolve the async runtime question**

Add to `rust/matrix-crypto-ffi/src/lib.rs`:
```rust
#[derive(uniffi::Record)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum IdentityFfiError {
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
}

#[uniffi::export]
pub async fn device_identity_keys(
    user_id: String,
    device_id: String,
) -> Result<IdentityKeys, IdentityFfiError> {
    matrix_crypto_core::device_identity_keys(&user_id, &device_id)
        .await
        .map(|k| {
            // Destructured, not field-accessed. See Global Constraints.
            let matrix_crypto_core::IdentityKeys { curve25519, ed25519 } = k;
            IdentityKeys { curve25519, ed25519 }
        })
        .map_err(|e| match e {
            matrix_crypto_core::IdentityError::MalformedIdentifier { detail } => {
                IdentityFfiError::MalformedIdentifier { detail }
            }
        })
}
```

Build for a device target and run the example app. **If it panics at runtime with a message about no reactor running**, `matrix-sdk-crypto`'s futures need a tokio reactor: change the attribute to `#[uniffi::export(async_runtime = "tokio")]` and add `tokio = { version = "1", features = ["rt-multi-thread"] }` to the FFI crate's `[dependencies]`. Record which was needed in the spec's §5.1.

**If you add `async_runtime = "tokio"`, stop and report before going further.** Task 8
established that UniFFI callback methods returning a value synchronously are dispatched
via `UniffiCallInvoker::invokeBlocking`, which blocks the calling native thread on a
promise whenever that thread is not the JS thread. Without a tokio runtime this costs
nothing, because exported functions already run on the JS thread. With one, every signal
delivery becomes a real cross-thread blocking round-trip — on a channel the spec requires
to be silent and cheap, firing on key events.

That is a design decision, not an implementation detail, and it is not this task's to
make. Add the attribute if the reactor is genuinely required, verify the probe and the
signal still work, and then report the threading consequence explicitly so it can be
ruled on.

- [ ] **Step 7: Surface it and regenerate**

Add to `packages/react-native-matrix-crypto/src/facade.ts`:
```ts
import { deviceIdentityKeys as nativeDeviceIdentityKeys } from './generated/matrix_crypto'

export interface IdentityKeys {
  curve25519: string
  ed25519: string
}

export async function getDeviceIdentityKeys(
  userId: string,
  deviceId: string,
): Promise<IdentityKeys> {
  try {
    return await nativeDeviceIdentityKeys(userId, deviceId)
  } catch (e) {
    throw toCryptoError(e)
  }
}
```

Export `getDeviceIdentityKeys` and the `IdentityKeys` type from `src/index.ts`, then run `./scripts/assert-no-drift.sh` and commit the regenerated bindings.

- [ ] **Step 8: Add the on-device check**

The shared suite from Task 9b covers the chain contract and stays binding-agnostic, so the crypto check is appended by the harness rather than added to the suite.

In `packages/example-app/src/ProbeHarness.tsx`, add `getDeviceIdentityKeys` to the import from `react-native-matrix-crypto`, then replace the effect body:

```tsx
  useEffect(() => {
    runInteropSuite(jsiBinding()).then(async (results) => {
      // M1b-specific: proves a genuine cryptographic value crosses the same
      // chain the probe proved in M1a.
      try {
        const keys = await getDeviceIdentityKeys('@a:server1', 'DEVICE1')
        results.push({
          name: 'real_crypto',
          ok: keys.ed25519.length === 43 && keys.curve25519.length === 43,
          detail: `${keys.ed25519.length}/${keys.curve25519.length}`,
        })
      } catch (e) {
        results.push({ name: 'real_crypto', ok: false, detail: String(e) })
      }

      setChecks(results)
      for (const c of results) {
        console.log(`PROBE_CHECK ${c.name} ${c.ok ? 'PASS' : 'FAIL'} ${c.detail}`)
      }
      console.log(`PROBE_SUMMARY ${results.filter((c) => c.ok).length}/${results.length}`)
    })
  }, [])
```

- [ ] **Step 9: Rebuild both platforms, confirm six checks, record the delta**

```bash
yarn --cwd packages/react-native-matrix-crypto exec ubrn -- build ios \
  --config ../../ubrn.config.yaml \
  --targets aarch64-apple-ios,aarch64-apple-ios-sim,x86_64-apple-ios --release --and-generate
./scripts/measure-artifacts.sh m1b-with-matrix-sdk-crypto
yarn --cwd packages/example-app ios --device
```
Expected: `PROBE_SUMMARY 6/6`.

Repeat for Android per Task 12, then compare:
```bash
node -e '
  const rows = require("./artifact-sizes.json");
  const base = rows.find(r => r.label === "m1a-baseline");
  const now  = rows.find(r => r.label === "m1b-with-matrix-sdk-crypto");
  const mb = kb => (kb / 1024).toFixed(1) + " MB";
  console.log("xcframework:", mb(base.xcframeworkKB), "->", mb(now.xcframeworkKB));
  console.log("tarball:    ", mb(base.tarballKB),     "->", mb(now.tarballKB));
  if (now.tarballKB > 150 * 1024) {
    console.log("\nSIZE GATE TRIPPED: tarball exceeds 150 MB.");
    console.log("Spec section 10 requires re-opening the binary distribution decision.");
    console.log("Pre-agreed fallback: split per-platform packages via optionalDependencies.");
  } else {
    console.log("\nSize gate clear: packing binaries into the tarball remains viable.");
  }
'
```

- [ ] **Step 10: Commit**

```bash
git add rust/ packages/ artifact-sizes.json
git commit -m "feat(core): Add device identity keys backed by matrix-sdk-crypto"
```

**M1b is complete when six checks pass on both platforms, every M1a gate is still green, and the size delta is recorded and evaluated against the gate.**

---

## Notes for the executor

- **Run the guardrail-catches-a-violation steps.** They look like busywork. They are the only evidence the gate is wired up; a gate that has never failed is not known to work.
- **First `ubrn` invocation compiles ubrn itself from Rust source.** Several minutes, once per machine. Not a hang.
- **Never hand-edit anything under `src/generated/` or `cpp/generated/`.** Change the Rust, regenerate, commit the result.
- **A physical iOS device is required for Task 11**, not just the simulator, because the simulator never exercises the device architecture slice.
- **`.github/workflows/release.yml` is deliberately not in this plan.** The skeleton never publishes. The tag-triggered full cross-compile, pack and `npm publish` pipeline of spec §9 belongs to M2, once the size gate in Task 14 has decided whether binaries can ship in the tarball at all.
- **If ubrn 0.31.0-5 turns out to be broken** on something load-bearing, stop and report rather than working around it. It is the plan's largest risk (spec §12), and the whole point of M1a is to find that out cheaply.
