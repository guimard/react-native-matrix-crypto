# Security policy

## Reporting a vulnerability

Report it privately, through **[GitHub's private security advisory form](https://github.com/linagora/react-native-matrix-crypto/security/advisories/new)** on this repository. Please do not open a public issue for a suspected vulnerability.

Include what you need to make it reproducible: the version, the platform, the calls involved, and what you observed against what you expected. If you have a proof of concept, attach it to the advisory rather than posting it anywhere public.

You should get an acknowledgement within a week. If you have not heard anything after that, please say so on the advisory rather than assuming it was seen.

## What this policy covers

This repository: the two Rust crates, the TypeScript facade, the generated bindings and the native shims that carry calls between them.

**Not the cryptography itself.** The primitives, the Olm and Megolm implementations, the verification protocols and the crypto store all come from [`matrix-sdk-crypto`](https://github.com/matrix-org/matrix-rust-sdk) and [`vodozemac`](https://github.com/matrix-org/vodozemac). A defect in either belongs to its own project, and reporting it there reaches the people who can fix it. If you are unsure which side a finding falls on, report it here and say so — sorting that out is our job, not yours.

The example app under `packages/example-app/` is a demonstration. It holds nothing of a user's, ships no release build anyone should install, and is out of scope unless the finding is also true of the library it drives.

## Versions

Pre-1.0. Fixes go to the latest published version; there are no maintained release branches. See [the roadmap](README.md#roadmap) for where the surface is still moving.

## What you should know before deploying

**This library has not been independently audited.** It wraps a widely deployed cryptographic library, but the bridge around it is new.

**Two of its defaults are deliberately permissive.** A room key is shared with every device a recipient has, including devices nobody has signed or verified — upstream's `AllDevices` strategy, which upstream marks not recommended per MSC4153. And events are decrypted from any device, at upstream's `Untrusted` trust requirement, which upstream also marks not recommended. Both are argued where they are made, in `rust/matrix-crypto-core/src/session.rs`. Neither is a defect and neither is a report; they are the posture you deploy, and they are the two facts most likely to matter to your threat model.
