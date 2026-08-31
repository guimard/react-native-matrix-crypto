#!/usr/bin/env bash
set -euo pipefail

# Every doc link in this repository points at something that exists.
#
# A doc link is a claim: "this name is real, and your editor will take you
# there". Nothing in this repository checked that claim, and three of them
# were false at once. The one that mattered was `[`ANNOUNCED_METHODS`]` in
# `verification.rs`, a constant the code-scanning opt-in had deleted, sitting
# inside a sentence that was also false. Neither the sentence nor the link
# failed anything: `cargo test`, `clippy` and every gate here passed.
#
# WHAT THIS DOES NOT CATCH, and it has to be said here rather than
# discovered. A link is one of two ways this tree names a thing that is not
# there. The other is plain text in an ordinary comment, and no link checker
# can see it: `verification.rs` cites a test called
# `a_scanned_flow_is_not_retained_forever` in a `//` comment, that test has
# never existed, and this gate passes over it without a word. If you are
# reading this because you are about to trust it, trust it for links only.

cd "$(dirname "$0")/.."

FAILED=0

# --- Rust ------------------------------------------------------------------
#
# `--document-private-items` is not optional. Without it rustdoc does not
# look inside private modules, and every module in `matrix-crypto-core` is
# private, so the same command finds exactly zero unresolved links and this
# gate becomes decoration. That is precisely how the deleted constant
# survived: its link was in a private module's own header.
#
# `-A rustdoc::private_intra_doc_links` is not optional either. Fifteen
# public items in this tree link to private ones deliberately, which is a
# different lint and a legitimate style here; denying it would make the gate
# unlandable rather than useful.
echo "--- Rust doc links ---"
if RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -A rustdoc::private_intra_doc_links" \
     cargo doc --manifest-path rust/Cargo.toml --no-deps --workspace \
     --document-private-items >/tmp/doc-links-rust.log 2>&1; then
  echo "PASS: every Rust intra-doc link resolves"
else
  echo "FAIL: a Rust doc link points at something that does not exist."
  grep -E "^(error|warning)|unresolved link|--> " /tmp/doc-links-rust.log | head -40
  echo
  echo "      A doc link is a claim that a name is real. Fix the name, or, if"
  echo "      the target is historical or \`#[cfg(test)]\`, write it as a plain"
  echo "      code span with no brackets and say why."
  FAILED=1
fi

# --- TypeScript ------------------------------------------------------------
#
# `{@link X}` resolves against what the file has in scope, so a name a doc
# comment sends a reader to has to be imported even when nothing in the file
# uses it. `types.ts` and `signals.ts` both carry a type-only import block
# that exists for exactly that, and both drifted: four links were added to
# one and two to the other without the blocks growing, under the paragraphs
# explaining why the blocks are there.
#
# Scoped to the published package's own sources. Generated files are not
# hand-written and test files are not published.
echo "--- TypeScript doc links ---"
if node scripts/assert-doc-links.mjs; then
  :
else
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
