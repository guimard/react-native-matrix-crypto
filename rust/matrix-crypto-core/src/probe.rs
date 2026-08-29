use crate::error::ProbeError;

/// Result of a successful probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub echoed: String,
    pub payload: Vec<u8>,
    /// The crate version, and after it the build that produced this binary:
    /// `0.1.0+emit.1a2b3c4d`. See `observer::EMIT_BUILD` for what the suffix
    /// identifies and why a version alone was not enough. Semver build
    /// metadata, so it is still a valid version string and semver defines it
    /// as carrying the same precedence as a bare `0.1.0`; a consumer doing
    /// `=== '0.1.0'` on it does not agree, which is the one thing this
    /// changes and the reason it is documented on the field.
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
        // The build suffix is the whole reason this field is worth reading:
        // it makes a running artifact say which emission path it carries,
        // which is what B2's measurement could not establish about its own
        // two arms. `observer::EMIT_BUILD` carries the argument.
        core_version: format!(
            "{}+emit.{:08x}",
            env!("CARGO_PKG_VERSION"),
            crate::observer::EMIT_BUILD
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echoes_input_and_reports_version() {
        let report = probe("hello".to_string(), vec![1, 2, 3]).await.unwrap();
        assert_eq!(report.echoed, "hello");
        let (version, _build) = report
            .core_version
            .split_once("+emit.")
            .expect("core_version must carry the crate version and the emission build");
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    /// The build suffix has to be *derived*, not merely present.
    ///
    /// The failure this guards is silent and total: `include_str!` handed
    /// nothing, or a hash left at its seed, produces a suffix that is stable,
    /// well-formed, printed on every run, and identical for every build ever
    /// made -- which is precisely the property `core_version` already had and
    /// the reason the suffix was added. Asserting the shape alone would pass
    /// against it.
    #[tokio::test]
    async fn the_build_suffix_is_derived_rather_than_constant() {
        let report = probe("x".to_string(), vec![]).await.unwrap();
        let build = report
            .core_version
            .split_once("+emit.")
            .expect("core_version must carry the emission build")
            .1;

        assert_eq!(build.len(), 8, "the build suffix is a 32-bit hash in hex");
        assert!(
            build
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "the build suffix must be lowercase hex, got {build:?}"
        );
        // FNV-1a's offset basis, i.e. the value the hash still holds if it
        // consumed no bytes at all.
        assert_ne!(
            build, "811c9dc5",
            "the build suffix is still the hash's seed: it consumed no source"
        );
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
        let report = probe("x".to_string(), vec![0x00, 0xff, 0xfe])
            .await
            .unwrap();
        assert_eq!(report.payload, vec![0xfe, 0xff, 0x00]);
    }

    #[tokio::test]
    async fn rejects_empty_input() {
        let err = probe(String::new(), vec![]).await.unwrap_err();
        assert_eq!(
            err,
            ProbeError::Rejected {
                reason: "input must not be empty".to_string()
            }
        );
    }
}
