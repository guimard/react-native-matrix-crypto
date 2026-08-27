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
