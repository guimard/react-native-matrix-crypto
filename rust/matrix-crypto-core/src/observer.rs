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
