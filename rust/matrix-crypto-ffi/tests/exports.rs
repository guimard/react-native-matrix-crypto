// The FFI crate must expose the core's probe unchanged. This test does not
// cross the FFI boundary; it only proves the re-export compiles and delegates.
#[tokio::test]
async fn ffi_probe_delegates_to_core() {
    let report = matrix_crypto_ffi::probe("hi".to_string(), vec![9, 8])
        .await
        .unwrap();
    assert_eq!(report.echoed, "hi");
    assert_eq!(report.payload, vec![8, 9]);
}

#[tokio::test]
async fn ffi_probe_propagates_typed_error() {
    let err = matrix_crypto_ffi::probe(String::new(), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(err, matrix_crypto_ffi::ProbeFfiError::Rejected { reason } if reason == "input must not be empty")
    );
}

/// The signing identity's two calls exist on this crate's surface and reach
/// the core, which is the whole content of the bridge: both are one-line
/// delegations, so what can go wrong is that they are absent, or wired to
/// the wrong core function, or swallow the core's error.
///
/// No machine is created in this test binary, so the core answers
/// `NotInitialised` for both, and asserting on that particular variant is
/// what distinguishes a real delegation from a stub: a function returning
/// `Ok(())` or a default record would pass a test that only checked it
/// could be called.
#[tokio::test]
async fn the_signing_identity_calls_reach_the_core() {
    let err = matrix_crypto_ffi::identity_status().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));

    let err = matrix_crypto_ffi::bootstrap_identity().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}
