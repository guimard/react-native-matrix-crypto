/// Errors the core can return.
///
/// Carries no payload content and no device identifier. See spec section 7.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    #[error("probe rejected: {reason}")]
    Rejected { reason: String },
}
