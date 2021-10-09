/// Errors that can happen during attestation and verification process
#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    #[error("Attestation Service error")]
    AttestationServiceError,
    #[error("Report error")]
    ReportError,
    #[error("Connection error")]
    ConnectionError,
    #[error("Attestation Service API version not compatible")]
    ApiVersionNotCompatible,
}