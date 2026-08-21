use thiserror::Error;

pub type Result<T> = std::result::Result<T, WafidError>;

#[derive(Debug, Error)]
pub enum WafidError {
    #[error("invalid target url '{target}': {reason}")]
    InvalidUrl { target: String, reason: String },

    #[error("failed to load signatures from {path}: {source}")]
    SignatureLoad {
        path: String,
        source: serde_yaml::Error,
    },

    #[error("invalid signature pack: {0}")]
    SignatureInvalid(String),

    #[error("http client configuration error: {0}")]
    HttpConfig(String),

    #[error("request to {url} failed after {attempts} attempt(s): {detail}")]
    RequestFailed {
        url: String,
        attempts: u32,
        detail: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl WafidError {
    pub fn signature_invalid(msg: impl Into<String>) -> Self {
        WafidError::SignatureInvalid(msg.into())
    }
}
