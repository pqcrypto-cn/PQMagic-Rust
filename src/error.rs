use std::fmt;

pub type Result<T> = std::result::Result<T, PqmagicError>;

#[derive(Debug)]
pub enum PqmagicError {
    UnknownAlgorithm(String),
    BufferLength { expected: usize, actual: usize },
    Keygen(i32),
    Signing(i32),
    Verification(i32),
    SignMessage(i32),
    VerifyMessage(i32),
    Encapsulation(i32),
    Decapsulation(i32),

    NotAKemAlgorithm(String),
    NotASigAlgorithm(String),
}

impl fmt::Display for PqmagicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqmagicError::UnknownAlgorithm(name) => write!(f, "Unknown algorithm: {}", name),
            PqmagicError::BufferLength { expected, actual } => {
                write!(f, "Buffer length mismatch: expected {}, got {}", expected, actual)
            }
            PqmagicError::Keygen(code) => write!(f, "Key generation failed: code {}", code),
            PqmagicError::Signing(code) => write!(f, "Signing failed: code {}", code),
            PqmagicError::Verification(code) => write!(f, "Verification failed: code {}", code),
            PqmagicError::SignMessage(code) => write!(f, "Sign message failed: code {}", code),
            PqmagicError::VerifyMessage(code) => write!(f, "Open signed message failed: code {}", code),
            PqmagicError::Encapsulation(code) => write!(f, "Encapsulation failed: code {}", code),
            PqmagicError::Decapsulation(code) => write!(f, "Decapsulation failed: code {}", code),
            PqmagicError::NotAKemAlgorithm(code) => write!(f, "{} is not a KEM algorithm", code),
            PqmagicError::NotASigAlgorithm(code) => write!(f, "{} is not a SIG algorithm", code),
        }
    }
}

impl std::error::Error for PqmagicError {}
