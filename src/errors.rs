use std::array::TryFromSliceError;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug)]
pub enum CryptoError {
    InvalidSignature,
    /// Key bytes failed to decode, or a public key does not belong to its secret key
    InvalidKey,
    ChaCha20Poly1305EncryptionError(chacha20poly1305::Error),
    IncongruentLength(usize, usize),
    /// The session's message counter is used up; start a new session
    NonceExhausted,
    /// Serialized session has an unknown version or a malformed field
    InvalidSession,
    TryFromSliceError(TryFromSliceError),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidKey => write!(f, "Invalid key"),
            CryptoError::ChaCha20Poly1305EncryptionError(e) => e.fmt(f),
            CryptoError::IncongruentLength(expected, actual) => {
                write!(
                    f,
                    "Incongruent length: expected {}, got {}",
                    expected, actual
                )
            }
            CryptoError::NonceExhausted => {
                write!(f, "Nonce counter exhausted, start a new session")
            }
            CryptoError::InvalidSession => write!(f, "Invalid serialized session"),
            CryptoError::TryFromSliceError(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<chacha20poly1305::Error> for CryptoError {
    fn from(e: chacha20poly1305::Error) -> Self {
        CryptoError::ChaCha20Poly1305EncryptionError(e)
    }
}

impl From<TryFromSliceError> for CryptoError {
    fn from(e: TryFromSliceError) -> Self {
        CryptoError::TryFromSliceError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(
            CryptoError::InvalidSignature.to_string(),
            "Invalid signature"
        );
        assert_eq!(CryptoError::InvalidKey.to_string(), "Invalid key");
        assert_eq!(
            CryptoError::IncongruentLength(32, 31).to_string(),
            "Incongruent length: expected 32, got 31"
        );
        assert_eq!(
            CryptoError::NonceExhausted.to_string(),
            "Nonce counter exhausted, start a new session"
        );
        assert_eq!(
            CryptoError::InvalidSession.to_string(),
            "Invalid serialized session"
        );

        let aead = chacha20poly1305::Error;
        assert_eq!(CryptoError::from(aead).to_string(), aead.to_string());
        let slice = <[u8; 2]>::try_from(&[0u8; 1][..]).unwrap_err();
        assert_eq!(CryptoError::from(slice).to_string(), slice.to_string());
    }
}
