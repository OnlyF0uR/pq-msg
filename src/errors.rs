use std::array::TryFromSliceError;

use pqcrypto_falcon::ffi::PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug)]
pub enum CryptoError {
    InvalidSignature,
    UnknownVerificationError,
    PQCryptoError(pqcrypto_traits::Error),
    InvalidKeyLength(crypto_common::InvalidLength),
    ChaCha20Poly1305EncryptionError(chacha20poly1305::Error),
    IncongruentLength(usize, usize),
    FalconSignatureTooShort(usize),
    SignatureVerificationFailed,
    TryFromSliceError(TryFromSliceError),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::PQCryptoError(e) => e.fmt(f),
            CryptoError::UnknownVerificationError => write!(f, "Unknown verification error"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidKeyLength(e) => e.fmt(f),
            CryptoError::ChaCha20Poly1305EncryptionError(e) => e.fmt(f),
            CryptoError::IncongruentLength(expected, actual) => {
                write!(
                    f,
                    "Incongruent length: expected {}, got {}",
                    expected, actual
                )
            }
            CryptoError::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
            CryptoError::FalconSignatureTooShort(len) => {
                write!(
                    f,
                    "Signature too short: expected at least {} bytes, got {}",
                    PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES, len
                )
            }
            CryptoError::TryFromSliceError(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<pqcrypto_traits::Error> for CryptoError {
    fn from(e: pqcrypto_traits::Error) -> Self {
        CryptoError::PQCryptoError(e)
    }
}

impl From<crypto_common::InvalidLength> for CryptoError {
    fn from(e: crypto_common::InvalidLength) -> Self {
        CryptoError::InvalidKeyLength(e)
    }
}

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
