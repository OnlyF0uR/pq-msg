use pqcrypto_falcon::{
    falconpadded1024, falconpadded1024_keypair,
    ffi::{
        PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES,
        PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    },
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

use crate::errors::CryptoError;

/// Type alias for a public key byte array
pub type PublicKeyBytes = [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
/// Type alias for a secret key byte array
pub type SecretKeyBytes = [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES];

/// Common operations for verifying signatures
///
/// This trait provides methods for accessing public keys and verifying
/// signed messages with post-quantum cryptographic algorithms.
pub trait ViewOperations {
    /// Gets a reference to the public key
    fn pub_key(&self) -> &falconpadded1024::PublicKey;

    /// Gets a reference to the public key as a byte array
    fn pub_key_bytes(&self) -> &[u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES] {
        let id = unsafe {
            &*(self.pub_key().as_bytes().as_ptr()
                as *const [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES])
        };
        id
    }

    /// Verifies if a signature is valid for the provided message
    ///
    /// # Arguments
    /// * `msg` - The message that was signed
    /// * `sig` - The signature to verify
    ///
    /// # Returns
    /// - `Result<bool, CryptoError>`: True if signature is valid, false if invalid,
    ///   or an error if verification couldn't be completed
    fn verify_comp(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        if sig.len() != PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES + msg.len() {
            return Err(CryptoError::InvalidSignature);
        }

        let sm = falconpadded1024::SignedMessage::from_bytes(sig)?;
        let v_result = falconpadded1024::open(&sm, self.pub_key());
        if let Err(e) = v_result {
            if e.to_string().contains("verification failed") {
                return Ok(false);
            }

            return Err(CryptoError::UnknownVerificationError);
        }

        // Where v_result is the message
        Ok(v_result.unwrap() == msg)
    }

    /// Verifies a signature and returns the original message bytes
    ///
    /// # Arguments
    /// * `sig` - The signature bytes to verify
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The verified message or an error
    fn verify_message_bytes(&self, sig: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sig.len() < PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES {
            return Err(CryptoError::InvalidSignature);
        }

        let sm = falconpadded1024::SignedMessage::from_bytes(sig)?;
        match falconpadded1024::open(&sm, self.pub_key()) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                if e.to_string().contains("verification failed") {
                    return Err(CryptoError::InvalidSignature);
                }
                return Err(CryptoError::UnknownVerificationError);
            }
        }
    }

    /// Verifies a signature and returns the original message bytes
    ///
    /// # Arguments
    /// * `sm` - The signed message to verify
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The verified message or an error
    fn verify_message(&self, sm: &falconpadded1024::SignedMessage) -> Result<Vec<u8>, CryptoError> {
        match falconpadded1024::open(&sm, self.pub_key()) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                if e.to_string().contains("verification failed") {
                    return Err(CryptoError::InvalidSignature);
                }
                return Err(CryptoError::UnknownVerificationError);
            }
        }
    }
}

/// A key pair used only for signature verification
///
/// This struct represents a post-quantum cryptography key pair used only
/// for verifying signatures. It contains just the public key component.
pub struct VerifierPair {
    pub_key: falconpadded1024::PublicKey,
}

impl VerifierPair {
    /// Creates a new verifier pair from public key bytes
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    ///
    /// # Returns
    /// - `Result<VerifierPair, CryptoError>`: The constructed verifier or an error
    #[must_use]
    pub fn new(pub_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = falconpadded1024::PublicKey::from_bytes(pub_key)?;
        Ok(Self { pub_key })
    }

    /// Creates a new verifier pair from public key bytes (alias for new)
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    ///
    /// # Returns
    /// - `Result<VerifierPair, CryptoError>`: The constructed verifier or an error
    pub fn from_bytes(pub_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = falconpadded1024::PublicKey::from_bytes(pub_key)?;
        Ok(Self { pub_key })
    }

    /// Converts the public key to bytes
    ///
    /// # Returns
    /// A vector containing the public key bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pub_key.as_bytes().to_vec()
    }
}

impl ViewOperations for VerifierPair {
    fn pub_key(&self) -> &falconpadded1024::PublicKey {
        &self.pub_key
    }
}

/// A complete key pair used for both signing and verification
///
/// This struct represents a post-quantum cryptography key pair used for
/// creating digital signatures and verifying them. It contains both
/// public and secret key components using the Falcon-padded-1024 algorithm.
#[derive(Clone)]
pub struct SignerPair {
    pub_key: falconpadded1024::PublicKey,
    sec_key: falconpadded1024::SecretKey,
}

impl SignerPair {
    /// Creates a new random signer pair
    ///
    /// # Returns
    /// A new SignerPair with generated public and secret keys
    pub fn create() -> Self {
        let (pk, sk) = falconpadded1024_keypair();
        Self {
            pub_key: pk,
            sec_key: sk,
        }
    }

    /// Signs a message using this pair's secret key
    ///
    /// # Arguments
    /// * `msg` - The message to sign
    ///
    /// # Returns
    /// A signed message that can be verified by others
    pub fn sign(&self, msg: &[u8]) -> falconpadded1024::SignedMessage {
        falconpadded1024::sign(msg, &self.sec_key)
    }

    /// Creates a signer pair from separate public and secret key bytes
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    /// * `sec_key` - The secret key bytes
    ///
    /// # Returns
    /// - `Result<SignerPair, CryptoError>`: The constructed signer pair or an error
    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = falconpadded1024::PublicKey::from_bytes(pub_key)?;
        let sec_key = falconpadded1024::SecretKey::from_bytes(sec_key)?;
        Ok(Self { pub_key, sec_key })
    }

    /// Converts the key pair to raw byte arrays
    ///
    /// # Returns
    /// - `Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), CryptoError>`:
    ///   A tuple containing the public and secret keys as byte arrays
    pub fn to_bytes(
        &self,
    ) -> Result<
        (
            [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
            [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        ),
        CryptoError,
    > {
        Ok((
            self.pub_key.as_bytes().try_into()?,
            self.sec_key.as_bytes().try_into()?,
        ))
    }

    /// Converts the key pair to a single byte vector with public key followed by secret key
    ///
    /// # Returns
    /// A vector containing the concatenated public and secret key bytes
    pub fn to_bytes_uniform(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.pub_key.as_bytes());
        bytes.extend_from_slice(self.sec_key.as_bytes());
        bytes
    }

    /// Creates a signer pair from a single byte slice containing both public and secret keys
    ///
    /// # Arguments
    /// * `bytes` - The concatenated public and secret key bytes
    ///
    /// # Returns
    /// - `Result<SignerPair, CryptoError>`: The constructed signer pair or an error
    pub fn from_bytes_uniform(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len()
            != PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
        {
            return Err(CryptoError::IncongruentLength(
                PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                bytes.len(),
            ));
        }
        let pub_key = falconpadded1024::PublicKey::from_bytes(
            &bytes[..PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
        )?;
        let sec_key = falconpadded1024::SecretKey::from_bytes(
            &bytes[PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES..],
        )?;
        Ok(Self { pub_key, sec_key })
    }
}

impl ViewOperations for SignerPair {
    fn pub_key(&self) -> &falconpadded1024::PublicKey {
        &self.pub_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_sign() {
        let signer = SignerPair::create();
        let msg = b"Hello, World!";
        let sig = signer.sign(msg);

        assert!(signer.verify_comp(msg, &sig.as_bytes().to_vec()).unwrap());
    }

    #[test]
    fn test_verifier_verify() {
        let signer = SignerPair::create();
        let msg = b"Hello, World!";
        let sig = signer.sign(msg);

        let verifier = VerifierPair::new(signer.pub_key().as_bytes()).unwrap();
        assert!(verifier.verify_comp(msg, &sig.as_bytes().to_vec()).unwrap());
    }

    #[test]
    fn test_verify_message() {
        let signer = SignerPair::create();
        let msg = b"Hello, World!";
        let sig = signer.sign(msg);

        let verifier = VerifierPair::new(signer.pub_key().as_bytes()).unwrap();
        let verified_msg = verifier.verify_message(&sig).unwrap();

        assert_eq!(msg.to_vec(), verified_msg);
    }

    #[test]
    fn test_signer_bytes() {
        let signer = SignerPair::create();
        let (pub_key, sec_key) = signer.to_bytes().unwrap();

        let signer2 = SignerPair::from_bytes(&pub_key, &sec_key).unwrap();
        assert_eq!(signer.pub_key().as_bytes(), signer2.pub_key().as_bytes());
    }

    #[test]
    fn test_verifier_bytes() {
        let signer = SignerPair::create();
        let verifier = VerifierPair::new(signer.pub_key().as_bytes()).unwrap();
        let pub_key = verifier.to_bytes();

        let verifier2 = VerifierPair::from_bytes(&pub_key).unwrap();
        assert_eq!(
            verifier.pub_key().as_bytes(),
            verifier2.pub_key().as_bytes()
        );
    }
}
