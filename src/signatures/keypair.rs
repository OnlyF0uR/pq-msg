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

pub type PublicKeyBytes = [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
pub type SecretKeyBytes = [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES];

pub trait ViewOperations {
    fn pub_key(&self) -> &falconpadded1024::PublicKey;
    fn pub_key_bytes(&self) -> &[u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES] {
        let id = unsafe {
            &*(self.pub_key().as_bytes().as_ptr()
                as *const [u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES])
        };
        id
    }
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

pub struct VerifierPair {
    pub_key: falconpadded1024::PublicKey,
}

impl VerifierPair {
    #[must_use]
    pub fn new(pub_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = falconpadded1024::PublicKey::from_bytes(pub_key)?;
        Ok(Self { pub_key })
    }

    pub fn from_bytes(pub_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = falconpadded1024::PublicKey::from_bytes(pub_key)?;
        Ok(Self { pub_key })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pub_key.as_bytes().to_vec()
    }
}

impl ViewOperations for VerifierPair {
    fn pub_key(&self) -> &falconpadded1024::PublicKey {
        &self.pub_key
    }
}

#[derive(Clone)]
pub struct SignerPair {
    pub_key: falconpadded1024::PublicKey,
    sec_key: falconpadded1024::SecretKey,
}

impl SignerPair {
    pub fn create() -> Self {
        let (pk, sk) = falconpadded1024_keypair();
        Self {
            pub_key: pk,
            sec_key: sk,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> falconpadded1024::SignedMessage {
        falconpadded1024::sign(msg, &self.sec_key)
    }

    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = falconpadded1024::PublicKey::from_bytes(pub_key)?;
        let sec_key = falconpadded1024::SecretKey::from_bytes(sec_key)?;
        Ok(Self { pub_key, sec_key })
    }

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

    pub fn to_bytes_uniform(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.pub_key.as_bytes());
        bytes.extend_from_slice(self.sec_key.as_bytes());
        bytes
    }

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
