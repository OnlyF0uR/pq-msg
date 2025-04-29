use pqcrypto_mlkem::{
    ffi::{
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES, PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    },
    mlkem1024::{self, SharedSecret},
    mlkem1024_decapsulate, mlkem1024_encapsulate, mlkem1024_keypair,
};
use pqcrypto_traits::kem::{PublicKey, SecretKey};

use crate::errors::CryptoError;

/// A Key Encapsulation Mechanism (KEM) pair using ML-KEM (formerly Kyber)
///
/// This struct represents a post-quantum cryptography key pair used for
/// key encapsulation and decapsulation operations. It utilizes ML-KEM1024,
/// which provides 256-bit equivalent security strength.
pub struct KEMPair {
    pub_key: mlkem1024::PublicKey,
    sec_key: mlkem1024::SecretKey,
}

impl KEMPair {
    /// Creates a new random KEM pair
    ///
    /// # Returns
    /// A new KEMPair with generated public and secret keys
    pub fn create() -> Self {
        let (pk, sk) = mlkem1024_keypair();
        Self {
            pub_key: pk,
            sec_key: sk,
        }
    }

    /// Creates a KEM pair from separate public and secret key bytes
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    /// * `sec_key` - The secret key bytes
    ///
    /// # Returns
    /// - `Result<KEMPair, CryptoError>`: The constructed KEMPair or an error
    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = mlkem1024::PublicKey::from_bytes(pub_key)?;
        let sec_key = mlkem1024::SecretKey::from_bytes(sec_key)?;
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
            [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
            [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES],
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

    /// Creates a KEM pair from a single byte slice containing both public and secret keys
    ///
    /// # Arguments
    /// * `bytes` - The concatenated public and secret key bytes
    ///
    /// # Returns
    /// - `Result<KEMPair, CryptoError>`: The constructed KEMPair or an error
    pub fn from_bytes_uniform(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len()
            != PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
        {
            return Err(CryptoError::IncongruentLength(
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                bytes.len(),
            ));
        }
        let pub_key = mlkem1024::PublicKey::from_bytes(
            &bytes[..PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
        )?;
        let sec_key = mlkem1024::SecretKey::from_bytes(
            &bytes[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES..],
        )?;
        Ok(Self { pub_key, sec_key })
    }

    /// Encapsulates a shared secret using the provided public key
    ///
    /// # Arguments
    /// * `receiver_pubkey` - The receiver's public key
    ///
    /// # Returns
    /// A tuple containing the shared secret and the ciphertext to send to the receiver
    pub fn encapsulate(
        &self,
        receiver_pubkey: &mlkem1024::PublicKey,
    ) -> (SharedSecret, mlkem1024::Ciphertext) {
        mlkem1024_encapsulate(receiver_pubkey)
    }

    /// Decapsulates a shared secret from the provided ciphertext using this pair's secret key
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext received from the sender
    ///
    /// # Returns
    /// - `Result<SharedSecret, CryptoError>`: The decapsulated shared secret or an error
    pub fn decapsulate(
        &self,
        ciphertext: &mlkem1024::Ciphertext,
    ) -> Result<SharedSecret, CryptoError> {
        let shared_secret = mlkem1024_decapsulate(ciphertext, &self.sec_key);
        Ok(shared_secret)
    }
}

/// Converts a SharedSecret to a byte array
///
/// # Arguments
/// * `ss` - The SharedSecret to convert
///
/// # Returns
/// A byte array representation of the shared secret
pub fn ss2b(ss: &SharedSecret) -> [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES] {
    unsafe { *(ss as *const SharedSecret as *const [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES]) }
}

/// Converts a byte array to a SharedSecret
///
/// # Arguments
/// * `bytes` - The byte array to convert
///
/// # Returns
/// A SharedSecret created from the provided bytes
pub fn b2ss(bytes: &[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES]) -> SharedSecret {
    unsafe {
        std::ptr::read(
            bytes as *const [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES] as *const SharedSecret,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair() {
        let keypair = KEMPair::create();
        let (pub_key, sec_key) = keypair.to_bytes().unwrap();
        let new_keypair = KEMPair::from_bytes(&pub_key, &sec_key).unwrap();
        assert_eq!(keypair.pub_key.as_bytes(), new_keypair.pub_key.as_bytes());
        assert_eq!(keypair.sec_key.as_bytes(), new_keypair.sec_key.as_bytes());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let sender = KEMPair::create();
        let receiver = KEMPair::create();

        let (shared_secret, ciphertext) = sender.encapsulate(&receiver.pub_key);
        let dec_shared_secret = receiver.decapsulate(&ciphertext).unwrap();

        let ss1 = ss2b(&shared_secret);
        let ss2 = ss2b(&dec_shared_secret);

        assert_eq!(ss1, ss2, "Difference in shared secrets!");
    }
}
