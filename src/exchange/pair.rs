use ml_kem::{
    DecapsulationKey1024, EncapsulationKey1024, KeyExport, MlKem1024,
    kem::{Decapsulate, Encapsulate, Kem},
};
use zeroize::Zeroizing;

use crate::errors::CryptoError;

/// Size of an ML-KEM-1024 public (encapsulation) key in bytes
pub const PUBLIC_KEY_BYTES: usize = 1568;
/// Size of an ML-KEM-1024 secret key in bytes (the 64-byte FIPS 203 seed)
pub const SECRET_KEY_BYTES: usize = 64;
/// Size of an ML-KEM-1024 ciphertext in bytes
pub const CIPHERTEXT_BYTES: usize = 1568;
/// Size of an ML-KEM shared secret in bytes
pub const SHARED_SECRET_BYTES: usize = 32;

/// A shared secret that is wiped from memory when dropped
pub type SharedSecret = Zeroizing<[u8; SHARED_SECRET_BYTES]>;

/// A Key Encapsulation Mechanism (KEM) pair using ML-KEM (formerly Kyber)
///
/// This struct represents a post-quantum cryptography key pair used for
/// key encapsulation and decapsulation operations. It utilizes ML-KEM-1024,
/// which provides 256-bit equivalent security strength.
/// The secret key is wiped from memory when the pair is dropped.
pub struct KEMPair {
    sec_key: DecapsulationKey1024,
}

impl KEMPair {
    /// Creates a new random KEM pair
    ///
    /// # Returns
    /// A new KEMPair with generated public and secret keys
    pub fn create() -> Self {
        let (sec_key, _) = MlKem1024::generate_keypair();
        Self { sec_key }
    }

    /// Creates a KEM pair from separate public and secret key bytes
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    /// * `sec_key` - The secret key bytes (64-byte seed)
    ///
    /// # Returns
    /// - `Result<KEMPair, CryptoError>`: The constructed KEMPair, or an error if
    ///   the lengths are wrong or the public key does not belong to the secret key
    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, CryptoError> {
        let seed: Zeroizing<[u8; SECRET_KEY_BYTES]> = Zeroizing::new(
            sec_key
                .try_into()
                .map_err(|_| CryptoError::IncongruentLength(SECRET_KEY_BYTES, sec_key.len()))?,
        );
        let pair = Self {
            sec_key: DecapsulationKey1024::from_seed((*seed).into()),
        };
        if pair.pub_key_bytes()[..] != *pub_key {
            return Err(CryptoError::InvalidKey);
        }
        Ok(pair)
    }

    /// Returns the public key bytes, which are shared with peers
    pub fn pub_key_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.sec_key.encapsulation_key().to_bytes().into()
    }

    /// Converts the key pair to raw byte arrays
    ///
    /// # Returns
    /// A tuple containing the public key and the secret key (wiped when dropped)
    pub fn to_bytes(&self) -> ([u8; PUBLIC_KEY_BYTES], Zeroizing<[u8; SECRET_KEY_BYTES]>) {
        (
            self.pub_key_bytes(),
            Zeroizing::new(self.sec_key.to_bytes().into()),
        )
    }

    /// Converts the key pair to a single byte vector with public key followed by secret key
    ///
    /// # Returns
    /// A vector containing the concatenated public and secret key bytes (wiped when dropped)
    pub fn to_bytes_uniform(&self) -> Zeroizing<Vec<u8>> {
        let (pub_key, sec_key) = self.to_bytes();
        Zeroizing::new([&pub_key[..], &sec_key[..]].concat())
    }

    /// Creates a KEM pair from a single byte slice containing both public and secret keys
    ///
    /// # Arguments
    /// * `bytes` - The concatenated public and secret key bytes
    ///
    /// # Returns
    /// - `Result<KEMPair, CryptoError>`: The constructed KEMPair or an error
    pub fn from_bytes_uniform(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_KEY_BYTES + SECRET_KEY_BYTES {
            return Err(CryptoError::IncongruentLength(
                PUBLIC_KEY_BYTES + SECRET_KEY_BYTES,
                bytes.len(),
            ));
        }
        let (pub_key, sec_key) = bytes.split_at(PUBLIC_KEY_BYTES);
        Self::from_bytes(pub_key, sec_key)
    }

    /// Encapsulates a fresh shared secret for the holder of `receiver_pubkey`
    ///
    /// # Arguments
    /// * `receiver_pubkey` - The receiver's public key
    ///
    /// # Returns
    /// - `Result<(SharedSecret, [u8; CIPHERTEXT_BYTES]), CryptoError>`: The shared secret
    ///   and the ciphertext to send to the receiver, or an error if the key is invalid
    pub fn encapsulate(
        receiver_pubkey: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<(SharedSecret, [u8; CIPHERTEXT_BYTES]), CryptoError> {
        let ek = EncapsulationKey1024::new(receiver_pubkey.into())
            .map_err(|_| CryptoError::InvalidKey)?;
        let (ciphertext, shared_secret) = ek.encapsulate();
        Ok((Zeroizing::new(shared_secret.into()), ciphertext.into()))
    }

    /// Decapsulates a shared secret from the provided ciphertext using this pair's secret key
    ///
    /// ML-KEM uses implicit rejection: a tampered ciphertext yields an unrelated
    /// secret instead of an error, so a mismatch only shows up once decryption fails.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext received from the sender
    ///
    /// # Returns
    /// The decapsulated shared secret
    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> SharedSecret {
        Zeroizing::new(self.sec_key.decapsulate(ciphertext.into()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair() {
        let keypair = KEMPair::create();
        let (pub_key, sec_key) = keypair.to_bytes();
        let new_keypair = KEMPair::from_bytes(&pub_key, &sec_key[..]).unwrap();
        assert_eq!(keypair.to_bytes_uniform(), new_keypair.to_bytes_uniform());

        let uniform = KEMPair::from_bytes_uniform(&keypair.to_bytes_uniform()).unwrap();
        assert_eq!(keypair.to_bytes_uniform(), uniform.to_bytes_uniform());
    }

    #[test]
    fn test_from_bytes_rejects_foreign_pubkey() {
        let keypair = KEMPair::create();
        let other = KEMPair::create();
        let result = KEMPair::from_bytes(&other.pub_key_bytes(), &keypair.to_bytes().1[..]);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
        assert!(matches!(
            KEMPair::from_bytes(&keypair.pub_key_bytes(), &[0u8; 10]),
            Err(CryptoError::IncongruentLength(SECRET_KEY_BYTES, 10))
        ));
    }

    #[test]
    fn test_invalid_inputs() {
        let keypair = KEMPair::create();

        assert!(matches!(
            KEMPair::from_bytes_uniform(&[0u8; 10]),
            Err(CryptoError::IncongruentLength(n, 10)) if n == PUBLIC_KEY_BYTES + SECRET_KEY_BYTES
        ));
        // A truncated public key can't match the secret key
        assert!(matches!(
            KEMPair::from_bytes(&keypair.pub_key_bytes()[1..], &keypair.to_bytes().1[..]),
            Err(CryptoError::InvalidKey)
        ));
        // Not a valid ML-KEM public key: coefficients out of range
        assert!(matches!(
            KEMPair::encapsulate(&[0xFF; PUBLIC_KEY_BYTES]),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let receiver = KEMPair::create();

        let (shared_secret, ciphertext) = KEMPair::encapsulate(&receiver.pub_key_bytes()).unwrap();
        let dec_shared_secret = receiver.decapsulate(&ciphertext);

        assert_eq!(
            shared_secret, dec_shared_secret,
            "Difference in shared secrets!"
        );

        // A different receiver gets an unrelated secret (implicit rejection)
        assert_ne!(shared_secret, KEMPair::create().decapsulate(&ciphertext));
    }
}
