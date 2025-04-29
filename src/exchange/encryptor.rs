use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use pqcrypto_mlkem::mlkem1024::SharedSecret;

use crate::errors::CryptoError;

use super::pair::ss2b;

/// An encryptor utilizing XChaCha20Poly1305 authenticated encryption with a Kyber shared secret
///
/// This struct provides an interface for encrypting and decrypting data using
/// a post-quantum shared secret established via ML-KEM (formerly Kyber).
/// It uses XChaCha20Poly1305 for authenticated encryption with associated data (AEAD).
pub struct Encryptor {
    /// The ML-KEM shared secret used to derive the encryption key
    shared_secret: SharedSecret,
}

impl Encryptor {
    /// Creates a new encryptor with the given shared secret
    ///
    /// # Arguments
    /// * `shared_secret` - The ML-KEM shared secret to use for encryption/decryption
    ///
    /// # Returns
    /// A new Encryptor instance initialized with the provided shared secret
    pub fn new(shared_secret: SharedSecret) -> Self {
        Self { shared_secret }
    }

    /// Encrypts plaintext using XChaCha20Poly1305 with the stored shared secret
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `nonce` - A 24-byte nonce (must be unique for each encryption with the same key)
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The encrypted ciphertext or an error
    ///
    /// # Security Notes
    /// - The nonce must never be reused with the same key
    /// - The ciphertext includes an authentication tag to verify integrity
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, CryptoError> {
        let ss = ss2b(&self.shared_secret);
        let cipher = XChaCha20Poly1305::new_from_slice(&ss)?;
        let nonce = XNonce::from_slice(nonce);

        let ciphertext = cipher.encrypt(nonce, plaintext)?;
        Ok(ciphertext)
    }

    /// Decrypts ciphertext using XChaCha20Poly1305 with the stored shared secret
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `nonce` - The 24-byte nonce used during encryption
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The decrypted plaintext or an error
    ///
    /// # Security Notes
    /// - This function will return an error if the ciphertext has been tampered with
    /// - The same nonce used for encryption must be provided for decryption
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, CryptoError> {
        let ss = ss2b(&self.shared_secret);
        let cipher = XChaCha20Poly1305::new_from_slice(&ss)?;
        let nonce = XNonce::from_slice(nonce);

        Ok(cipher.decrypt(nonce, ciphertext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::pair::b2ss;

    #[test]
    fn test_encryption_decryption() {
        let mock_ss_bytes = [0u8; 32];
        let shared_secret = b2ss(&mock_ss_bytes);

        let encryptor = Encryptor::new(shared_secret);

        let plaintext = b"Hello, world!";
        let nonce = b"the length of this is 24";

        let ciphertext = encryptor.encrypt(plaintext, nonce).unwrap();
        let decrypted_plaintext = encryptor.decrypt(&ciphertext, nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }
}
