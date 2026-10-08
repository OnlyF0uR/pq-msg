use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};

use crate::errors::CryptoError;

/// An encryptor utilizing XChaCha20Poly1305 authenticated encryption
///
/// This struct provides an interface for encrypting and decrypting data using
/// a 32-byte symmetric key. It uses XChaCha20Poly1305 for authenticated
/// encryption with associated data (AEAD). The key is wiped from memory on drop.
///
/// Derive the key with a KDF (as `MessageSession` does) rather than using a raw
/// KEM shared secret, and never let two parties encrypt under the same key.
pub struct Encryptor {
    cipher: XChaCha20Poly1305,
}

impl Encryptor {
    /// Creates a new encryptor with the given key
    ///
    /// # Arguments
    /// * `key` - The 32-byte key to use for encryption/decryption
    ///
    /// # Returns
    /// A new Encryptor instance initialized with the provided key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }

    /// Encrypts plaintext using XChaCha20Poly1305 with the stored key
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
        Ok(self.cipher.encrypt(nonce.into(), plaintext)?)
    }

    /// Decrypts ciphertext using XChaCha20Poly1305 with the stored key
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
        Ok(self.cipher.decrypt(nonce.into(), ciphertext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let encryptor = Encryptor::new(&[7u8; 32]);

        let plaintext = b"Hello, world!";
        let nonce = b"the length of this is 24";

        let mut ciphertext = encryptor.encrypt(plaintext, nonce).unwrap();
        let decrypted_plaintext = encryptor.decrypt(&ciphertext, nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        // Tampering is detected
        ciphertext[0] ^= 1;
        assert!(encryptor.decrypt(&ciphertext, nonce).is_err());
    }
}
