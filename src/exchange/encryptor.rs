use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use pqcrypto_mlkem::mlkem1024::SharedSecret;

use crate::errors::CryptoError;

use super::pair::ss2b;

pub struct Encryptor {
    shared_secret: SharedSecret,
}

impl Encryptor {
    pub fn new(shared_secret: SharedSecret) -> Self {
        Self { shared_secret }
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 24 {
            return Err(CryptoError::IncongruentLength(24, nonce.len()));
        }

        let ss = ss2b(&self.shared_secret);
        let cipher = XChaCha20Poly1305::new_from_slice(&ss)?;
        let nonce = XNonce::from_slice(nonce);

        let ciphertext = cipher.encrypt(nonce, plaintext)?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 24 {
            return Err(CryptoError::IncongruentLength(24, nonce.len()));
        }

        let ss = ss2b(&self.shared_secret);
        let cipher = XChaCha20Poly1305::new_from_slice(&ss)?;
        let nonce = XNonce::from_slice(nonce);

        Ok(cipher.decrypt(nonce, ciphertext)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::exchange::pair::b2ss;

    use super::*;

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
