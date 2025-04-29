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

pub struct KEMPair {
    pub_key: mlkem1024::PublicKey,
    sec_key: mlkem1024::SecretKey,
}

impl KEMPair {
    pub fn create() -> Self {
        let (pk, sk) = mlkem1024_keypair();
        Self {
            pub_key: pk,
            sec_key: sk,
        }
    }

    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key = mlkem1024::PublicKey::from_bytes(pub_key)?;
        let sec_key = mlkem1024::SecretKey::from_bytes(sec_key)?;
        Ok(Self { pub_key, sec_key })
    }

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

    pub fn to_bytes_uniform(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.pub_key.as_bytes());
        bytes.extend_from_slice(self.sec_key.as_bytes());
        bytes
    }

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

    pub fn encapsulate(
        &self,
        receiver_pubkey: &mlkem1024::PublicKey,
    ) -> (SharedSecret, mlkem1024::Ciphertext) {
        mlkem1024_encapsulate(receiver_pubkey)
    }

    pub fn decapsulate(
        &self,
        ciphertext: &mlkem1024::Ciphertext,
    ) -> Result<SharedSecret, CryptoError> {
        let shared_secret = mlkem1024_decapsulate(ciphertext, &self.sec_key);
        Ok(shared_secret)
    }
}

pub fn ss2b(ss: &SharedSecret) -> [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES] {
    unsafe { *(ss as *const SharedSecret as *const [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES]) }
}

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
