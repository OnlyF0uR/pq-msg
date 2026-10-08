use sha2::{Digest, Sha256};

use crate::{
    errors::CryptoError,
    exchange::pair::{self, KEMPair},
    signatures::keypair::{self, PublicKeyBytes, SignerPair, VerifierPair, ViewOperations},
};

/// Label prepended to a prekey before it is signed, so a prekey signature can
/// never be mistaken for a message signature
const PREKEY_LABEL: &[u8] = b"pq-msg/v2 prekey";

/// Size of a serialized signed prekey in bytes
pub const SIGNED_PREKEY_BYTES: usize = pair::PUBLIC_KEY_BYTES + keypair::SIGNATURE_BYTES;

/// Identifies a prekey: the SHA-256 hash of its public key
pub type PrekeyId = [u8; 32];

/// The public half of a prekey, signed by its owner's FN-DSA identity key
///
/// A prekey is an ordinary [`KEMPair`] that a responder creates ahead of time.
/// The responder keeps the `KEMPair` and publishes this signed public part, for
/// example on a server. An initiator starts a session by encapsulating to it.
///
/// There are two kinds, and the difference is only how the responder treats them:
/// - **One-time prekeys** are used for a single session. Once the session is set
///   up, the responder deletes the `KEMPair` everywhere it is stored. After that,
///   nothing can decrypt that session's handshake, which gives forward secrecy.
/// - A **last-resort prekey** is used whenever no one-time prekey is left. It is
///   reused, so sessions using it only gain forward secrecy once the responder
///   replaces it and deletes the old one. Rotate it regularly (for example weekly).
#[derive(Clone)]
pub struct SignedPrekey {
    kem_pub_key: [u8; pair::PUBLIC_KEY_BYTES],
    signature: keypair::SignatureBytes,
}

impl SignedPrekey {
    /// Signs the public key of `prekey` with the owner's identity key
    ///
    /// # Arguments
    /// * `owner` - The identity signer pair of the prekey's owner
    /// * `prekey` - The prekey to publish
    ///
    /// # Returns
    /// - `Result<SignedPrekey, CryptoError>`: The signed prekey or an error
    pub fn new(owner: &mut SignerPair, prekey: &KEMPair) -> Result<Self, CryptoError> {
        let kem_pub_key = prekey.pub_key_bytes();
        let signature = owner.sign(&signed_data(&kem_pub_key))?;
        Ok(Self {
            kem_pub_key,
            signature,
        })
    }

    /// Checks that this prekey was signed by the owner of `identity`
    ///
    /// # Arguments
    /// * `identity` - The FN-DSA public key of the claimed owner
    ///
    /// # Returns
    /// True if the signature is valid for this identity, false otherwise
    pub fn verify(&self, identity: &PublicKeyBytes) -> bool {
        VerifierPair::new(identity)
            .is_ok_and(|v| v.verify(&signed_data(&self.kem_pub_key), &self.signature))
    }

    /// Returns the identifier the responder uses to find the matching `KEMPair`
    pub fn id(&self) -> PrekeyId {
        Sha256::digest(self.kem_pub_key).into()
    }

    /// Returns the prekey's ML-KEM public key
    pub fn kem_pub_key(&self) -> &[u8; pair::PUBLIC_KEY_BYTES] {
        &self.kem_pub_key
    }

    /// Serializes the signed prekey: public key followed by signature
    pub fn to_bytes(&self) -> [u8; SIGNED_PREKEY_BYTES] {
        let mut bytes = [0u8; SIGNED_PREKEY_BYTES];
        bytes[..pair::PUBLIC_KEY_BYTES].copy_from_slice(&self.kem_pub_key);
        bytes[pair::PUBLIC_KEY_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    /// Deserializes a signed prekey
    ///
    /// This only checks the length. Call [`SignedPrekey::verify`] (as
    /// `MessageSession::new_initiator` does) before trusting it.
    ///
    /// # Arguments
    /// * `bytes` - The serialized signed prekey
    ///
    /// # Returns
    /// - `Result<SignedPrekey, CryptoError>`: The signed prekey or an error
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SIGNED_PREKEY_BYTES {
            return Err(CryptoError::IncongruentLength(
                SIGNED_PREKEY_BYTES,
                bytes.len(),
            ));
        }
        let (kem_pub_key, signature) = bytes.split_at(pair::PUBLIC_KEY_BYTES);
        Ok(Self {
            kem_pub_key: kem_pub_key.try_into()?,
            signature: signature.try_into()?,
        })
    }
}

/// The bytes signed for a prekey: label || public key
fn signed_data(kem_pub_key: &[u8; pair::PUBLIC_KEY_BYTES]) -> Vec<u8> {
    [PREKEY_LABEL, &kem_pub_key[..]].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_prekey() {
        let mut owner = SignerPair::create();
        let prekey = KEMPair::create();
        let signed = SignedPrekey::new(&mut owner, &prekey).unwrap();

        assert!(signed.verify(owner.pub_key_bytes()));
        assert!(!signed.verify(SignerPair::create().pub_key_bytes()));
        let mut undecodable = *owner.pub_key_bytes();
        undecodable[0] ^= 0xFF;
        assert!(!signed.verify(&undecodable));
        assert_eq!(signed.kem_pub_key(), &prekey.pub_key_bytes());

        let restored = SignedPrekey::from_bytes(&signed.to_bytes()).unwrap();
        assert!(restored.verify(owner.pub_key_bytes()));
        assert_eq!(restored.id(), signed.id());
        assert_ne!(signed.id(), {
            let other = KEMPair::create();
            SignedPrekey::new(&mut owner, &other).unwrap().id()
        });
    }

    #[test]
    fn test_swapped_kem_key_rejected() {
        // Someone (e.g. a malicious server) swaps in their own KEM key under the owner's signature
        let mut owner = SignerPair::create();
        let signed = SignedPrekey::new(&mut owner, &KEMPair::create()).unwrap();

        let mut bytes = signed.to_bytes();
        bytes[..pair::PUBLIC_KEY_BYTES].copy_from_slice(&KEMPair::create().pub_key_bytes());
        let swapped = SignedPrekey::from_bytes(&bytes).unwrap();
        assert!(!swapped.verify(owner.pub_key_bytes()));

        assert!(matches!(
            SignedPrekey::from_bytes(&bytes[1..]),
            Err(CryptoError::IncongruentLength(SIGNED_PREKEY_BYTES, _))
        ));
    }

    #[test]
    fn test_validly_signed_invalid_kem_key_rejected() {
        // A malicious peer signs a KEM key that isn't valid ML-KEM; starting a
        // session with it must fail cleanly
        let mut owner = SignerPair::create();
        let kem_pub_key = [0xFF; pair::PUBLIC_KEY_BYTES];
        let bad = SignedPrekey {
            kem_pub_key,
            signature: owner.sign(&signed_data(&kem_pub_key)).unwrap(),
        };
        assert!(bad.verify(owner.pub_key_bytes()));

        let result = crate::messaging::MessageSession::new_initiator(
            SignerPair::create(),
            [0u8; 24],
            &bad,
            owner.pub_key_bytes(),
        );
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }
}
