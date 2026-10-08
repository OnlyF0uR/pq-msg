use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard, sign_key_size,
    signature_size, vrfy_key_size,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::errors::CryptoError;

/// Size of an FN-DSA-1024 public (verifying) key in bytes
pub const PUBLIC_KEY_BYTES: usize = vrfy_key_size(FN_DSA_LOGN_1024);
/// Size of an FN-DSA-1024 secret (signing) key in bytes
pub const SECRET_KEY_BYTES: usize = sign_key_size(FN_DSA_LOGN_1024);
/// Size of an FN-DSA-1024 signature in bytes
pub const SIGNATURE_BYTES: usize = signature_size(FN_DSA_LOGN_1024);

/// Type alias for a public key byte array
pub type PublicKeyBytes = [u8; PUBLIC_KEY_BYTES];
/// Type alias for a secret key byte array
pub type SecretKeyBytes = [u8; SECRET_KEY_BYTES];
/// Type alias for a signature byte array
pub type SignatureBytes = [u8; SIGNATURE_BYTES];

/// Common operations for verifying signatures
///
/// This trait provides methods for accessing public keys and verifying
/// detached signatures with FN-DSA (Falcon).
pub trait ViewOperations {
    /// Gets a reference to the public key as a byte array
    fn pub_key_bytes(&self) -> &PublicKeyBytes;

    /// Verifies if a detached signature is valid for the provided message
    ///
    /// # Arguments
    /// * `msg` - The message that was signed
    /// * `sig` - The signature to verify
    ///
    /// # Returns
    /// True if the signature is valid for this public key, false otherwise
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        VerifyingKeyStandard::decode(self.pub_key_bytes())
            .is_some_and(|vk| vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg))
    }
}

/// A key pair used only for signature verification
///
/// This struct represents a post-quantum cryptography key pair used only
/// for verifying signatures. It contains just the public key component.
#[derive(Clone)]
pub struct VerifierPair {
    pub_key: PublicKeyBytes,
}

impl VerifierPair {
    /// Creates a new verifier pair from public key bytes
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    ///
    /// # Returns
    /// - `Result<VerifierPair, CryptoError>`: The constructed verifier, or an error
    ///   if the key has the wrong length or does not decode
    pub fn new(pub_key: &[u8]) -> Result<Self, CryptoError> {
        let pub_key: PublicKeyBytes = pub_key
            .try_into()
            .map_err(|_| CryptoError::IncongruentLength(PUBLIC_KEY_BYTES, pub_key.len()))?;
        VerifyingKeyStandard::decode(&pub_key).ok_or(CryptoError::InvalidKey)?;
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
        Self::new(pub_key)
    }

    /// Converts the public key to bytes
    ///
    /// # Returns
    /// The public key bytes
    pub fn to_bytes(&self) -> PublicKeyBytes {
        self.pub_key
    }
}

impl ViewOperations for VerifierPair {
    fn pub_key_bytes(&self) -> &PublicKeyBytes {
        &self.pub_key
    }
}

/// A complete key pair used for both signing and verification
///
/// This struct represents a post-quantum cryptography key pair used for
/// creating digital signatures and verifying them. It contains both
/// public and secret key components using FN-DSA-1024 (Falcon).
/// The secret key is wiped from memory when the pair (or any clone) is dropped.
pub struct SignerPair {
    pub_key: PublicKeyBytes,
    sec_key: Zeroizing<SecretKeyBytes>,
    /// The decoded secret key, kept so signing doesn't re-decode it every time
    signing_key: Box<SigningKeyStandard>,
}

impl SignerPair {
    /// Creates a new random signer pair
    ///
    /// # Returns
    /// A new SignerPair with generated public and secret keys
    pub fn create() -> Self {
        let mut pub_key = [0u8; PUBLIC_KEY_BYTES];
        let mut sec_key = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
        KeyPairGeneratorStandard::default().keygen(
            FN_DSA_LOGN_1024,
            &mut OsRng,
            &mut sec_key[..],
            &mut pub_key,
        );
        let signing_key = decode_signing_key(&sec_key).expect("freshly generated key decodes");
        Self {
            pub_key,
            sec_key,
            signing_key,
        }
    }

    /// Signs a message using this pair's secret key
    ///
    /// # Arguments
    /// * `msg` - The message to sign
    ///
    /// # Returns
    /// - `Result<SignatureBytes, CryptoError>`: A detached signature, or an error
    ///   if the secret key is invalid
    pub fn sign(&mut self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let mut sig = [0u8; SIGNATURE_BYTES];
        self.signing_key
            .sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig)
            .ok_or(CryptoError::InvalidKey)?;
        Ok(sig)
    }

    /// Creates a signer pair from separate public and secret key bytes
    ///
    /// # Arguments
    /// * `pub_key` - The public key bytes
    /// * `sec_key` - The secret key bytes
    ///
    /// # Returns
    /// - `Result<SignerPair, CryptoError>`: The constructed signer pair, or an error if
    ///   the secret key does not decode or the public key does not belong to it
    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, CryptoError> {
        let sec_key: Zeroizing<SecretKeyBytes> = Zeroizing::new(
            sec_key
                .try_into()
                .map_err(|_| CryptoError::IncongruentLength(SECRET_KEY_BYTES, sec_key.len()))?,
        );
        let signing_key = decode_signing_key(&sec_key).ok_or(CryptoError::InvalidKey)?;
        let mut derived = [0u8; PUBLIC_KEY_BYTES];
        signing_key.to_verifying_key(&mut derived);
        if derived[..] != *pub_key {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            pub_key: derived,
            sec_key,
            signing_key,
        })
    }

    /// Converts the key pair to raw byte arrays
    ///
    /// # Returns
    /// A tuple containing the public key and the secret key (wiped when dropped)
    pub fn to_bytes(&self) -> (PublicKeyBytes, Zeroizing<SecretKeyBytes>) {
        (self.pub_key, self.sec_key.clone())
    }

    /// Converts the key pair to a single byte vector with public key followed by secret key
    ///
    /// # Returns
    /// A vector containing the concatenated public and secret key bytes (wiped when dropped)
    pub fn to_bytes_uniform(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new([&self.pub_key[..], &self.sec_key[..]].concat())
    }

    /// Creates a signer pair from a single byte slice containing both public and secret keys
    ///
    /// # Arguments
    /// * `bytes` - The concatenated public and secret key bytes
    ///
    /// # Returns
    /// - `Result<SignerPair, CryptoError>`: The constructed signer pair or an error
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
}

impl Clone for SignerPair {
    fn clone(&self) -> Self {
        Self {
            pub_key: self.pub_key,
            sec_key: self.sec_key.clone(),
            signing_key: decode_signing_key(&self.sec_key).expect("a decoded key decodes again"),
        }
    }
}

impl ViewOperations for SignerPair {
    fn pub_key_bytes(&self) -> &PublicKeyBytes {
        &self.pub_key
    }
}

/// Decodes a secret key into its heap-allocated signing form
///
/// The decoded key is a ~118 KB struct, and unoptimized builds copy it around enough to
/// overflow a 1 MB stack (the Windows main-thread default), so decoding runs on a
/// thread with a large stack whenever threads are available.
// ponytail: workaround for fn-dsa 0.4's stack-hungry decode; drop the thread once it fits in 1 MB in debug
fn decode_signing_key(sec_key: &SecretKeyBytes) -> Option<Box<SigningKeyStandard>> {
    let decode = || SigningKeyStandard::decode(sec_key).map(Box::new);
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn_scoped(scope, decode)
        {
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            // No threads on this platform (e.g. wasm): decode in place
            Err(_) => decode(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_sign() {
        let mut signer = SignerPair::create();
        let msg = b"Hello, World!";
        let sig = signer.sign(msg).unwrap();

        assert!(signer.verify(msg, &sig));
        assert!(!signer.verify(b"Hello, World?", &sig));
    }

    #[test]
    fn test_verifier_verify() {
        let mut signer = SignerPair::create();
        let msg = b"Hello, World!";
        let sig = signer.sign(msg).unwrap();

        let verifier = VerifierPair::new(signer.pub_key_bytes()).unwrap();
        assert!(verifier.verify(msg, &sig));

        let other = VerifierPair::new(SignerPair::create().pub_key_bytes()).unwrap();
        assert!(!other.verify(msg, &sig));
    }

    #[test]
    fn test_signer_bytes() {
        let signer = SignerPair::create();
        let (pub_key, sec_key) = signer.to_bytes();

        let mut signer2 = SignerPair::from_bytes(&pub_key, &sec_key[..]).unwrap();
        assert_eq!(signer.pub_key_bytes(), signer2.pub_key_bytes());
        assert!(signer.verify(b"msg", &signer2.sign(b"msg").unwrap()));

        let signer3 = SignerPair::from_bytes_uniform(&signer.to_bytes_uniform()).unwrap();
        assert_eq!(signer.pub_key_bytes(), signer3.pub_key_bytes());

        // A clone signs with the same key
        assert!(signer.verify(b"msg", &signer3.clone().sign(b"msg").unwrap()));
    }

    #[test]
    fn test_invalid_inputs() {
        let mut signer = SignerPair::create();
        let (pub_key, sec_key) = signer.to_bytes();

        assert!(matches!(
            SignerPair::from_bytes_uniform(&[0u8; 10]),
            Err(CryptoError::IncongruentLength(n, 10)) if n == PUBLIC_KEY_BYTES + SECRET_KEY_BYTES
        ));
        assert!(matches!(
            SignerPair::from_bytes(&pub_key, &sec_key[1..]),
            Err(CryptoError::IncongruentLength(SECRET_KEY_BYTES, _))
        ));

        // Right length, but the keys don't decode (corrupted header byte)
        let mut bad_sec = sec_key.clone();
        bad_sec[0] ^= 0xFF;
        assert!(matches!(
            SignerPair::from_bytes(&pub_key, &bad_sec[..]),
            Err(CryptoError::InvalidKey)
        ));
        let mut bad_pub = pub_key;
        bad_pub[0] ^= 0xFF;
        assert!(matches!(
            VerifierPair::new(&bad_pub),
            Err(CryptoError::InvalidKey)
        ));

        // Malformed signatures are rejected, never a panic
        let sig = signer.sign(b"msg").unwrap();
        assert!(!signer.verify(b"msg", &sig[..10]));
        assert!(!signer.verify(b"msg", &[]));
        let mut flipped = sig;
        flipped[100] ^= 1;
        assert!(!signer.verify(b"msg", &flipped));
    }

    #[test]
    fn test_works_on_small_stack() {
        // Regression: the decoded signing key is a ~118 KB struct that unoptimized builds
        // copy several times, which overflowed the 1 MB Windows main-thread stack
        let bytes = SignerPair::create().to_bytes_uniform();
        std::thread::Builder::new()
            .stack_size(512 << 10)
            .spawn(move || {
                let mut signer = SignerPair::from_bytes_uniform(&bytes).unwrap();
                let sig = signer.sign(b"msg").unwrap();
                assert!(signer.verify(b"msg", &sig));
                assert!(signer.clone().verify(b"msg", &sig));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_signer_rejects_foreign_pubkey() {
        let signer = SignerPair::create();
        let other = SignerPair::create();
        let result = SignerPair::from_bytes(other.pub_key_bytes(), &signer.to_bytes().1[..]);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn test_verifier_bytes() {
        let signer = SignerPair::create();
        let verifier = VerifierPair::new(signer.pub_key_bytes()).unwrap();
        let pub_key = verifier.to_bytes();

        let verifier2 = VerifierPair::from_bytes(&pub_key).unwrap();
        assert_eq!(verifier.pub_key_bytes(), verifier2.pub_key_bytes());

        assert!(matches!(
            VerifierPair::new(&pub_key[1..]),
            Err(CryptoError::IncongruentLength(PUBLIC_KEY_BYTES, _))
        ));
    }
}
