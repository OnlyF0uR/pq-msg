use pqcrypto_falcon::{
    falconpadded1024::{self},
    ffi::{
        PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES,
        PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    },
};
use pqcrypto_mlkem::{
    ffi::{
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES, PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    },
    mlkem1024::{self, SharedSecret},
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey};
use pqcrypto_traits::sign::SignedMessage;
use rand::RngCore;

use crate::{
    errors::CryptoError,
    exchange::{
        encryptor,
        pair::{self, KEMPair, b2ss, ss2b},
    },
    signatures::keypair::{SignerPair, VerifierPair, ViewOperations},
};

/// The maximum value a nonce counter can reach before rolling over
const MAX_NONCE_COUNTER: u64 = u64::MAX - 1;

/// MessageSession manages the cryptographic state for secure message exchange
/// between two parties using post-quantum cryptographic algorithms.
///
/// Each session contains:
/// - A KEM keypair for key encapsulation mechanism
/// - A digital signature keypair for signing messages
/// - A shared secret established with the other party
/// - A verifier for validating messages from the other party
/// - A nonce for preventing replay attacks
pub struct MessageSession {
    /// The KEM keypair for this session
    kem_pair: pair::KEMPair,
    /// The digital signature keypair for this session
    ds_pair: SignerPair,
    /// The shared secret established with the other party
    shared_secret: SharedSecret,
    /// The verifier for the other party's messages
    target_verifier: VerifierPair,
    /// The current nonce: 0..16 session id, 16..24 counter (u64, 8 bytes)
    current_nonce: [u8; 24],
}

impl MessageSession {
    /// Serializes the session to a byte array
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The serialized session or an error
    ///
    /// # Security Note
    /// The serialized data contains sensitive cryptographic material including private keys.
    /// It should be stored securely and only deserialized in a trusted environment.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = Vec::new();

        // PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
        bytes.extend_from_slice(self.kem_pair.to_bytes_uniform().as_slice());

        // PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
        bytes.extend_from_slice(self.ds_pair.to_bytes_uniform().as_slice());

        // PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
        bytes.extend_from_slice(&ss2b(&self.shared_secret));

        // Target verifier
        bytes.extend_from_slice(&self.target_verifier.to_bytes());

        // Current nonce
        bytes.extend_from_slice(&self.current_nonce[..]);
        Ok(bytes)
    }

    /// Deserializes a session from a byte array
    ///
    /// # Arguments
    /// * `bytes` - The serialized session bytes
    ///
    /// # Returns
    /// - `Result<Self, CryptoError>`: The deserialized session or an error
    ///
    /// # Errors
    /// Returns an error if the byte array is not the correct length or format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Calculate expected byte length for validation
        let expected_length = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
            + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
            + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
            + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + 24;

        if bytes.len() != expected_length {
            return Err(CryptoError::IncongruentLength(expected_length, bytes.len()));
        }

        let mut idx = 0;

        // Parse KEM keypair
        let kem_pair = pair::KEMPair::from_bytes_uniform(
            &bytes[idx..idx
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        )?;

        idx += PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        // Parse DS keypair
        let ds_pair = SignerPair::from_bytes_uniform(
            &bytes[idx..idx
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        )?;

        idx += PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        // Parse shared secret
        let ss_bytes = &bytes[idx..idx + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
        let shared_secret = b2ss(parse_ss(ss_bytes)?);
        idx += PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES;

        // Parse target verifier
        let target_verifier = VerifierPair::from_bytes(
            &bytes[idx..idx + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
        )?;
        idx += PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

        // Parse current nonce
        let current_nonce = bytes[idx..idx + 24].try_into().unwrap();
        idx += 24;

        // Final validation
        if idx != bytes.len() {
            return Err(CryptoError::IncongruentLength(bytes.len(), idx));
        }

        Ok(Self {
            kem_pair,
            ds_pair,
            shared_secret,
            target_verifier,
            current_nonce,
        })
    }

    /// Creates a new session as the initiator
    ///
    /// # Arguments
    /// * `my_keypair` - Your own KEM keypair
    /// * `my_signer` - Your own signer pair
    /// * `base_nonce` - Base nonce (0..16 session id, 16..24 counter)
    /// * `target_pubkey` - KEM public key of the target
    /// * `target_verifier` - Falcon verifier containing the public key of the target
    ///
    /// # Returns
    /// - `Result<(Self, [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES]), CryptoError>`:
    ///   The session and ciphertext for the responder, or an error
    pub fn new_initiator(
        my_keypair: KEMPair,   // This the your own keypair
        my_signer: SignerPair, // This is your own signer pair
        base_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes), provided by server
        target_pubkey: &[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES], // KEM public key of the target
        target_verifier: &[u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES], // Falcon verifier containing the falcon public key of the target
    ) -> Result<(Self, [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES]), CryptoError> {
        let pubkey = mlkem1024::PublicKey::from_bytes(target_pubkey)?;

        // We are the initiator, we need to encapsulate a shared secret for the receiver
        let (shared_secret, ciphertext) = my_keypair.encapsulate(&pubkey);

        // This contains the falcon public key of the target we are trying to reach
        // We will need this to verify his/her messages (signatures)
        let target_verifier = VerifierPair::from_bytes(target_verifier)?;

        // Return the ciphertext and shared secret
        Ok((
            Self {
                kem_pair: my_keypair,
                ds_pair: my_signer,
                shared_secret,
                target_verifier,
                current_nonce: base_nonce,
            },
            ct2b(&ciphertext)?,
        ))
    }

    /// Creates a new session as the responder
    ///
    /// # Arguments
    /// * `my_keypair` - Your own KEM keypair
    /// * `my_signer` - Your own signer pair
    /// * `base_nonce` - Base nonce (0..16 session id, 16..24 counter)
    /// * `ciphertext_bytes` - KEM ciphertext sent by the initiator
    /// * `sender_verifier` - Falcon verifier containing the public key of the initiator
    ///
    /// # Returns
    /// - `Result<Self, CryptoError>`: The session or an error
    pub fn new_responder(
        my_keypair: KEMPair,   // This the your own keypair
        my_signer: SignerPair, // This is your own signer pair
        base_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes), provided by server
        ciphertext_bytes: &[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES], // KEM ciphertext sent to us by the initiator
        sender_verifier: &[u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES], // Falcon verifier containing the falcon public key of the initiator
    ) -> Result<Self, CryptoError> {
        // We just have someone that attempts to establish a shared secret with us

        // Compute the shared secret using our private key
        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes)?;
        let shared_secret = my_keypair.decapsulate(&ciphertext)?;

        // This contains the verifier pubkey of the sender that is trying to reach us
        let target_verifier = VerifierPair::from_bytes(sender_verifier)?;

        Ok(Self {
            kem_pair: my_keypair,
            ds_pair: my_signer,
            shared_secret,
            target_verifier,
            current_nonce: base_nonce,
        })
    }

    /// Creates a signed and encrypted message for the other party
    ///
    /// # Arguments
    /// * `message` - The plaintext message to encrypt
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The encrypted message or an error
    ///
    /// # Security Note
    /// This method automatically increments the nonce counter to ensure
    /// uniqueness for each message.
    pub fn craft_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Sign the message with our digital signature key
        let sig = self.ds_pair.sign(message);

        // Increment the nonce for this message
        self.increment_nonce();

        // Encrypt the signed message with the shared secret
        encryptor::Encryptor::new(self.shared_secret).encrypt(&sig.as_bytes(), &self.current_nonce)
    }

    /// Decrypts and validates a message from the other party
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message
    ///
    /// # Returns
    /// - `Result<Vec<u8>, CryptoError>`: The decrypted and validated message or an error
    ///
    /// # Security Note
    /// This method automatically increments the nonce counter to match
    /// the sender's nonce. If the nonces are out of sync, validation will fail.
    pub fn validate_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Increment the nonce to match the sender's nonce
        self.increment_nonce();

        // Decrypt the message using the shared secret
        let decrypted_message = encryptor::Encryptor::new(self.shared_secret)
            .decrypt(ciphertext, &self.current_nonce)?;

        // Verify that the decrypted message is large enough to contain a signature
        if decrypted_message.len() < PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES {
            return Err(CryptoError::FalconSignatureTooShort(
                decrypted_message.len(),
            ));
        }

        // Parse the signed message and verify the signature
        let sm = falconpadded1024::SignedMessage::from_bytes(&decrypted_message)?;
        let msg = self.target_verifier.verify_message(&sm)?;

        // Return the verified message
        Ok(msg)
    }

    /// Increments the nonce counter safely, handling overflow
    ///
    /// # Security Note
    /// If the counter reaches its maximum value, it will wrap around to 0.
    /// This is a compromise between security and usability, as the session
    /// should ideally be refreshed before reaching this limit.
    fn increment_nonce(&mut self) {
        let mut counter = u64::from_le_bytes(self.current_nonce[16..24].try_into().unwrap());

        // Check for potential overflow
        if counter >= MAX_NONCE_COUNTER {
            // Reset counter to 0 when it reaches max value
            // In a production system, you might want to regenerate the session instead
            counter = 0;
        } else {
            counter += 1;
        }

        self.current_nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    }

    /// Gets the current nonce counter value
    ///
    /// # Returns
    /// - `u64`: The current nonce counter value
    pub fn get_counter(&self) -> u64 {
        u64::from_le_bytes(self.current_nonce[16..24].try_into().unwrap())
    }
}

/// Converts a ciphertext to a byte array
///
/// # Arguments
/// * `ct` - The ciphertext to convert
///
/// # Returns
/// - `Result<[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES], CryptoError>`:
///   The byte array or an error
fn ct2b(
    ct: &mlkem1024::Ciphertext,
) -> Result<[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES], CryptoError> {
    let slice = ct.as_bytes();

    if slice.len() == PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES {
        let ptr = slice.as_ptr() as *const [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        unsafe { Ok(*ptr) }
    } else {
        Err(CryptoError::IncongruentLength(
            PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
            slice.len(),
        ))
    }
}

/// Parses a byte slice into a fixed-size array for a shared secret
///
/// # Arguments
/// * `slice` - The byte slice to parse
///
/// # Returns
/// - `Result<&[T; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES], CryptoError>`:
///   The fixed-size array or an error
pub fn parse_ss<T>(slice: &[T]) -> Result<&[T; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES], CryptoError> {
    if slice.len() == PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES {
        let ptr = slice.as_ptr() as *const [T; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
        unsafe { Ok(&*ptr) }
    } else {
        Err(CryptoError::IncongruentLength(
            PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES,
            slice.len(),
        ))
    }
}

/// Generates a random session ID of 16 bytes, used in nonce creation
///
/// # Returns
/// - `[u8; 16]`: The generated session ID
///   The random 16-byte array
pub fn gen_session_id() -> [u8; 16] {
    let mut session_id = [0u8; 16];
    rand::rng().fill_bytes(&mut session_id);

    session_id
}

/// Creates a nonce from a session ID and a counter
///
/// # Arguments
/// * `session_id` - The session ID (16 bytes)
/// * `counter` - The counter value (u64)
///
/// # Returns
/// - `[u8; 24]`: The generated nonce (16 bytes session ID + 8 bytes counter)
///   The nonce is a combination of the session ID and the counter
pub fn create_nonce(session_id: &[u8; 16], counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(session_id);
    nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_session_serialization() {
        // Generate necessary keypairs
        let kem_pair = pair::KEMPair::create();
        let ds_pair = SignerPair::create();
        let target_kem_pair = pair::KEMPair::create();
        let target_ds_pair = SignerPair::create();

        // Create base nonce of 16 + 8 bytes (u64 counter)
        let base_nonce = create_nonce(&gen_session_id(), 0);

        // We now want to send a message to someone
        let (session, _) = MessageSession::new_initiator(
            kem_pair,                               // our kem pair
            ds_pair,                                // our ds pair
            base_nonce,                             // base nonce
            &target_kem_pair.to_bytes().unwrap().0, // target public key
            &target_ds_pair.to_bytes().unwrap().0,  // target verifier public key
        )
        .unwrap();

        // Serialize the session
        let serialized = session.to_bytes().unwrap();

        // Deserialize and verify the session
        let deserialized = MessageSession::from_bytes(&serialized).unwrap();

        // Verify both sessions have the same nonce
        assert_eq!(session.current_nonce, deserialized.current_nonce);
    }

    #[test]
    fn test_full_message_exchange() {
        // Generate keypairs for both Alice and Bob
        let alice_kem = pair::KEMPair::create();
        let alice_ds = SignerPair::create();
        let bob_kem = pair::KEMPair::create();
        let bob_ds = SignerPair::create();

        // Create base nonce
        let base_nonce = create_nonce(&gen_session_id(), 0);

        // Alice initiates a session with Bob
        let (mut alice_session, ciphertext) = MessageSession::new_initiator(
            alice_kem,
            alice_ds.clone(),
            base_nonce,
            &bob_kem.to_bytes().unwrap().0,
            &bob_ds.to_bytes().unwrap().0,
        )
        .unwrap();

        // Bob responds to Alice's session initiation
        let mut bob_session = MessageSession::new_responder(
            bob_kem,
            bob_ds.clone(),
            base_nonce,
            &ciphertext,
            &alice_ds.to_bytes().unwrap().0,
        )
        .unwrap();

        assert_eq!(
            ss2b(&alice_session.shared_secret),
            ss2b(&bob_session.shared_secret)
        );

        // Alice sends a message to Bob
        let message = b"Hello, Bob! This is a secret message.";
        let encrypted_message = alice_session.craft_message(message).unwrap();

        assert_eq!(
            alice_session.current_nonce[16..24],
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(bob_session.current_nonce[16..24], [0, 0, 0, 0, 0, 0, 0, 0]);

        // Bob decrypts and verifies Alice's message
        let raw_message = bob_session.validate_message(&encrypted_message).unwrap();

        assert_eq!(bob_session.current_nonce[16..24], [1, 0, 0, 0, 0, 0, 0, 0]);

        // Check if the decrypted message matches the original
        assert_eq!(raw_message, message);

        // // Bob replies to Alice
        let reply = b"Hello, Alice! I received your message safely.";
        let encrypted_reply = bob_session.craft_message(reply).unwrap();

        // // Alice decrypts and verifies Bob's reply
        let raw_reply = alice_session.validate_message(&encrypted_reply).unwrap();

        // Bob and alices nonces should now equal
        assert_eq!(alice_session.current_nonce, bob_session.current_nonce);

        // // Check if the decrypted reply matches the original
        assert_eq!(raw_reply, reply);
    }

    #[test]
    fn test_nonce_desync() {
        // Generate keypairs for both Alice and Bob
        let alice_kem = pair::KEMPair::create();
        let alice_ds = SignerPair::create();
        let bob_kem = pair::KEMPair::create();
        let bob_ds = SignerPair::create();

        // Create base nonce
        let base_nonce = create_nonce(&gen_session_id(), 0);

        // Alice initiates a session with Bob
        let (mut alice_session, ciphertext) = MessageSession::new_initiator(
            alice_kem,
            alice_ds.clone(),
            base_nonce,
            &bob_kem.to_bytes().unwrap().0,
            &bob_ds.to_bytes().unwrap().0,
        )
        .unwrap();

        // Bob responds to Alice's session initiation
        let mut bob_session = MessageSession::new_responder(
            bob_kem,
            bob_ds.clone(),
            base_nonce,
            &ciphertext,
            &alice_ds.to_bytes().unwrap().0,
        )
        .unwrap();

        assert_eq!(
            ss2b(&alice_session.shared_secret),
            ss2b(&bob_session.shared_secret)
        );

        // Alice sends a message to Bob
        let message = b"Hello, Bob! This is a secret message.";
        let encrypted_message = alice_session.craft_message(message).unwrap();

        assert_eq!(
            alice_session.current_nonce[16..24],
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(bob_session.current_nonce[16..24], [0, 0, 0, 0, 0, 0, 0, 0]);

        // Lets artificially increase bob's nonce to simulate a desync
        bob_session.increment_nonce();
        assert_eq!(bob_session.current_nonce[16..24], [1, 0, 0, 0, 0, 0, 0, 0]);

        // However Alice signed the message with a nonce counter of 0
        let result = bob_session.validate_message(&encrypted_message);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_increment_and_counter() {
        // Generate keypairs
        let kem_pair = pair::KEMPair::create();
        let ds_pair = SignerPair::create();
        let target_kem_pair = pair::KEMPair::create();
        let target_ds_pair = SignerPair::create();

        // Create base nonce with initial counter value
        let initial_counter = 42;
        let base_nonce = create_nonce(&gen_session_id(), initial_counter);

        // Create a session
        let (mut session, _) = MessageSession::new_initiator(
            kem_pair,
            ds_pair,
            base_nonce,
            &target_kem_pair.to_bytes().unwrap().0,
            &target_ds_pair.to_bytes().unwrap().0,
        )
        .unwrap();

        // Test initial counter value
        let counter = session.get_counter();
        assert_eq!(counter, initial_counter);

        // Test increment_nonce
        session.increment_nonce();
        let new_counter = session.get_counter();
        assert_eq!(new_counter, initial_counter + 1);
    }

    #[test]
    fn test_counter_wraparound() {
        // Generate keypairs
        let kem_pair = pair::KEMPair::create();
        let ds_pair = SignerPair::create();
        let target_kem_pair = pair::KEMPair::create();
        let target_ds_pair = SignerPair::create();

        // Create base nonce with counter set to MAX_NONCE_COUNTER
        let base_nonce = create_nonce(&gen_session_id(), MAX_NONCE_COUNTER);

        // Create a session
        let (mut session, _) = MessageSession::new_initiator(
            kem_pair,
            ds_pair,
            base_nonce,
            &target_kem_pair.to_bytes().unwrap().0,
            &target_ds_pair.to_bytes().unwrap().0,
        )
        .unwrap();

        // Test initial counter value
        assert_eq!(session.get_counter(), MAX_NONCE_COUNTER);

        // Test increment_nonce wraps around
        session.increment_nonce();
        assert_eq!(session.get_counter(), 0);
    }

    #[test]
    fn test_shared_secret_consistency() {
        // Create two KEM pairs
        let alice_kem = pair::KEMPair::create();
        let bob_kem = pair::KEMPair::create();

        // Alice initiates (would normally be sent to Bob)
        let pubkey = mlkem1024::PublicKey::from_bytes(&bob_kem.to_bytes().unwrap().0).unwrap();
        let (alice_ss, ciphertext) = alice_kem.encapsulate(&pubkey);
        let ciphertext_bytes = ct2b(&ciphertext).unwrap();

        // Bob receives and decapsulates
        let ciphertext_received = mlkem1024::Ciphertext::from_bytes(&ciphertext_bytes).unwrap();
        let bob_ss = bob_kem.decapsulate(&ciphertext_received).unwrap();

        // Convert both to byte arrays for comparison
        let alice_ss_bytes = ss2b(&alice_ss);
        let bob_ss_bytes = ss2b(&bob_ss);

        // The shared secrets should be identical
        assert_eq!(alice_ss_bytes, bob_ss_bytes);
    }
}
