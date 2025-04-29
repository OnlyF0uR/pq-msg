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

use crate::{
    errors::CryptoError,
    exchange::{
        encryptor,
        pair::{self, KEMPair, b2ss, ss2b},
    },
    signatures::keypair::{SignerPair, VerifierPair, ViewOperations},
};

pub struct MessageSession {
    kem_pair: pair::KEMPair,
    ds_pair: SignerPair,
    shared_secret: SharedSecret,
    target_verifier: VerifierPair,
    current_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes)
}

impl MessageSession {
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len()
            != PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + 24
        {
            return Err(CryptoError::IncongruentLength(
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
                    + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + 24,
                bytes.len(),
            ));
        }

        let mut idx = 0;

        let kem_pair = pair::KEMPair::from_bytes_uniform(
            &bytes[idx..idx
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        )?;

        idx += PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        let ds_pair = SignerPair::from_bytes_uniform(
            &bytes[idx..idx
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        )?;

        idx += PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        let ss_bytes = &bytes[idx..idx + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
        let shared_secret = b2ss(parse_ss(ss_bytes)?);
        idx += PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES;

        let target_verifier = VerifierPair::from_bytes(
            &bytes[idx..idx + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
        )?;
        idx += PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

        let current_nonce = bytes[idx..idx + 24].try_into().unwrap();
        idx += 24;

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

    pub fn new_responder(
        my_keypair: KEMPair,   // This the your own keypair
        my_signer: SignerPair, // This is your own signer pair
        base_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes), provided by server
        ciphertext_bytes: &[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES], // KEM ciphertext semt tp us by the initiator
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

    pub fn craft_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self.ds_pair.sign(message);

        self.increment_nonce();
        encryptor::Encryptor::new(self.shared_secret).encrypt(&sig.as_bytes(), &self.current_nonce)
    }

    pub fn validate_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.increment_nonce();

        let decrypted_message = encryptor::Encryptor::new(self.shared_secret)
            .decrypt(ciphertext, &self.current_nonce)?;

        if decrypted_message.len() < PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES {
            return Err(CryptoError::FalconSignatureTooShort(
                decrypted_message.len(),
            ));
        }

        let sm = falconpadded1024::SignedMessage::from_bytes(&decrypted_message)?;
        let msg = self.target_verifier.verify_message(&sm)?;

        // Return the crafted message object as well as the bytes of the message itself
        Ok(msg)
    }

    fn increment_nonce(&mut self) {
        let mut counter = u64::from_le_bytes(self.current_nonce[16..24].try_into().unwrap());
        counter += 1;
        self.current_nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    }

    // fn rollback_nonce(&mut self, n: u64) {
    //     let mut counter = u64::from_le_bytes(self.current_nonce[16..24].try_into().unwrap());
    //     counter -= n;
    //     self.current_nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    // }
}

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
        let base_nonce = [0u8; 24];

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
        let base_nonce = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

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

        // print bobs nonce
        println!("Bob's nonce: {:?}", bob_session.current_nonce);
        println!("Alice's nonce - 1: {:?}", alice_session.current_nonce);

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
        let base_nonce = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

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
    fn test_nonce_increment_and_rollback() {
        // Generate keypairs
        let kem_pair = pair::KEMPair::create();
        let ds_pair = SignerPair::create();
        let target_kem_pair = pair::KEMPair::create();
        let target_ds_pair = SignerPair::create();

        // Create base nonce with initial counter value
        let mut base_nonce = [0u8; 24];
        let initial_counter: u64 = 42;
        base_nonce[16..24].copy_from_slice(&initial_counter.to_le_bytes());

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
        let counter = u64::from_le_bytes(session.current_nonce[16..24].try_into().unwrap());
        assert_eq!(counter, initial_counter);

        // Test increment_nonce
        session.increment_nonce();
        let new_counter = u64::from_le_bytes(session.current_nonce[16..24].try_into().unwrap());
        assert_eq!(new_counter, initial_counter + 1);

        // Test rollback_nonce
        // session.rollback_nonce(1);
        // let rolled_back_counter =
        //     u64::from_le_bytes(session.current_nonce[16..24].try_into().unwrap());
        // assert_eq!(rolled_back_counter, initial_counter);
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
