use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    errors::CryptoError,
    exchange::{
        encryptor::Encryptor,
        pair::{self, KEMPair},
        prekey::SignedPrekey,
    },
    signatures::keypair::{self, PublicKeyBytes, SignerPair, VerifierPair, ViewOperations},
};

/// Protocol label hashed into every session transcript
const PROTOCOL_LABEL: &[u8] = b"pq-msg/v2";
/// Version byte of the `MessageSession::to_bytes` format
const SESSION_FORMAT_VERSION: u8 = 2;
/// Direction tags, signed with every message so it can't be reflected back to its sender
const INITIATOR_TO_RESPONDER: u8 = 0;
const RESPONDER_TO_INITIATOR: u8 = 1;
/// Length of a serialized session
const SESSION_BYTES: usize = 2
    + keypair::PUBLIC_KEY_BYTES
    + keypair::SECRET_KEY_BYTES
    + keypair::PUBLIC_KEY_BYTES
    + 32 * 3
    + 16
    + 8 * 2;

/// MessageSession manages the cryptographic state for secure message exchange
/// between two parties using post-quantum cryptographic algorithms.
///
/// Each session contains:
/// - A digital signature keypair for signing our messages
/// - A verifier for validating messages from the other party
/// - One chain key and one counter per direction, derived from the ML-KEM shared
///   secret, so both parties can send at the same time without nonce reuse
/// - A transcript hash of the handshake that every message signature is bound to
///
/// Every message is encrypted with its own key, derived from the chain key, after which
/// the chain key moves forward and the old one is wiped. Someone who steals the session
/// (or a stored `to_bytes()` copy) can't decrypt the messages that came before.
///
/// Messages must be validated in the order they were crafted.
pub struct MessageSession {
    /// The digital signature keypair for this session
    ds_pair: SignerPair,
    /// The verifier for the other party's messages
    target_verifier: VerifierPair,
    /// Whether we initiated the session, which decides our sending direction
    is_initiator: bool,
    /// Hash of the handshake: session id, both identities, KEM public key and ciphertext
    transcript: [u8; 32],
    /// Chain key for the next message we send
    send_chain: Zeroizing<[u8; 32]>,
    /// Chain key for the next message we receive
    recv_chain: Zeroizing<[u8; 32]>,
    /// Session id, the first 16 bytes of every nonce
    session_id: [u8; 16],
    /// Counter of the last message we sent
    send_counter: u64,
    /// Counter of the last message we received
    recv_counter: u64,
}

impl MessageSession {
    /// Serializes the session to a byte array
    ///
    /// # Returns
    /// The serialized session (wiped when dropped)
    ///
    /// # Security Note
    /// The serialized data contains sensitive cryptographic material including private keys.
    /// It should be stored securely and only deserialized in a trusted environment.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(SESSION_BYTES));
        bytes.push(SESSION_FORMAT_VERSION);
        bytes.push(self.is_initiator as u8);
        bytes.extend_from_slice(&self.ds_pair.to_bytes_uniform());
        bytes.extend_from_slice(self.target_verifier.pub_key_bytes());
        bytes.extend_from_slice(&self.transcript);
        bytes.extend_from_slice(&self.send_chain[..]);
        bytes.extend_from_slice(&self.recv_chain[..]);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.send_counter.to_le_bytes());
        bytes.extend_from_slice(&self.recv_counter.to_le_bytes());
        bytes
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
    /// Returns an error if the byte array is not the correct length, version or format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SESSION_BYTES {
            return Err(CryptoError::IncongruentLength(SESSION_BYTES, bytes.len()));
        }
        if bytes[0] != SESSION_FORMAT_VERSION || bytes[1] > 1 {
            return Err(CryptoError::InvalidSession);
        }

        let mut rest = &bytes[2..];
        let mut take = |n: usize| {
            let (head, tail) = rest.split_at(n);
            rest = tail;
            head
        };

        Ok(Self {
            is_initiator: bytes[1] == 1,
            ds_pair: SignerPair::from_bytes_uniform(take(
                keypair::PUBLIC_KEY_BYTES + keypair::SECRET_KEY_BYTES,
            ))?,
            target_verifier: VerifierPair::new(take(keypair::PUBLIC_KEY_BYTES))?,
            transcript: take(32).try_into()?,
            send_chain: Zeroizing::new(take(32).try_into()?),
            recv_chain: Zeroizing::new(take(32).try_into()?),
            session_id: take(16).try_into()?,
            send_counter: u64::from_le_bytes(take(8).try_into()?),
            recv_counter: u64::from_le_bytes(take(8).try_into()?),
        })
    }

    /// Creates a new session as the initiator
    ///
    /// Send the responder everything it needs to call [`MessageSession::new_responder`]:
    /// the returned ciphertext, `target_prekey.id()`, the base nonce and your FN-DSA
    /// public key.
    ///
    /// # Arguments
    /// * `my_signer` - Your own signer pair
    /// * `base_nonce` - Base nonce (0..16 session id, 16..24 counter), shared with the responder
    /// * `target_prekey` - A signed prekey of the target
    /// * `target_verifier` - FN-DSA public key of the target. Get it from a source you
    ///   trust: it is what proves the prekey really belongs to the target.
    ///
    /// # Returns
    /// - `Result<(Self, [u8; pair::CIPHERTEXT_BYTES]), CryptoError>`:
    ///   The session and ciphertext for the responder, or `InvalidSignature` if the
    ///   prekey was not signed by `target_verifier`
    pub fn new_initiator(
        my_signer: SignerPair,
        base_nonce: [u8; 24],
        target_prekey: &SignedPrekey,
        target_verifier: &PublicKeyBytes,
    ) -> Result<(Self, [u8; pair::CIPHERTEXT_BYTES]), CryptoError> {
        let target_verifier = VerifierPair::new(target_verifier)?;
        if !target_prekey.verify(target_verifier.pub_key_bytes()) {
            return Err(CryptoError::InvalidSignature);
        }

        // We are the initiator, we encapsulate a shared secret for the responder
        let (shared_secret, ciphertext) = KEMPair::encapsulate(target_prekey.kem_pub_key())?;

        let session = Self::establish(
            my_signer,
            target_verifier,
            true,
            base_nonce,
            target_prekey.kem_pub_key(),
            &ciphertext,
            &shared_secret,
        );
        Ok((session, ciphertext))
    }

    /// Creates a new session as the responder
    ///
    /// If `my_prekey` is a one-time prekey, delete it everywhere you store it once
    /// this returns. That deletion is what gives the session forward secrecy.
    ///
    /// # Arguments
    /// * `my_prekey` - The prekey the initiator used (look it up by the id they sent)
    /// * `my_signer` - Your own signer pair
    /// * `base_nonce` - Base nonce (0..16 session id, 16..24 counter), shared with the initiator
    /// * `ciphertext` - KEM ciphertext sent by the initiator
    /// * `sender_verifier` - FN-DSA public key of the initiator
    ///
    /// # Returns
    /// - `Result<Self, CryptoError>`: The session or an error
    pub fn new_responder(
        my_prekey: &KEMPair,
        my_signer: SignerPair,
        base_nonce: [u8; 24],
        ciphertext: &[u8; pair::CIPHERTEXT_BYTES],
        sender_verifier: &PublicKeyBytes,
    ) -> Result<Self, CryptoError> {
        let target_verifier = VerifierPair::new(sender_verifier)?;
        let shared_secret = my_prekey.decapsulate(ciphertext);

        Ok(Self::establish(
            my_signer,
            target_verifier,
            false,
            base_nonce,
            &my_prekey.pub_key_bytes(),
            ciphertext,
            &shared_secret,
        ))
    }

    /// Derives the transcript and one chain key per direction, identically on both sides
    fn establish(
        ds_pair: SignerPair,
        target_verifier: VerifierPair,
        is_initiator: bool,
        base_nonce: [u8; 24],
        responder_kem_pubkey: &[u8; pair::PUBLIC_KEY_BYTES],
        ciphertext: &[u8; pair::CIPHERTEXT_BYTES],
        shared_secret: &[u8; pair::SHARED_SECRET_BYTES],
    ) -> Self {
        let (initiator, responder) = if is_initiator {
            (ds_pair.pub_key_bytes(), target_verifier.pub_key_bytes())
        } else {
            (target_verifier.pub_key_bytes(), ds_pair.pub_key_bytes())
        };

        // All fields are fixed-length, so plain concatenation is unambiguous
        let transcript: [u8; 32] = Sha256::new()
            .chain_update(PROTOCOL_LABEL)
            .chain_update(base_nonce)
            .chain_update(initiator)
            .chain_update(responder)
            .chain_update(responder_kem_pubkey)
            .chain_update(ciphertext)
            .finalize()
            .into();

        let hkdf = Hkdf::<Sha256>::new(Some(&transcript), shared_secret);
        let mut i2r = Zeroizing::new([0u8; 32]);
        let mut r2i = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"pq-msg/v2 initiator->responder", &mut i2r[..])
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hkdf.expand(b"pq-msg/v2 responder->initiator", &mut r2i[..])
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let (send_chain, recv_chain) = if is_initiator { (i2r, r2i) } else { (r2i, i2r) };

        let counter = u64::from_le_bytes(base_nonce[16..].try_into().unwrap());
        Self {
            ds_pair,
            target_verifier,
            is_initiator,
            transcript,
            send_chain,
            recv_chain,
            session_id: base_nonce[..16].try_into().unwrap(),
            send_counter: counter,
            recv_counter: counter,
        }
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
    /// This method increments the send counter to ensure a unique nonce for each
    /// message, and fails with `NonceExhausted` instead of ever reusing one.
    pub fn craft_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let counter = self
            .send_counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        let direction = self.send_direction();

        // Sign the message bound to this session, direction and position
        let signed_data = self.signed_data(direction, counter, message);
        let sig = self.ds_pair.sign(&signed_data)?;

        let plaintext = Zeroizing::new([&sig[..], message].concat());
        let (message_key, next_chain) = ratchet(&self.send_chain);
        let ciphertext = Encryptor::new(&message_key)
            .encrypt(&plaintext, &create_nonce(&self.session_id, counter))?;

        // Assigning drops (and wipes) the old chain key
        self.send_chain = next_chain;
        self.send_counter = counter;
        Ok(ciphertext)
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
    /// Messages must arrive in the order they were crafted. The receive counter only
    /// advances for authentic messages, so replayed or forged input is rejected
    /// without desynchronizing the session.
    pub fn validate_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let counter = self
            .recv_counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        let direction = 1 - self.send_direction();

        let (message_key, next_chain) = ratchet(&self.recv_chain);
        let mut plaintext = Encryptor::new(&message_key)
            .decrypt(ciphertext, &create_nonce(&self.session_id, counter))?;
        if plaintext.len() < keypair::SIGNATURE_BYTES {
            return Err(CryptoError::InvalidSignature);
        }

        let (sig, message) = plaintext.split_at(keypair::SIGNATURE_BYTES);
        if !self
            .target_verifier
            .verify(&self.signed_data(direction, counter, message), sig)
        {
            return Err(CryptoError::InvalidSignature);
        }

        self.recv_chain = next_chain;
        self.recv_counter = counter;
        plaintext.drain(..keypair::SIGNATURE_BYTES);
        Ok(plaintext)
    }

    /// The direction tag of the messages we send
    fn send_direction(&self) -> u8 {
        if self.is_initiator {
            INITIATOR_TO_RESPONDER
        } else {
            RESPONDER_TO_INITIATOR
        }
    }

    /// The bytes actually signed for a message: transcript || direction || counter || message
    fn signed_data(&self, direction: u8, counter: u64, message: &[u8]) -> Vec<u8> {
        [
            &self.transcript[..],
            &[direction],
            &counter.to_le_bytes(),
            message,
        ]
        .concat()
    }

    /// Gets the counter of the last message sent
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Gets the counter of the last message received
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }
}

/// Splits a chain key into the key for one message and the next chain key
///
/// This is a one-way step: the next chain key can't be turned back into this one.
fn ratchet(chain: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hkdf = Hkdf::<Sha256>::from_prk(chain).expect("32 bytes is a valid HKDF-SHA256 PRK");
    let mut message_key = Zeroizing::new([0u8; 32]);
    let mut next_chain = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"pq-msg/v2 message key", &mut message_key[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    hkdf.expand(b"pq-msg/v2 chain key", &mut next_chain[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    (message_key, next_chain)
}

/// Generates a random session ID of 16 bytes, used in nonce creation
///
/// # Returns
/// - `[u8; 16]`: The generated session ID
///   The random 16-byte array
pub fn gen_session_id() -> [u8; 16] {
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

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

    /// A new prekey for `owner`: the secret part and the signed public part
    fn signed_prekey(owner: &mut SignerPair) -> (KEMPair, SignedPrekey) {
        let prekey = KEMPair::create();
        let signed = SignedPrekey::new(owner, &prekey).unwrap();
        (prekey, signed)
    }

    /// Alice (initiator) and Bob (responder) with a fresh session
    fn session_pair(base_counter: u64) -> (MessageSession, MessageSession) {
        let alice_ds = SignerPair::create();
        let mut bob_ds = SignerPair::create();
        let (bob_prekey, bob_signed_prekey) = signed_prekey(&mut bob_ds);
        let base_nonce = create_nonce(&gen_session_id(), base_counter);

        let (alice, ciphertext) = MessageSession::new_initiator(
            alice_ds.clone(),
            base_nonce,
            &bob_signed_prekey,
            bob_ds.pub_key_bytes(),
        )
        .unwrap();
        let bob = MessageSession::new_responder(
            &bob_prekey,
            bob_ds,
            base_nonce,
            &ciphertext,
            alice_ds.pub_key_bytes(),
        )
        .unwrap();
        (alice, bob)
    }

    #[test]
    fn test_message_session_serialization() {
        let (mut alice, mut bob) = session_pair(0);
        bob.validate_message(&alice.craft_message(b"before").unwrap())
            .unwrap();

        // Serialize and deserialize Alice, then keep talking with the restored copy
        let mut restored = MessageSession::from_bytes(&alice.to_bytes()).unwrap();
        assert_eq!(alice.to_bytes(), restored.to_bytes());
        assert_eq!(restored.send_counter(), 1);

        let msg = bob.validate_message(&restored.craft_message(b"after").unwrap());
        assert_eq!(msg.unwrap(), b"after");
        let reply = restored.validate_message(&bob.craft_message(b"reply").unwrap());
        assert_eq!(reply.unwrap(), b"reply");
    }

    #[test]
    fn test_session_deserialization_rejects_bad_input() {
        let (alice, _) = session_pair(0);
        let bytes = alice.to_bytes();

        assert!(matches!(
            MessageSession::from_bytes(&bytes[1..]),
            Err(CryptoError::IncongruentLength(SESSION_BYTES, _))
        ));

        let mut wrong_version = bytes.to_vec();
        wrong_version[0] = 1;
        assert!(matches!(
            MessageSession::from_bytes(&wrong_version),
            Err(CryptoError::InvalidSession)
        ));

        let mut wrong_role = bytes.to_vec();
        wrong_role[1] = 2;
        assert!(matches!(
            MessageSession::from_bytes(&wrong_role),
            Err(CryptoError::InvalidSession)
        ));

        // Corrupted key material: our own public key no longer matches our secret key
        let mut wrong_own_key = bytes.to_vec();
        wrong_own_key[3] ^= 1;
        assert!(matches!(
            MessageSession::from_bytes(&wrong_own_key),
            Err(CryptoError::InvalidKey)
        ));

        // Corrupted peer key: it no longer decodes
        let mut wrong_peer_key = bytes.to_vec();
        wrong_peer_key[2 + keypair::PUBLIC_KEY_BYTES + keypair::SECRET_KEY_BYTES] ^= 0xFF;
        assert!(matches!(
            MessageSession::from_bytes(&wrong_peer_key),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn test_wrong_peer_identity_rejected() {
        // Bob believes the session came from Carol; Alice's messages must not pass as hers
        let alice_ds = SignerPair::create();
        let carol_ds = SignerPair::create();
        let mut bob_ds = SignerPair::create();
        let (bob_prekey, bob_signed_prekey) = signed_prekey(&mut bob_ds);
        let base_nonce = create_nonce(&gen_session_id(), 0);

        let (mut alice, ct) = MessageSession::new_initiator(
            alice_ds,
            base_nonce,
            &bob_signed_prekey,
            bob_ds.pub_key_bytes(),
        )
        .unwrap();
        let mut bob = MessageSession::new_responder(
            &bob_prekey,
            bob_ds,
            base_nonce,
            &ct,
            carol_ds.pub_key_bytes(),
        )
        .unwrap();

        assert!(
            bob.validate_message(&alice.craft_message(b"hi").unwrap())
                .is_err()
        );
    }

    #[test]
    fn test_invalid_peer_keys_rejected() {
        let mut bob_ds = SignerPair::create();
        let (bob_prekey, bob_signed_prekey) = signed_prekey(&mut bob_ds);
        let base_nonce = create_nonce(&gen_session_id(), 0);
        let mut undecodable = *bob_ds.pub_key_bytes();
        undecodable[0] ^= 0xFF;

        let initiator = MessageSession::new_initiator(
            SignerPair::create(),
            base_nonce,
            &bob_signed_prekey,
            &undecodable,
        );
        assert!(matches!(initiator, Err(CryptoError::InvalidKey)));

        let responder = MessageSession::new_responder(
            &bob_prekey,
            bob_ds,
            base_nonce,
            &[0u8; pair::CIPHERTEXT_BYTES],
            &undecodable,
        );
        assert!(matches!(responder, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn test_plaintext_too_short_for_signature() {
        // Only the peer holds the key, but a buggy or malicious peer could still send this
        let (alice, mut bob) = session_pair(0);
        let short = Encryptor::new(&ratchet(&alice.send_chain).0)
            .encrypt(b"no signature here", &create_nonce(&alice.session_id, 1))
            .unwrap();

        assert!(matches!(
            bob.validate_message(&short),
            Err(CryptoError::InvalidSignature)
        ));
        assert_eq!(bob.recv_counter(), 0);
    }

    #[test]
    fn test_full_message_exchange() {
        let (mut alice, mut bob) = session_pair(0);

        // Each side derived the other's chain keys
        assert_eq!(alice.send_chain, bob.recv_chain);
        assert_eq!(alice.recv_chain, bob.send_chain);
        assert_ne!(alice.send_chain, alice.recv_chain);
        assert_eq!(alice.transcript, bob.transcript);

        // Alice sends a message to Bob
        let message = b"Hello, Bob! This is a secret message.";
        let encrypted_message = alice.craft_message(message).unwrap();
        assert_eq!(alice.send_counter(), 1);
        assert_eq!(bob.recv_counter(), 0);

        // Bob decrypts and verifies Alice's message
        let raw_message = bob.validate_message(&encrypted_message).unwrap();
        assert_eq!(bob.recv_counter(), 1);
        assert_eq!(raw_message, message);

        // Bob replies to Alice
        let reply = b"Hello, Alice! I received your message safely.";
        let encrypted_reply = bob.craft_message(reply).unwrap();
        let raw_reply = alice.validate_message(&encrypted_reply).unwrap();
        assert_eq!(raw_reply, reply);

        assert_eq!(alice.send_counter(), bob.recv_counter());
        assert_eq!(alice.recv_counter(), bob.send_counter());
    }

    #[test]
    fn test_concurrent_sends() {
        // Regression: both parties used to share one key and one counter, so two
        // messages sent at the same time reused a key-nonce pair and leaked m_A ^ m_B
        let (mut alice, mut bob) = session_pair(0);

        let (ma, mb) = (
            b"attack at dawn, bring snacks!!",
            b"meet me at the north gate 9pm.",
        );
        let ca = alice.craft_message(ma).unwrap();
        let cb = bob.craft_message(mb).unwrap();

        let ct_xor: Vec<u8> = ca.iter().zip(&cb).map(|(x, y)| x ^ y).collect();
        let pt_xor: Vec<u8> = ma.iter().zip(mb).map(|(x, y)| x ^ y).collect();
        assert!(!ct_xor.windows(pt_xor.len()).any(|w| w == pt_xor));

        // Both messages still arrive, and the session stays in sync
        assert_eq!(bob.validate_message(&ca).unwrap(), ma);
        assert_eq!(alice.validate_message(&cb).unwrap(), mb);
        let next = alice.craft_message(b"next").unwrap();
        assert_eq!(bob.validate_message(&next).unwrap(), b"next");
    }

    #[test]
    fn test_replay_and_garbage_do_not_desync() {
        let (mut alice, mut bob) = session_pair(0);

        let first = alice.craft_message(b"first").unwrap();
        bob.validate_message(&first).unwrap();

        // A replayed message and random garbage are rejected without moving the counter
        assert!(bob.validate_message(&first).is_err());
        assert!(bob.validate_message(&[0u8; 2000]).is_err());
        assert_eq!(bob.recv_counter(), 1);

        let second = alice.craft_message(b"second").unwrap();
        assert_eq!(bob.validate_message(&second).unwrap(), b"second");
    }

    #[test]
    fn test_out_of_order_rejected() {
        let (mut alice, mut bob) = session_pair(0);

        let first = alice.craft_message(b"first").unwrap();
        let second = alice.craft_message(b"second").unwrap();

        assert!(bob.validate_message(&second).is_err());
        assert_eq!(bob.validate_message(&first).unwrap(), b"first");
        assert_eq!(bob.validate_message(&second).unwrap(), b"second");
    }

    #[test]
    fn test_reflected_message_rejected() {
        let (mut alice, _) = session_pair(0);

        // Alice's own message sent back to her doesn't decrypt under her receive key
        let msg = alice.craft_message(b"hello").unwrap();
        assert!(alice.validate_message(&msg).is_err());
    }

    #[test]
    fn test_forwarded_message_rejected() {
        // Bob receives a signed message from Alice, then opens a session to Carol
        // claiming to be Alice and forwards it. The signature is bound to the
        // Alice-Bob transcript, so Carol must reject it.
        let alice_ds = SignerPair::create();
        let mut bob_ds = SignerPair::create();
        let (bob_prekey, bob_signed_prekey) = signed_prekey(&mut bob_ds);
        let mut carol_ds = SignerPair::create();
        let (carol_prekey, carol_signed_prekey) = signed_prekey(&mut carol_ds);
        let base_nonce = create_nonce(&gen_session_id(), 0);

        let (mut alice, ct) = MessageSession::new_initiator(
            alice_ds.clone(),
            base_nonce,
            &bob_signed_prekey,
            bob_ds.pub_key_bytes(),
        )
        .unwrap();
        let bob = MessageSession::new_responder(
            &bob_prekey,
            bob_ds.clone(),
            base_nonce,
            &ct,
            alice_ds.pub_key_bytes(),
        )
        .unwrap();

        // Bob decrypts Alice's message to get her signature and the message
        let sent = alice.craft_message(b"I owe Bob 100 euros").unwrap();
        let signed = Encryptor::new(&ratchet(&bob.recv_chain).0)
            .decrypt(&sent, &create_nonce(&bob.session_id, 1))
            .unwrap();

        // Bob opens a session to Carol, telling her he is Alice. He encapsulated the
        // shared secret and the transcript is public, so he can derive Carol's
        // receive key; the test simply reads it from her session.
        let (_, ct) = MessageSession::new_initiator(
            bob_ds,
            base_nonce,
            &carol_signed_prekey,
            carol_ds.pub_key_bytes(),
        )
        .unwrap();
        let mut carol = MessageSession::new_responder(
            &carol_prekey,
            carol_ds,
            base_nonce,
            &ct,
            alice_ds.pub_key_bytes(),
        )
        .unwrap();
        let forged = Encryptor::new(&ratchet(&carol.recv_chain).0)
            .encrypt(&signed, &create_nonce(&carol.session_id, 1))
            .unwrap();

        assert!(matches!(
            carol.validate_message(&forged),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn test_stolen_session_cannot_read_past_messages() {
        let (mut alice, mut bob) = session_pair(0);

        let first = alice.craft_message(b"first").unwrap();
        bob.validate_message(&first).unwrap();

        // An attacker later steals Bob's stored session and rewinds its counter.
        // The chain key has already moved on, so the old message stays unreadable.
        let mut stolen = MessageSession::from_bytes(&bob.to_bytes()).unwrap();
        stolen.recv_counter = 0;
        assert!(stolen.validate_message(&first).is_err());
    }

    #[test]
    fn test_deleted_prekey_gives_forward_secrecy() {
        let alice_ds = SignerPair::create();
        let mut bob_ds = SignerPair::create();
        let (last_resort, _) = signed_prekey(&mut bob_ds);
        let (one_time, one_time_signed) = signed_prekey(&mut bob_ds);
        let base_nonce = create_nonce(&gen_session_id(), 0);

        let (mut alice, ct) = MessageSession::new_initiator(
            alice_ds.clone(),
            base_nonce,
            &one_time_signed,
            bob_ds.pub_key_bytes(),
        )
        .unwrap();
        let mut bob = MessageSession::new_responder(
            &one_time,
            bob_ds.clone(),
            base_nonce,
            &ct,
            alice_ds.pub_key_bytes(),
        )
        .unwrap();
        drop(one_time); // Bob deletes the one-time prekey

        // An attacker records the handshake and the first message
        let recorded = alice.craft_message(b"secret").unwrap();
        assert_eq!(bob.validate_message(&recorded).unwrap(), b"secret");

        // Later every key Bob still has leaks; none of them opens the recorded session
        let mut attacker = MessageSession::new_responder(
            &last_resort,
            bob_ds,
            base_nonce,
            &ct,
            alice_ds.pub_key_bytes(),
        )
        .unwrap();
        assert!(attacker.validate_message(&recorded).is_err());
    }

    #[test]
    fn test_initiator_rejects_prekey_not_signed_by_target() {
        // E.g. a malicious server hands out its own prekey for Bob
        let bob_ds = SignerPair::create();
        let mut mallory_ds = SignerPair::create();
        let (_, fake) = signed_prekey(&mut mallory_ds);

        let result = MessageSession::new_initiator(
            SignerPair::create(),
            create_nonce(&gen_session_id(), 0),
            &fake,
            bob_ds.pub_key_bytes(),
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_counter_exhaustion() {
        let (mut alice, mut bob) = session_pair(u64::MAX - 1);

        let last = alice.craft_message(b"last").unwrap();
        assert_eq!(alice.send_counter(), u64::MAX);
        assert_eq!(bob.validate_message(&last).unwrap(), b"last");

        // No wrap-around back to 0: the session refuses instead of reusing a nonce
        assert!(matches!(
            alice.craft_message(b"one more"),
            Err(CryptoError::NonceExhausted)
        ));
        assert!(matches!(
            bob.validate_message(&last),
            Err(CryptoError::NonceExhausted)
        ));
    }

    #[test]
    fn test_empty_message() {
        let (mut alice, mut bob) = session_pair(0);
        let encrypted = alice.craft_message(b"").unwrap();
        assert_eq!(bob.validate_message(&encrypted).unwrap(), b"");
    }

    #[test]
    fn test_session_ids_are_random() {
        assert_ne!(gen_session_id(), gen_session_id());
    }

    #[test]
    fn test_nonce_creation() {
        // Generate a session ID
        let session_id = gen_session_id();

        // Create a nonce with a counter of 5
        let counter = 5;
        let nonce = create_nonce(&session_id, counter);

        // Verify the nonce structure
        assert_eq!(&nonce[..16], &session_id[..]);
        assert_eq!(&nonce[16..], &counter.to_le_bytes()[..]);
    }

    #[test]
    fn test_base_counter() {
        let (mut alice, mut bob) = session_pair(42);
        assert_eq!(alice.send_counter(), 42);
        assert_eq!(bob.recv_counter(), 42);

        bob.validate_message(&alice.craft_message(b"hi").unwrap())
            .unwrap();
        assert_eq!(alice.send_counter(), 43);
        assert_eq!(bob.recv_counter(), 43);
    }
}
