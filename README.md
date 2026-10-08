# pq-msg

[![Crates.io](https://img.shields.io/crates/v/pq-msg.svg)](https://crates.io/crates/pq-msg)
[![Documentation](https://docs.rs/pq-msg/badge.svg)](https://docs.rs/pq-msg)
[![License](https://img.shields.io/crates/l/pq-msg.svg)](https://github.com/OnlyF0uR/pq-msg)

## 🔒 Overview

A Rust crate that combines multiple post-quantum cryptographic techniques to facilitate quantum-resistant end-to-end encrypted messaging. `pq-msg` serves as an abstraction layer over various cryptographic schemes to provide a comprehensive solution for secure communication in a post-quantum world. It is written entirely in safe, pure Rust (`#![forbid(unsafe_code)]`).

## 🛠️ Cryptographic Foundation

| Component | Implementation | Purpose |
|-----------|---------------|---------|
| **Key Exchange** | ML-KEM-1024 (FIPS 203) via [`ml-kem`](https://crates.io/crates/ml-kem) | Quantum-resistant key establishment |
| **Key Derivation** | HKDF-SHA256 | One key chain per direction, a fresh key per message |
| **Symmetric Encryption** | XChaCha20Poly1305 | Fast and secure data encryption |
| **Message Authentication** | FN-DSA-1024 (Falcon, draft FIPS 206) via [`fn-dsa`](https://crates.io/crates/fn-dsa) | Quantum-resistant digital signatures |

## ⚠️ Security Warnings

**This library is experimental and has not been independently audited. Do not use it in production.**

- **ML-KEM:** the [`ml-kem`](https://crates.io/crates/ml-kem) crate states that its implementation "has never been independently audited! USE AT YOUR OWN RISK!"
- **FN-DSA:** FIPS 206 has not been published yet. The [`fn-dsa`](https://crates.io/crates/fn-dsa) crate implements a best guess at the draft and warns that its keys and signatures *may not interoperate with the final standard*. When FIPS 206 is published, `pq-msg` will release another breaking version, and signing keys and stored sessions will need to be regenerated.

## ⚙️ Usage

```rust
use pq_msg::{
    exchange::{pair::KEMPair, prekey::SignedPrekey},
    messaging::{MessageSession, create_nonce, gen_session_id},
    signatures::keypair::{SignerPair, ViewOperations},
};

fn main() {
    let alice_signer = SignerPair::create();
    let mut bob_signer = SignerPair::create();

    // Bob creates a one-time prekey and signs its public part, which he shares with Alice
    let bob_prekey = KEMPair::create();
    let bob_signed_prekey = SignedPrekey::new(&mut bob_signer, &bob_prekey).unwrap();

    // Create a base nonce with a new session id, and a counter of 0
    let base_nonce = create_nonce(&gen_session_id(), 0);

    // Lets create the message session for Alice first. This checks that the prekey
    // was signed by Bob.
    let (mut alice_session, ciphertext) = MessageSession::new_initiator(
        alice_signer.clone(),
        base_nonce,
        &bob_signed_prekey,
        bob_signer.pub_key_bytes(), // Bob's public signer key
    )
    .unwrap();

    // Now for Bob it would look like this
    let mut bob_session = MessageSession::new_responder(
        &bob_prekey,
        bob_signer.clone(),
        base_nonce,
        &ciphertext,
        alice_signer.pub_key_bytes(), // Alice's public signer key
    )
    .unwrap();

    // The prekey was one-time, so Bob deletes it now (dropping it wipes it from memory)
    drop(bob_prekey);

    // Both sessions now hold one chain key per direction, derived from the shared secret.
    // Every message gets its own key, and the chain moves forward after each one.

    // Alice creates a message and prepares to send it to Bob
    let message = b"Hello, Bob! This is a secret message.";
    let encrypted_message = alice_session.craft_message(message).unwrap();

    // Bob decrypts and verifies Alice's message
    let raw_message = bob_session.validate_message(&encrypted_message).unwrap();

    // Both message and raw_message are equal, let's print them out to illustrate
    let message_str = String::from_utf8_lossy(message);
    let raw_message_str = String::from_utf8_lossy(&raw_message);

    println!("[1] Alice's message: {}", message_str);
    println!("[2] Bob's decrypted message: {}", raw_message_str);

    // Bob crafts a reply message to Alice
    let reply = b"Hello, Alice! I received your message safely.";
    let encrypted_reply = bob_session.craft_message(reply).unwrap();

    // Alice decrypts and verifies Bob's reply
    let raw_reply = alice_session.validate_message(&encrypted_reply).unwrap();

    // Both reply and raw_reply are equal, let's print them again
    let reply_str = String::from_utf8_lossy(reply);
    let raw_reply_str = String::from_utf8_lossy(&raw_reply);

    println!("[3] Bob's reply: {}", reply_str);
    println!("[4] Alice's decrypted reply: {}", raw_reply_str);
}
```

Run this example with:
```bash
cargo run --example full_exchange
```

## 🔐 Protocol

1. **Prekeys.** The responder creates ML-KEM-1024 key pairs ahead of time ("prekeys") and signs each public key with their FN-DSA identity key (`SignedPrekey`). They keep the secret parts and share the signed public parts, directly or through a server.
2. **Handshake.** The initiator checks the prekey's signature against the responder's identity key, encapsulates a shared secret to the prekey and sends the ciphertext. Both sides share a 24-byte base nonce (a 16-byte session id plus an 8-byte starting counter).
3. **Transcript.** Both sides hash the protocol label, the base nonce, both FN-DSA public keys, the prekey and the KEM ciphertext into a 32-byte transcript.
4. **Chain keys.** HKDF-SHA256 (salt = transcript, input = shared secret) derives two chain keys: one for initiator → responder and one for responder → initiator. Both parties can send at the same time without ever reusing a key and nonce pair.
5. **Messages.** For every message, the sender's chain key is split into a one-time message key and the next chain key, and the old chain key is wiped. The message is signed over `transcript || direction || counter || message` and encrypted with XChaCha20Poly1305 under the message key. The nonce is `session id || counter`. Binding the signature this way means a message can't be forwarded to another session, reflected back to its sender, or replayed.

## 🛡️ Forward Secrecy

Forward secrecy means a key stolen *later* can't decrypt traffic recorded *earlier*. pq-msg provides it at two levels:

- **Within a session.** Each message key is used once and the chain key only moves forward. Someone who steals a session (from memory, or a stored `to_bytes()` copy) can't decrypt the messages that came before it.
- **Across sessions, through one-time prekeys.** Once the responder deletes the one-time prekey a session used, nothing they still hold can decrypt that session's handshake.

This only works if the prekey rules are followed:

| Who | Must do |
|---|---|
| Responder's device | Create a batch of one-time prekeys plus one last-resort prekey, and sign them all with `SignedPrekey::new`. After `new_responder` with a one-time prekey, **delete that prekey everywhere it is stored**. Replace the last-resort prekey regularly (for example weekly), and publish more one-time prekeys before they run out. |
| Server | Hand out each one-time prekey **only once**, then remove it. Fall back to the last-resort prekey when none are left. Rate-limit fetches so an attacker can't drain them. |
| Initiator | Get the responder's FN-DSA identity key from a source you trust. `new_initiator` checks the prekey against it, so a server can't swap in its own prekey. Then send the responder the ciphertext, `prekey.id()`, the base nonce and your identity key. |

Sessions set up with the **last-resort prekey** only gain forward secrecy once that prekey is replaced and deleted.

**Not provided: post-compromise security.** If an attacker steals a live session, they can read its *future* messages until the session ends; the session doesn't "heal". Start new sessions regularly to limit this. Healing ratchets (such as Signal's Triple Ratchet) are much more complex and are not planned.

## 🖧 Prekey Server (optional)

pq-msg itself is a library and doesn't include networking. The opt-in `server` feature adds `PrekeyServer`, an in-memory reference implementation of the server rules above. It is useful for prototypes and tests:

```toml
pq-msg = { version = "0.2", features = ["server"] }
```

```bash
cargo run --example prekey_server --features server
```

For production, follow the same rules with a real database and your own account authentication. See the [`server` module documentation](https://docs.rs/pq-msg/latest/pq_msg/server/) for what a production server must add.

## ⚠️ Limitations

- Messages must be validated in the order they were crafted. A replayed, reordered or tampered message is rejected, and the session stays usable.
- A session ends after 2⁶⁴ messages per direction (`NonceExhausted`). The counter never wraps around.
- No post-compromise security (see above).

## ⬆️ Upgrading from 0.1

0.2 is a breaking release. The `pqcrypto-*` crates it relied on are unmaintained ([RUSTSEC-2026-0164](https://rustsec.org/advisories/RUSTSEC-2026-0164)) because PQClean has been archived.

- Signing keys, signatures and serialized sessions from 0.1 can't be loaded. ML-KEM public keys and ciphertexts are unchanged, but secret keys are now stored as the 64-byte FIPS 203 seed.
- Signatures are detached: `SignerPair::sign(&mut self, msg)` returns the signature, and `ViewOperations::verify(msg, sig)` returns a `bool`.
- Sessions start from a signed prekey: `MessageSession::new_initiator` takes a `&SignedPrekey` (and checks its signature) instead of a raw KEM public key and your own KEM pair, and `new_responder` borrows the matching prekey (`&KEMPair`).
- `get_counter` is replaced by `send_counter` and `recv_counter`. `MessageSession::to_bytes` returns its bytes directly.
- `KEMPair::encapsulate` is an associated function that takes the receiver's public key bytes, `decapsulate` returns the secret directly, and `Encryptor::new` takes a 32-byte key.
- Removed: `ss2b`, `b2ss`, `parse_ss` (shared secrets are plain byte arrays now), `verify_comp`, `verify_message` and `verify_message_bytes`.
- Secret key material is wiped from memory on drop, and functions that return it wrap it in `Zeroizing`.

## 📚 Documentation

For full documentation and examples, please visit [docs.rs/pq-msg](https://docs.rs/pq-msg).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the [MIT](LICENSE-MIT)/[Apache-2.0](LICENSE-APACHE) dual license.