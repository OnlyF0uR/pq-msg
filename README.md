# pq-msg

[![Crates.io](https://img.shields.io/crates/v/pq-msg.svg)](https://crates.io/crates/pq-msg)
[![Documentation](https://docs.rs/pq-msg/badge.svg)](https://docs.rs/pq-msg)
[![License](https://img.shields.io/crates/l/pq-msg.svg)](https://github.com/OnlyF0uR/pq-msg)

## 🔒 Overview

A Rust crate that combines multiple post-quantum cryptographic techniques to facilitate quantum-resistant end-to-end encrypted messaging. `pq-msg` serves as an abstraction layer over various cryptographic schemes to provide a comprehensive solution for secure communication in a post-quantum world.

## 🛠️ Cryptographic Foundation

| Component | Implementation | Purpose |
|-----------|---------------|---------|
| **Key Exchange** | ML-KEM (FIPS 203) | Quantum-resistant key establishment |
| **Symmetric Encryption** | XChaCha20Poly1305 | Fast and secure data encryption |
| **Message Authentication** | Falcon (FN-DSA, FIPS 206) | Quantum-resistant digital signatures |

## ⚙️ Usage

```rust
use pq_msg::{
    exchange::pair::KEMPair, messaging::MessageSession, messaging::create_nonce,
    messaging::gen_session_id, signatures::keypair::SignerPair,
};

fn main() {
    let alice_kem = KEMPair::create();
    let alice_signer = SignerPair::create();

    let bob_kem = KEMPair::create();
    let bob_signer = SignerPair::create();

    // Create a base nonce with a new session id, and a counter of
    let base_nonce = create_nonce(&gen_session_id(), 0);

    // Lets create the message session for Alice first
    let (mut alice_session, ciphertext) = MessageSession::new_initiator(
        alice_kem,
        alice_signer.clone(),
        base_nonce,
        &bob_kem.to_bytes().unwrap().0,    // Bob's public KEM key
        &bob_signer.to_bytes().unwrap().0, // Bob's public signer key
    )
    .unwrap();

    // Now for Bob it would look like this
    let mut bob_session = MessageSession::new_responder(
        bob_kem,
        bob_signer.clone(),
        base_nonce,
        &ciphertext,
        &alice_signer.to_bytes().unwrap().0, // Alice's public signer key
    )
    .unwrap();

    // Now both sessions contain a shared secret they use to encrypt and decrypt messages
    // and a nonce that is incremented with each message sent or received.

    // Alice creates a mesasge and prepares to send it to Bob
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

## ⚠️ Important Notice

**This library is currently in development and should be considered experimental.**

Some of the cryptographic packages used have not been independently audited, and certain components are awaiting final standardization by NIST. Please refrain from using this in production environments and consider it for educational and research purposes until further notice.

## 📚 Documentation

For full documentation and examples, please visit [docs.rs/pq-msg](https://docs.rs/pq-msg).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the [MIT](LICENSE-MIT)/[Apache-2.0](LICENSE-APACHE) dual license.