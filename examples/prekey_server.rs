//! The full prekey flow through the reference server.
//! Run with: cargo run --example prekey_server --features server

use std::collections::HashMap;

use pq_msg::{
    exchange::{
        pair::KEMPair,
        prekey::{PrekeyId, SignedPrekey},
    },
    messaging::{MessageSession, create_nonce, gen_session_id},
    server::PrekeyServer,
    signatures::keypair::{SignerPair, ViewOperations},
};

fn main() {
    let mut server = PrekeyServer::new();

    // --- Bob's device: create prekeys, keep the secrets, publish the signed public parts
    let mut bob_signer = SignerPair::create();
    let bob_last_resort = KEMPair::create();
    let bob_last_resort_signed = SignedPrekey::new(&mut bob_signer, &bob_last_resort).unwrap();

    let mut bob_one_time: HashMap<PrekeyId, KEMPair> = HashMap::new();
    let mut published = Vec::new();
    for _ in 0..3 {
        let prekey = KEMPair::create();
        let signed = SignedPrekey::new(&mut bob_signer, &prekey).unwrap();
        bob_one_time.insert(signed.id(), prekey);
        published.push(signed);
    }
    server
        .publish(
            "bob",
            *bob_signer.pub_key_bytes(),
            bob_last_resort_signed.clone(),
            published,
        )
        .unwrap();
    println!(
        "Bob published 3 one-time prekeys and a last-resort prekey ({} one-time left)",
        server.one_time_remaining(&"bob")
    );

    // --- Alice's device: fetch Bob's bundle and start a session
    let alice_signer = SignerPair::create();
    let bundle = server.fetch(&"bob").unwrap();

    // In a real app Alice checks Bob's identity key against a copy she trusts
    // (for example by comparing safety numbers in person)
    assert_eq!(&bundle.identity, bob_signer.pub_key_bytes());

    let base_nonce = create_nonce(&gen_session_id(), 0);
    let (mut alice_session, ciphertext) = MessageSession::new_initiator(
        alice_signer.clone(),
        base_nonce,
        &bundle.prekey,
        &bundle.identity,
    )
    .unwrap();

    // Alice sends Bob: the ciphertext, the prekey id, the base nonce and her identity key
    let prekey_id = bundle.prekey.id();

    // --- Bob's device: find the prekey Alice used and set up his side
    let mut bob_session = if let Some(prekey) = bob_one_time.remove(&prekey_id) {
        // One-time prekey: it is removed from Bob's store above and wiped when dropped
        // at the end of this block, which gives the session forward secrecy
        MessageSession::new_responder(
            &prekey,
            bob_signer.clone(),
            base_nonce,
            &ciphertext,
            alice_signer.pub_key_bytes(),
        )
        .unwrap()
    } else if prekey_id == bob_last_resort_signed.id() {
        // Last-resort prekey: kept until Bob rotates it
        MessageSession::new_responder(
            &bob_last_resort,
            bob_signer.clone(),
            base_nonce,
            &ciphertext,
            alice_signer.pub_key_bytes(),
        )
        .unwrap()
    } else {
        panic!("unknown prekey");
    };
    println!(
        "Session set up; Bob has {} one-time prekey secrets left on his device",
        bob_one_time.len()
    );

    // --- Talk
    let encrypted = alice_session.craft_message(b"Hi Bob!").unwrap();
    let message = bob_session.validate_message(&encrypted).unwrap();
    println!("Bob received: {}", String::from_utf8_lossy(&message));

    let encrypted = bob_session.craft_message(b"Hi Alice!").unwrap();
    let reply = alice_session.validate_message(&encrypted).unwrap();
    println!("Alice received: {}", String::from_utf8_lossy(&reply));
}
