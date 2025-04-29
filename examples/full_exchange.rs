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
