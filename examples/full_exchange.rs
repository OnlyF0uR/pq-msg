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
