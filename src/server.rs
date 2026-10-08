//! An in-memory reference prekey server (requires the `server` feature)
//!
//! A [`PrekeyServer`] holds every user's identity key and signed prekeys, and hands
//! each one-time prekey out only once. When a user's one-time prekeys run out, it
//! hands out their last-resort prekey instead.
//!
//! It is meant for prototypes, tests and as an executable description of the server's
//! rules. A production server must also:
//! - **Persist** prekeys in a database, and remove each one-time prekey in the same
//!   transaction that hands it out, so it can never be given out twice.
//! - **Authenticate accounts.** The first `publish` for a user decides their identity
//!   key; after that only the holder of that key can add prekeys, because every prekey
//!   must carry their signature. Who may claim a user name in the first place is up to
//!   your account system.
//! - **Rate-limit fetches.** Otherwise an attacker can drain a user's one-time prekeys,
//!   which pushes everyone onto the last-resort prekey and its weaker forward secrecy.
//! - **Deliver the session setup** (ciphertext, prekey id, base nonce, sender identity)
//!   and the messages themselves. That transport is not part of this crate.

use std::collections::{HashMap, hash_map::Entry};
use std::hash::Hash;

use crate::{
    errors::CryptoError, exchange::prekey::SignedPrekey, signatures::keypair::PublicKeyBytes,
};

/// What an initiator needs to start a session with a user
pub struct PrekeyBundle {
    /// The user's FN-DSA identity public key. Check it against a copy you trust
    /// (for example by comparing it in person) before relying on it.
    pub identity: PublicKeyBytes,
    /// A one-time prekey if one was left, otherwise the user's last-resort prekey
    pub prekey: SignedPrekey,
}

struct Account {
    identity: PublicKeyBytes,
    last_resort: SignedPrekey,
    one_time: Vec<SignedPrekey>,
}

/// In-memory store of users' prekeys, keyed by any user id type `K`
pub struct PrekeyServer<K> {
    accounts: HashMap<K, Account>,
}

impl<K: Eq + Hash> PrekeyServer<K> {
    /// Creates an empty server
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// Publishes a user's prekeys
    ///
    /// The first call for a user registers `identity`. Later calls must use the same
    /// identity; they add the new one-time prekeys and replace the last-resort prekey.
    /// Each one-time prekey should only be published once.
    ///
    /// # Arguments
    /// * `user` - The user's id
    /// * `identity` - The user's FN-DSA identity public key
    /// * `last_resort` - The user's current last-resort prekey
    /// * `one_time` - New one-time prekeys
    ///
    /// # Returns
    /// - `Result<(), CryptoError>`: `InvalidSignature` if any prekey is not signed by
    ///   `identity`, or `InvalidKey` if the user is registered with another identity.
    ///   Nothing is stored on error.
    pub fn publish(
        &mut self,
        user: K,
        identity: PublicKeyBytes,
        last_resort: SignedPrekey,
        one_time: Vec<SignedPrekey>,
    ) -> Result<(), CryptoError> {
        if !last_resort.verify(&identity) || !one_time.iter().all(|p| p.verify(&identity)) {
            return Err(CryptoError::InvalidSignature);
        }
        match self.accounts.entry(user) {
            Entry::Occupied(mut entry) => {
                let account = entry.get_mut();
                if account.identity != identity {
                    return Err(CryptoError::InvalidKey);
                }
                account.last_resort = last_resort;
                account.one_time.extend(one_time);
            }
            Entry::Vacant(entry) => {
                entry.insert(Account {
                    identity,
                    last_resort,
                    one_time,
                });
            }
        }
        Ok(())
    }

    /// Hands out a prekey bundle for starting a session with `user`
    ///
    /// A one-time prekey is removed from the server as it is handed out.
    ///
    /// # Returns
    /// The bundle, or `None` if the user is unknown
    pub fn fetch(&mut self, user: &K) -> Option<PrekeyBundle> {
        let account = self.accounts.get_mut(user)?;
        let prekey = account
            .one_time
            .pop()
            .unwrap_or_else(|| account.last_resort.clone());
        Some(PrekeyBundle {
            identity: account.identity,
            prekey,
        })
    }

    /// Number of one-time prekeys left for `user`, so their client knows when to publish more
    pub fn one_time_remaining(&self, user: &K) -> usize {
        self.accounts.get(user).map_or(0, |a| a.one_time.len())
    }
}

impl<K: Eq + Hash> Default for PrekeyServer<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exchange::pair::KEMPair,
        signatures::keypair::{SignerPair, ViewOperations},
    };

    fn prekey(owner: &mut SignerPair) -> SignedPrekey {
        SignedPrekey::new(owner, &KEMPair::create()).unwrap()
    }

    #[test]
    fn test_one_time_prekeys_are_handed_out_once() {
        let mut bob = SignerPair::create();
        let last_resort = prekey(&mut bob);
        let one_time = vec![prekey(&mut bob), prekey(&mut bob)];
        let mut ids: Vec<_> = one_time.iter().map(|p| p.id()).collect();

        let mut server = PrekeyServer::new();
        server
            .publish("bob", *bob.pub_key_bytes(), last_resort.clone(), one_time)
            .unwrap();
        assert_eq!(server.one_time_remaining(&"bob"), 2);

        let mut handed_out = vec![
            server.fetch(&"bob").unwrap().prekey.id(),
            server.fetch(&"bob").unwrap().prekey.id(),
        ];
        handed_out.sort();
        ids.sort();
        assert_eq!(handed_out, ids);
        assert_eq!(server.one_time_remaining(&"bob"), 0);

        // Out of one-time prekeys: everyone gets the last-resort prekey
        let bundle = server.fetch(&"bob").unwrap();
        assert_eq!(bundle.prekey.id(), last_resort.id());
        assert_eq!(bundle.identity, *bob.pub_key_bytes());
        assert!(server.fetch(&"bob").is_some());

        assert!(server.fetch(&"carol").is_none());
        assert_eq!(server.one_time_remaining(&"carol"), 0);
    }

    #[test]
    fn test_publish_rejects_foreign_prekeys_and_identity_change() {
        let mut bob = SignerPair::create();
        let mut mallory = SignerPair::create();
        let mut server = PrekeyServer::new();

        // A last-resort prekey not signed by the identity is refused
        let result = server.publish("bob", *bob.pub_key_bytes(), prekey(&mut mallory), vec![]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));

        // A one-time prekey not signed by the identity is refused, and nothing is stored
        let result = server.publish(
            "bob",
            *bob.pub_key_bytes(),
            prekey(&mut bob),
            vec![prekey(&mut mallory)],
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
        assert!(server.fetch(&"bob").is_none());

        server
            .publish("bob", *bob.pub_key_bytes(), prekey(&mut bob), vec![])
            .unwrap();

        // Once registered, a user's identity can't be swapped out
        let result = server.publish(
            "bob",
            *mallory.pub_key_bytes(),
            prekey(&mut mallory),
            vec![],
        );
        assert!(matches!(result, Err(CryptoError::InvalidKey)));

        // The real owner can add more prekeys and replace the last-resort prekey
        let new_last_resort = prekey(&mut bob);
        server
            .publish(
                "bob",
                *bob.pub_key_bytes(),
                new_last_resort.clone(),
                vec![prekey(&mut bob)],
            )
            .unwrap();
        assert_eq!(server.one_time_remaining(&"bob"), 1);
        server.fetch(&"bob").unwrap();
        assert_eq!(
            server.fetch(&"bob").unwrap().prekey.id(),
            new_last_resort.id()
        );
    }

    #[test]
    fn test_default_is_empty() {
        let mut server = PrekeyServer::<u32>::default();
        assert!(server.fetch(&1).is_none());
    }
}
