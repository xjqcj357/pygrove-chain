//! Account state: balance, nonce, and (since Phase A) the public key the account
//! signs with. Stored under the `Subtree::Accounts` namespace, keyed by the raw
//! 20 bytes of `AccountId`.

use pygrove_core::AccountId;
use serde::{Deserialize, Serialize};

use crate::{store::StateStore, subtrees::Subtree};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
    /// Public key the account signs with. Empty until the account first signs
    /// a transaction (the witness's `Inline` pubkey is committed here at that
    /// point). For receive-only accounts this stays empty — anyone can credit
    /// them, but they can't spend until they commit a key.
    #[serde(default, with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// Algo tag of `pubkey` — Ed25519 (3) in Phase A. An UpgradeCrypto rotation
    /// in Phase B writes a new sig_algo for accounts created post-rotation;
    /// existing accounts retain their original algo until they re-key.
    #[serde(default)]
    pub sig_algo: u8,
}

pub fn load(store: &dyn StateStore, id: &AccountId) -> Option<Account> {
    let bytes = store.get(Subtree::Accounts, &id.0)?;
    ciborium::de::from_reader(&bytes[..]).ok()
}

pub fn load_or_default(store: &dyn StateStore, id: &AccountId) -> Account {
    load(store, id).unwrap_or_default()
}

pub fn save(store: &mut dyn StateStore, id: &AccountId, account: &Account) {
    let mut buf = Vec::new();
    // Deterministic CBOR encoding — ciborium is canonical for our shape (no
    // float fields, no maps with non-string keys, no NaNs).
    ciborium::ser::into_writer(account, &mut buf)
        .expect("Account serializes (no f64, no maps with non-string keys)");
    store.put(Subtree::Accounts, &id.0, &buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemState;

    #[test]
    fn unknown_account_is_default() {
        let s = MemState::new();
        let id = AccountId::new([1u8; 20]);
        assert_eq!(load(&s, &id).map(|a| a.balance), None);
        assert_eq!(load_or_default(&s, &id).balance, 0);
    }

    #[test]
    fn save_then_load_roundtrip() {
        let mut s = MemState::new();
        let id = AccountId::new([7u8; 20]);
        let acct = Account {
            balance: 50_000_000_000,
            nonce: 3,
            pubkey: vec![9u8; 32],
            sig_algo: 3,
        };
        save(&mut s, &id, &acct);
        let loaded = load(&s, &id).unwrap();
        assert_eq!(loaded.balance, acct.balance);
        assert_eq!(loaded.nonce, acct.nonce);
        assert_eq!(loaded.pubkey, acct.pubkey);
        assert_eq!(loaded.sig_algo, acct.sig_algo);
    }
}
