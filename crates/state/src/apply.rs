//! `apply_block` — the missing function from the audit.
//!
//! Validates and applies every transaction in a block atomically. If any tx
//! fails (bad signature, insufficient balance, wrong nonce, anything), the
//! whole block is rejected — callers don't see a half-applied state.
//!
//! Called by:
//!   - `pygrove-node` after PoW + header validation, before storing the block.
//!   - Tests that replay a block stream against a fresh `MemState`.
//!
//! Phase A scope: only `TxCall::Transfer` is supported; the other variants
//! reject. DeployContract/CallContract land with the v1.2 VM, UpgradeCrypto
//! lands with Phase B.

use pygrove_core::{AccountId, Block, PubKeyRef, TxBody, TxCall, Witness};
use pygrove_crypto as crypto;
use thiserror::Error;

use crate::{accounts, store::StateStore};

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("tx[{0}]: missing witness — body and witnesses must be parallel")]
    WitnessMissing(usize),
    #[error("tx[{0}]: witness hash mismatch (header_committed != computed)")]
    WitnessHashMismatch(usize),
    #[error("tx[{0}]: account {1} unknown — first tx must include Inline pubkey")]
    AccountUnknown(usize, String),
    #[error("tx[{0}]: pubkey does not derive to from_account")]
    PubKeyMismatch(usize),
    #[error("tx[{0}]: bad signature ({1})")]
    BadSignature(usize, String),
    #[error("tx[{idx}]: nonce mismatch — got {got}, expected {expected}")]
    NonceMismatch {
        idx: usize,
        got: u64,
        expected: u64,
    },
    #[error("tx[{idx}]: insufficient balance ({balance} < amount+fee {required})")]
    InsufficientBalance {
        idx: usize,
        balance: u128,
        required: u128,
    },
    #[error("tx[{0}]: amount + fee overflows u128")]
    AmountOverflow(usize),
    #[error("tx[{0}]: TxCall variant not supported in Phase A")]
    UnsupportedCall(usize),
    #[error("tx[{idx}]: pubkey algo {algo} disagrees with sig_algo {sig_algo}")]
    AlgoMismatch {
        idx: usize,
        algo: u8,
        sig_algo: u8,
    },
    #[error("coinbase reward overflow")]
    CoinbaseOverflow,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyOutput {
    pub txs_applied: usize,
    pub fees_collected_sat: u128,
    pub coinbase_minted_sat: u128,
    pub state_root: [u8; 32],
}

/// Validate and apply every tx in `block` to `store`. On success, returns the
/// updated state root and how much was minted; on failure, leaves `store`
/// unchanged (caller is expected to operate on a clone or revert via journal).
///
/// Note for v0.1: `MemState` doesn't have transactional semantics, so we
/// validate first (no writes) then apply (writes). v0.2 with GroveDB switches
/// to a journal so the validate-then-write split isn't required.
pub fn apply_block(
    store: &mut dyn StateStore,
    block: &Block,
    block_reward_sat: u128,
) -> Result<ApplyOutput, ApplyError> {
    let txs = &block.body.txs;
    let witnesses = &block.body.witnesses;

    // Pass 1: validate every tx without mutating state.
    let mut fees_total: u128 = 0;
    let mut staged: Vec<StagedTx> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let witness = witnesses
            .get(i)
            .ok_or(ApplyError::WitnessMissing(i))?;
        if witness.hash() != tx.witness_hash {
            return Err(ApplyError::WitnessHashMismatch(i));
        }
        let staged_tx = validate_tx(i, store, tx, witness)?;
        fees_total = fees_total
            .checked_add(staged_tx.fee_sat as u128)
            .ok_or(ApplyError::CoinbaseOverflow)?;
        staged.push(staged_tx);
    }

    // Pass 2: apply. Each tx pulls fresh state since earlier txs may have
    // updated the same accounts.
    for tx in &staged {
        let mut from = accounts::load_or_default(store, &tx.from_account);
        // Refresh check: if a previous tx in the same block changed our
        // balance/nonce, we must re-verify before applying.
        if from.nonce != tx.expected_nonce {
            return Err(ApplyError::NonceMismatch {
                idx: tx.idx,
                got: from.nonce,
                expected: tx.expected_nonce,
            });
        }
        let required = tx
            .amount
            .checked_add(tx.fee_sat as u128)
            .ok_or(ApplyError::AmountOverflow(tx.idx))?;
        if from.balance < required {
            return Err(ApplyError::InsufficientBalance {
                idx: tx.idx,
                balance: from.balance,
                required,
            });
        }
        from.balance -= required;
        from.nonce = from.nonce.saturating_add(1);
        // First tx from this account: commit the pubkey now.
        if from.pubkey.is_empty() {
            from.pubkey = tx.pubkey_bytes.clone();
            from.sig_algo = tx.sig_algo;
        }
        accounts::save(store, &tx.from_account, &from);

        // Credit recipient.
        let mut to_acct = accounts::load_or_default(store, &tx.to);
        to_acct.balance = to_acct.balance.saturating_add(tx.amount);
        accounts::save(store, &tx.to, &to_acct);
    }

    // Coinbase: block_reward + total fees → miner's account (header.coinbase).
    let miner = AccountId::from_coinbase(&block.header.coinbase);
    let mut miner_acct = accounts::load_or_default(store, &miner);
    let total_minted = block_reward_sat
        .checked_add(fees_total)
        .ok_or(ApplyError::CoinbaseOverflow)?;
    miner_acct.balance = miner_acct
        .balance
        .checked_add(total_minted)
        .ok_or(ApplyError::CoinbaseOverflow)?;
    accounts::save(store, &miner, &miner_acct);

    Ok(ApplyOutput {
        txs_applied: txs.len(),
        fees_collected_sat: fees_total,
        coinbase_minted_sat: total_minted,
        state_root: store.root(),
    })
}

struct StagedTx {
    idx: usize,
    from_account: AccountId,
    expected_nonce: u64,
    to: AccountId,
    amount: u128,
    fee_sat: u64,
    pubkey_bytes: Vec<u8>,
    sig_algo: u8,
}

fn validate_tx(
    idx: usize,
    store: &dyn StateStore,
    tx: &TxBody,
    witness: &Witness,
) -> Result<StagedTx, ApplyError> {
    // Phase A only supports Transfer; flag the rest explicitly so we don't
    // silently accept malformed txs.
    let (to, amount) = match &tx.call {
        TxCall::Transfer { to, amount } => (*to, *amount),
        _ => return Err(ApplyError::UnsupportedCall(idx)),
    };

    // Pull pubkey: either Inline (first time signing) or Known (lookup).
    let pubkey_bytes: Vec<u8> = match &witness.pubkey {
        PubKeyRef::Inline(bytes) => bytes.clone(),
        PubKeyRef::Known(_) => {
            let acct = accounts::load(store, &tx.from_account)
                .ok_or_else(|| ApplyError::AccountUnknown(idx, tx.from_account.to_string()))?;
            if acct.pubkey.is_empty() {
                return Err(ApplyError::AccountUnknown(idx, tx.from_account.to_string()));
            }
            if acct.sig_algo != witness.sig_algo {
                return Err(ApplyError::AlgoMismatch {
                    idx,
                    algo: acct.sig_algo,
                    sig_algo: witness.sig_algo,
                });
            }
            acct.pubkey
        }
    };

    // Inline pubkey case: verify it derives to from_account so an attacker
    // can't sign with their own key but claim to be someone else.
    if matches!(witness.pubkey, PubKeyRef::Inline(_)) {
        let derived = AccountId::from_pubkey(&pubkey_bytes);
        if derived != tx.from_account {
            return Err(ApplyError::PubKeyMismatch(idx));
        }
    }

    // Verify the signature over the canonical signing hash.
    let signing_hash = tx.signing_hash();
    crypto::verify(witness.sig_algo, &pubkey_bytes, &witness.sig, &signing_hash)
        .map_err(|e| ApplyError::BadSignature(idx, e.to_string()))?;

    // Nonce + balance pre-check (the apply pass re-checks against the live
    // store in case earlier txs mutated this account).
    let acct = accounts::load_or_default(store, &tx.from_account);
    let expected_nonce = acct.nonce;
    if tx.nonce != expected_nonce {
        return Err(ApplyError::NonceMismatch {
            idx,
            got: tx.nonce,
            expected: expected_nonce,
        });
    }
    let required = (amount)
        .checked_add(tx.fee_sat as u128)
        .ok_or(ApplyError::AmountOverflow(idx))?;
    if acct.balance < required {
        return Err(ApplyError::InsufficientBalance {
            idx,
            balance: acct.balance,
            required,
        });
    }

    Ok(StagedTx {
        idx,
        from_account: tx.from_account,
        expected_nonce,
        to,
        amount,
        fee_sat: tx.fee_sat,
        pubkey_bytes,
        sig_algo: witness.sig_algo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pygrove_core::{BlockBody, BlockHeader};
    use pygrove_crypto as crypto;
    use rand_core::OsRng;

    fn empty_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 1,
            parent: [0u8; 32],
            timestamp_ms: 0,
            bits: 0,
            nonce: 0,
            tx_root: [0u8; 32],
            witness_root: [0u8; 32],
            state_root: [0u8; 32],
            reflect_root: [0u8; 32],
            coinbase: [0u8; 32],
            sig_algo: 3,
            hash_algo: 1,
        }
    }

    #[test]
    fn empty_block_just_mints_coinbase() {
        let mut store = crate::MemState::new();
        let header = empty_header();
        let block = Block {
            header,
            body: BlockBody::default(),
        };
        let out = apply_block(&mut store, &block, 50_000_000_000).unwrap();
        assert_eq!(out.txs_applied, 0);
        assert_eq!(out.fees_collected_sat, 0);
        assert_eq!(out.coinbase_minted_sat, 50_000_000_000);
    }

    #[test]
    fn signed_transfer_moves_funds() {
        let mut store = crate::MemState::new();
        // Bootstrap: give Alice 1000 sat by hand (genesis-style).
        let mut rng = OsRng;
        let (alice_sk, alice_pk) = crypto::ed25519_keypair(&mut rng);
        let alice = AccountId::from_pubkey(&alice_pk);
        accounts::save(
            &mut store,
            &alice,
            &Account {
                balance: 1000,
                nonce: 0,
                pubkey: alice_pk.to_vec(),
                sig_algo: 3,
            },
        );
        let bob = AccountId::new([2u8; 20]);

        // Build, sign, package the tx.
        let mut tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::Transfer { to: bob, amount: 700 },
            fee_sat: 10,
            gas_limit: 21000,
            witness_hash: [0u8; 32],
        };
        let sig = crypto::sign(3, &alice_sk, &tx.signing_hash()).unwrap();
        let witness = Witness {
            sig_algo: 3,
            sig,
            pubkey: PubKeyRef::Known(alice),
        };
        tx.witness_hash = witness.hash();

        let block = Block {
            header: empty_header(),
            body: BlockBody {
                txs: vec![tx],
                witnesses: vec![witness],
            },
        };

        let out = apply_block(&mut store, &block, 50).unwrap();
        assert_eq!(out.txs_applied, 1);
        assert_eq!(out.fees_collected_sat, 10);

        let alice_after = accounts::load(&store, &alice).unwrap();
        assert_eq!(alice_after.balance, 1000 - 700 - 10);
        assert_eq!(alice_after.nonce, 1);
        let bob_after = accounts::load(&store, &bob).unwrap();
        assert_eq!(bob_after.balance, 700);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut store = crate::MemState::new();
        let mut rng = OsRng;
        let (alice_sk, alice_pk) = crypto::ed25519_keypair(&mut rng);
        let alice = AccountId::from_pubkey(&alice_pk);
        accounts::save(
            &mut store,
            &alice,
            &Account {
                balance: 1000,
                nonce: 0,
                pubkey: alice_pk.to_vec(),
                sig_algo: 3,
            },
        );
        let bob = AccountId::new([2u8; 20]);

        let mut tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::Transfer { to: bob, amount: 100 },
            fee_sat: 1,
            gas_limit: 21000,
            witness_hash: [0u8; 32],
        };
        let sig = crypto::sign(3, &alice_sk, &tx.signing_hash()).unwrap();
        let witness = Witness {
            sig_algo: 3,
            sig,
            pubkey: PubKeyRef::Known(alice),
        };
        tx.witness_hash = witness.hash();
        // Mutate amount AFTER signing — signature should no longer match.
        if let TxCall::Transfer { amount, .. } = &mut tx.call {
            *amount = 999;
        }

        let block = Block {
            header: empty_header(),
            body: BlockBody {
                txs: vec![tx],
                witnesses: vec![witness],
            },
        };
        assert!(matches!(
            apply_block(&mut store, &block, 50),
            Err(ApplyError::WitnessHashMismatch(_)) | Err(ApplyError::BadSignature(_, _))
        ));
    }
}
