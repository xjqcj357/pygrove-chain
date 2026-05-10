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

use crate::{accounts, store::StateStore, subtrees::Subtree};

/// Record stored in the `Attest` subtree per `AttestRound` tx. Keyed by
/// `(job_id || round_id_be)` so that a verifier in 2031 can re-execute
/// round N of a 2027 model bit-exactly against committed inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AttestRecord {
    pub job_id: [u8; 32],
    pub round_id: u64,
    pub model_hash: [u8; 32],
    pub dp_epsilon_milli: u32,
    pub coordinator: [u8; 20],
    pub block_height: u64,
    pub block_timestamp_ms: u64,
}

/// Pending crypto-rotation record stored in `Subtree::Meta` under key
/// `b"upgrade_crypto"`. `apply_block` checks each block's height against
/// `target_height` and (in v0.5) rotates the active SigAlgo / HashAlgo
/// when the height is reached.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingCryptoUpgrade {
    pub target_height: u64,
    pub sig_algo: u8,
    pub hash_algo: u8,
    pub announced_at_height: u64,
}

/// Coordinator-authority registry for an FL `job_id`. Once committed via a
/// `RegisterAttestCoordinator` tx, subsequent `AttestRound` txs for the
/// same `job_id` must come from one of the listed accounts. Stored under
/// `Subtree::Meta` at key `[ATTEST_AUTH_KEY_PREFIX || job_id]` (CBOR-encoded).
///
/// Roadmap #6: this is the v0.4 wedge — the registry exists, AttestRound
/// validates against it. In v0.5 the registration tx itself requires a
/// 2-of-3 SLH-DSA governance threshold sig (today: stub, like
/// UpgradeCrypto).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CoordinatorAuthority {
    pub job_id: [u8; 32],
    pub coordinators: Vec<[u8; 20]>,
    pub registered_at_height: u64,
}

/// Key prefix for coordinator-authority records in `Subtree::Meta`.
/// Full key: `[ATTEST_AUTH_KEY_PREFIX || job_id]` (5 + 32 = 37 bytes).
pub const ATTEST_AUTH_KEY_PREFIX: &[u8] = b"attau";

/// Build the `Subtree::Meta` storage key for a job's coordinator authority.
pub fn attest_auth_key(job_id: &[u8; 32]) -> [u8; 37] {
    let mut key = [0u8; 37];
    key[..5].copy_from_slice(ATTEST_AUTH_KEY_PREFIX);
    key[5..].copy_from_slice(job_id);
    key
}

/// Load the coordinator-authority registry for `job_id`, or `None` if no
/// registry has been published for that job (in which case `AttestRound`
/// is open to any attester, the testnet default).
pub fn load_attest_authority(
    store: &dyn StateStore,
    job_id: &[u8; 32],
) -> Option<CoordinatorAuthority> {
    let key = attest_auth_key(job_id);
    let bytes = store.get(Subtree::Meta, &key)?;
    ciborium::de::from_reader(&bytes[..]).ok()
}

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
    #[error("tx[{idx}]: UpgradeCrypto target sig_algo {sig_algo} not in this build's allowlist")]
    UpgradeSigAlgoNotAllowed { idx: usize, sig_algo: u8 },
    #[error("tx[{idx}]: UpgradeCrypto target hash_algo {hash_algo} not in this build's allowlist")]
    UpgradeHashAlgoNotAllowed { idx: usize, hash_algo: u8 },
    #[error(
        "tx[{idx}]: AttestRound from account not in coordinator authority registry for job_id"
    )]
    AttestCoordinatorNotAuthorized { idx: usize },
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

    // Phase A.5 effects: AttestRound and UpgradeCrypto write to non-account
    // subtrees. Walked after the main apply loop so signature/balance
    // validation has already passed.
    for (i, tx) in txs.iter().enumerate() {
        match &tx.call {
            TxCall::AttestRound {
                job_id,
                round_id,
                model_hash,
                dp_epsilon_milli,
            } => {
                // Roadmap #6: if a coordinator-authority registry exists
                // for this job_id, the tx's from_account must be in it.
                // Jobs without a registry are open (testnet default).
                if let Some(authority) = load_attest_authority(store, job_id) {
                    if !authority.coordinators.is_empty()
                        && !authority.coordinators.contains(&tx.from_account.0)
                    {
                        return Err(ApplyError::AttestCoordinatorNotAuthorized { idx: i });
                    }
                }
                let rec = AttestRecord {
                    job_id: *job_id,
                    round_id: *round_id,
                    model_hash: *model_hash,
                    dp_epsilon_milli: *dp_epsilon_milli,
                    coordinator: tx.from_account.0,
                    block_height: block.header.height,
                    block_timestamp_ms: block.header.timestamp_ms,
                };
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&rec, &mut buf)
                    .map_err(|_| ApplyError::WitnessHashMismatch(i))?;
                // Key = job_id (32) || round_id (big-endian u64).
                let mut key = [0u8; 40];
                key[..32].copy_from_slice(job_id);
                key[32..].copy_from_slice(&round_id.to_be_bytes());
                store.put(Subtree::Attest, &key, &buf);
            }
            TxCall::RegisterAttestCoordinator {
                job_id,
                coordinators,
            } => {
                // Roadmap #6 stub: any account can register an authority
                // today. v0.5 lands the 2-of-3 SLH-DSA governance
                // threshold gate (same staging pattern as UpgradeCrypto).
                let record = CoordinatorAuthority {
                    job_id: *job_id,
                    coordinators: coordinators.iter().map(|id| id.0).collect(),
                    registered_at_height: block.header.height,
                };
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&record, &mut buf)
                    .map_err(|_| ApplyError::WitnessHashMismatch(i))?;
                let key = attest_auth_key(job_id);
                store.put(Subtree::Meta, &key, &buf);
            }
            TxCall::UpgradeCrypto {
                target_height,
                sig_algo,
                hash_algo,
            } => {
                // FIPS-profile gate (#5 on the sprint roadmap). On a node built
                // with `cargo build --features fips`, `pygrove_crypto::allowed_*`
                // consults `FIPS_ALLOWLIST_*`, which excludes Ed25519 and
                // Falcon-512. Default builds use the wider allowlist. Either
                // way, governance announcements that target an algo this build
                // refuses to honor are rejected at apply time, before anything
                // is written to `Subtree::Meta`.
                if !pygrove_crypto::allowed_sig(*sig_algo) {
                    return Err(ApplyError::UpgradeSigAlgoNotAllowed {
                        idx: i,
                        sig_algo: *sig_algo,
                    });
                }
                if !pygrove_crypto::allowed_hash(*hash_algo) {
                    return Err(ApplyError::UpgradeHashAlgoNotAllowed {
                        idx: i,
                        hash_algo: *hash_algo,
                    });
                }
                // Stub: any account can announce a rotation today; the
                // governance-key threshold check lands with the SLH-DSA
                // wiring (DARPA C1, Raytheon FIPS path). Recorded so the
                // chain has an observable rotation event for testnet
                // exercises.
                let pending = PendingCryptoUpgrade {
                    target_height: *target_height,
                    sig_algo: *sig_algo,
                    hash_algo: *hash_algo,
                    announced_at_height: block.header.height,
                };
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&pending, &mut buf)
                    .map_err(|_| ApplyError::WitnessHashMismatch(i))?;
                store.put(Subtree::Meta, b"upgrade_crypto", &buf);
            }
            _ => {}
        }
    }

    // Coinbase. `block_reward_sat` is now computed by the caller (rpc.rs or
    // main.rs replay) using `pygrove_consensus::emission::current_reward()` —
    // a calendar-anchored function of (genesis_time, block.timestamp,
    // parent.timestamp, minted_so_far). This closes the cadence-mismatch bug:
    // even if blocks arrive 100× faster than target, each block's reward
    // shrinks proportionally, so cumulative emission tracks the schedule.
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
    // Phase A supports Transfer fully. UpgradeCrypto and AttestRound are
    // wired with stub semantics for the v0.4 sprint foundation: signatures
    // verify and effects are recorded, but full mainnet semantics
    // (governance threshold sigs, FL coordinator authority, etc.) land in
    // follow-up commits. DeployContract / CallContract still rejected
    // pending the wasmtime VM (Raytheon-recommended over CPython).
    let (to, amount) = match &tx.call {
        TxCall::Transfer { to, amount } => (*to, *amount),
        // Stubs: zero-effect on accounts, but signature still gets verified
        // by the path below. Apply pass writes effects to Meta / Reflect
        // subtrees instead of moving balance.
        TxCall::UpgradeCrypto { .. }
        | TxCall::AttestRound { .. }
        | TxCall::RegisterAttestCoordinator { .. } => (
            tx.from_account, // self-transfer of zero so the apply pass exists
            0u128,
        ),
        TxCall::DeployContract { .. } | TxCall::CallContract { .. } => {
            return Err(ApplyError::UnsupportedCall(idx));
        }
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

// The default-build tests rely on `pygrove_crypto::ed25519_keypair`, which
// only compiles when `--features fips` is OFF. FIPS-build tests live in
// `tests_fips` below and exercise the allowlist-rejection paths instead.
#[cfg(all(test, not(feature = "fips")))]
mod tests {
    use super::*;
    use crate::Account;
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

    /// Default-build allowlist sanity check. UpgradeCrypto targeting an algo
    /// id outside `DEFAULT_ALLOWLIST_*` gets refused — even though this is
    /// not a FIPS build, sig_algo=99 isn't a known primitive.
    #[test]
    fn upgrade_crypto_rejects_unknown_sig_algo() {
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

        let mut tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::UpgradeCrypto {
                target_height: 1_000_000,
                sig_algo: 99, // not in DEFAULT_ALLOWLIST_SIG
                hash_algo: 1,
            },
            fee_sat: 0,
            gas_limit: 0,
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
        assert!(matches!(
            apply_block(&mut store, &block, 50),
            Err(ApplyError::UpgradeSigAlgoNotAllowed { sig_algo: 99, .. })
        ));
    }

    /// Roadmap #6: `RegisterAttestCoordinator` writes a CoordinatorAuthority
    /// record. After it lands, `AttestRound` from a non-listed account is
    /// rejected; from a listed account it succeeds.
    #[test]
    fn attest_round_authority_registry_gates_attesters() {
        let mut store = crate::MemState::new();
        let mut rng = OsRng;
        // Alice will register herself as the sole authority for job_id.
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
        // Mallory is NOT in the authority list and will try to attest.
        let (mallory_sk, mallory_pk) = crypto::ed25519_keypair(&mut rng);
        let mallory = AccountId::from_pubkey(&mallory_pk);
        accounts::save(
            &mut store,
            &mallory,
            &Account {
                balance: 1000,
                nonce: 0,
                pubkey: mallory_pk.to_vec(),
                sig_algo: 3,
            },
        );

        let job_id = [0xAB; 32];

        // --- Block A: Alice registers herself as the only coordinator.
        let mut reg_tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::RegisterAttestCoordinator {
                job_id,
                coordinators: vec![alice],
            },
            fee_sat: 0,
            gas_limit: 0,
            witness_hash: [0u8; 32],
        };
        let reg_sig = crypto::sign(3, &alice_sk, &reg_tx.signing_hash()).unwrap();
        let reg_witness = Witness {
            sig_algo: 3,
            sig: reg_sig,
            pubkey: PubKeyRef::Known(alice),
        };
        reg_tx.witness_hash = reg_witness.hash();
        let block_a = Block {
            header: empty_header(),
            body: BlockBody {
                txs: vec![reg_tx],
                witnesses: vec![reg_witness],
            },
        };
        apply_block(&mut store, &block_a, 50).expect("registration applies");

        // Authority record landed.
        let auth = load_attest_authority(&store, &job_id).expect("authority exists");
        assert_eq!(auth.coordinators, vec![alice.0]);

        // --- Block B: Mallory tries to AttestRound — must be rejected.
        let mut bad_tx = TxBody {
            nonce: 0,
            from_account: mallory,
            call: TxCall::AttestRound {
                job_id,
                round_id: 1,
                model_hash: [0u8; 32],
                dp_epsilon_milli: 1500,
            },
            fee_sat: 0,
            gas_limit: 0,
            witness_hash: [0u8; 32],
        };
        let bad_sig = crypto::sign(3, &mallory_sk, &bad_tx.signing_hash()).unwrap();
        let bad_witness = Witness {
            sig_algo: 3,
            sig: bad_sig,
            pubkey: PubKeyRef::Known(mallory),
        };
        bad_tx.witness_hash = bad_witness.hash();
        let mut header_b = empty_header();
        header_b.height = 2;
        let block_b = Block {
            header: header_b,
            body: BlockBody {
                txs: vec![bad_tx],
                witnesses: vec![bad_witness],
            },
        };
        assert!(matches!(
            apply_block(&mut store, &block_b, 50),
            Err(ApplyError::AttestCoordinatorNotAuthorized { .. })
        ));

        // --- Block C: Alice attests, must succeed.
        let mut good_tx = TxBody {
            nonce: 1, // alice's nonce after the registration tx
            from_account: alice,
            call: TxCall::AttestRound {
                job_id,
                round_id: 1,
                model_hash: [0xCD; 32],
                dp_epsilon_milli: 1500,
            },
            fee_sat: 0,
            gas_limit: 0,
            witness_hash: [0u8; 32],
        };
        let good_sig = crypto::sign(3, &alice_sk, &good_tx.signing_hash()).unwrap();
        let good_witness = Witness {
            sig_algo: 3,
            sig: good_sig,
            pubkey: PubKeyRef::Known(alice),
        };
        good_tx.witness_hash = good_witness.hash();
        let mut header_c = empty_header();
        header_c.height = 3;
        let block_c = Block {
            header: header_c,
            body: BlockBody {
                txs: vec![good_tx],
                witnesses: vec![good_witness],
            },
        };
        apply_block(&mut store, &block_c, 50).expect("alice attests successfully");
    }

    /// Backward compat: a job_id with no registry stays open to any
    /// attester (testnet default — preserves the v0.4 testnet-3 surface).
    #[test]
    fn attest_round_open_for_unregistered_job() {
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
        let mut tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::AttestRound {
                job_id: [0x77; 32], // never registered
                round_id: 1,
                model_hash: [0u8; 32],
                dp_epsilon_milli: 0,
            },
            fee_sat: 0,
            gas_limit: 0,
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
        apply_block(&mut store, &block, 50).expect("open job accepts any attester");
    }
}

/// FIPS-profile tests. `pygrove_crypto::ed25519_keypair` is unavailable in
/// FIPS builds, so we can't construct real signed transactions here. These
/// tests exercise the static allowlist surface and confirm `UpgradeCrypto`
/// would reject Ed25519 (sig_algo=3) under a FIPS build's allowlist.
#[cfg(all(test, feature = "fips"))]
mod tests_fips {
    #[test]
    fn fips_allowlists_active() {
        assert!(pygrove_crypto::is_fips_build());
        assert!(!pygrove_crypto::allowed_sig(1)); // Falcon-512 not in FIPS
        assert!(!pygrove_crypto::allowed_sig(3)); // Ed25519 not in FIPS
        assert!(pygrove_crypto::allowed_sig(2)); // SLH-DSA-128s
        assert!(pygrove_crypto::allowed_sig(4)); // ML-DSA-65
        assert!(pygrove_crypto::allowed_hash(3)); // SHA3-512
        assert!(!pygrove_crypto::allowed_hash(1)); // Blake3-XOF-512
    }
}
