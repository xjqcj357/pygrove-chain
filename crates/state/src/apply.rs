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

use pygrove_consensus::reflection::Reflection;
use pygrove_core::{AccountId, Block, PubKeyRef, TxBody, TxCall, Witness};
use pygrove_crypto as crypto;
use std::collections::BTreeSet;
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
/// `target_height` and rotates the active SigAlgo / HashAlgo when the
/// height is reached, by writing an [`ActiveCrypto`] record.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingCryptoUpgrade {
    pub target_height: u64,
    pub sig_algo: u8,
    pub hash_algo: u8,
    pub announced_at_height: u64,
}

/// Active crypto-suite record written when a pending `UpgradeCrypto`
/// reaches its `target_height`. Stored under `Subtree::Meta` at key
/// `b"active_crypto"`. Subsequent transactions are expected to use the
/// algorithms specified here; full enforcement of that contract lands
/// with the governance threshold-sig wiring.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Copy)]
pub struct ActiveCrypto {
    pub sig_algo: u8,
    pub hash_algo: u8,
    pub activated_at_height: u64,
}

/// Load the currently-active crypto-suite record. Returns `None` if no
/// `UpgradeCrypto` has been activated yet (i.e. the genesis sig/hash
/// algos still apply).
pub fn load_active_crypto(store: &dyn StateStore) -> Option<ActiveCrypto> {
    let bytes = store.get(Subtree::Meta, b"active_crypto")?;
    ciborium::de::from_reader(&bytes[..]).ok()
}

/// Load the most recent per-block [`Reflection`] record. This is what
/// the WASM VM's `chain_reflect_get` host function (v0.5) returns for
/// the canonical `latest` key.
pub fn load_latest_reflection(store: &dyn StateStore) -> Option<Reflection> {
    let bytes = store.get(Subtree::Reflect, b"latest")?;
    ciborium::de::from_reader(&bytes[..]).ok()
}

/// One member of the governance committee. Each member has a signer-id
/// (arbitrary opaque), a sig_algo, and a pubkey blob. The signer-id is
/// what `GovernanceSig` references — the algo + pubkey come from this
/// record at verify time.
///
/// Today the committee is set at genesis (or bootstrap-set by the first
/// `SetGovernance` tx if missing). Future rotations swap members via a
/// `SetGovernance` proof signed by the current threshold-many members.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GovernanceSigner {
    pub signer_id: [u8; 32],
    pub sig_algo: u8,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
}

/// The active governance config. Committed to `Subtree::Meta` at key
/// `b"governance"`. A k-of-N threshold-signature requirement for
/// `UpgradeCrypto`, `RegisterAttestCoordinator`, and future
/// `SetGovernance` updates.
///
/// **Today**, members carry their pubkeys directly (Ed25519 / Falcon).
/// **Mainnet**, members will be 2-of-3 SLH-DSA-128s with HSM custody;
/// the wire format is unchanged — only the `sig_algo` field switches.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GovernanceConfig {
    pub epoch: u64,
    pub threshold: u32,
    pub signers: Vec<GovernanceSigner>,
}

impl GovernanceConfig {
    /// Validates the config is internally well-formed.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.signers.is_empty() {
            return Err("governance: signers cannot be empty");
        }
        if self.threshold == 0 {
            return Err("governance: threshold must be > 0");
        }
        if (self.threshold as usize) > self.signers.len() {
            return Err("governance: threshold > signers.len()");
        }
        // Duplicate signer_ids are not allowed.
        let mut seen: std::collections::BTreeSet<&[u8; 32]> =
            std::collections::BTreeSet::new();
        for s in &self.signers {
            if !seen.insert(&s.signer_id) {
                return Err("governance: duplicate signer_id");
            }
        }
        Ok(())
    }
}

/// A single signature from one governance member.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GovernanceSig {
    pub signer_id: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// A k-of-N threshold-signature proof. The verifier walks the
/// `signatures` vec, looks up each `signer_id` in the active
/// [`GovernanceConfig`], verifies the signature against the
/// caller-supplied 32-byte message hash, and accepts the proof when
/// distinct-signer verifications meet `threshold`.
///
/// Duplicate `signer_id`s in the proof count once. Unknown signers are
/// silently dropped (not a hard failure — lets the proof tolerate stale
/// committee snapshots).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GovernanceProof {
    pub signatures: Vec<GovernanceSig>,
}

/// Load the active governance config, or `None` if the chain is in
/// bootstrap mode (no config committed yet).
pub fn load_governance(store: &dyn StateStore) -> Option<GovernanceConfig> {
    let bytes = store.get(Subtree::Meta, b"governance")?;
    ciborium::de::from_reader(&bytes[..]).ok()
}

/// Verify a [`GovernanceProof`] reaches `cfg.threshold` distinct valid
/// signatures over `msg`. Returns `Ok(())` on success or a specific
/// error variant on failure.
pub fn verify_governance_proof(
    cfg: &GovernanceConfig,
    proof: &GovernanceProof,
    msg: &[u8; 32],
) -> Result<(), GovernanceError> {
    if (proof.signatures.len() as u32) < cfg.threshold {
        return Err(GovernanceError::BelowThreshold {
            got: proof.signatures.len() as u32,
            need: cfg.threshold,
        });
    }
    let mut seen: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    let mut verified: u32 = 0;
    for sig in &proof.signatures {
        if !seen.insert(sig.signer_id) {
            continue; // duplicate signer_id, counts once
        }
        let signer = match cfg.signers.iter().find(|s| s.signer_id == sig.signer_id) {
            Some(s) => s,
            None => continue, // unknown signer, ignored (not failure)
        };
        if crypto::verify(signer.sig_algo, &signer.pubkey, &sig.sig, msg).is_ok() {
            verified += 1;
            if verified >= cfg.threshold {
                return Ok(());
            }
        }
    }
    Err(GovernanceError::BelowThreshold {
        got: verified,
        need: cfg.threshold,
    })
}

/// Canonical signing payload for an `UpgradeCrypto` governance proof.
/// Domain-tagged so a sig over one governance action cannot be replayed
/// against another.
pub fn upgrade_crypto_gov_payload(
    target_height: u64,
    sig_algo: u8,
    hash_algo: u8,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"PGgov:upgrade\x00");
    h.update(&target_height.to_le_bytes());
    h.update(&[sig_algo, hash_algo]);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Canonical signing payload for a `RegisterAttestCoordinator`
/// governance proof. Coordinator list is sorted by `AccountId` bytes
/// before hashing so order-independent.
pub fn register_attest_gov_payload(
    job_id: &[u8; 32],
    coordinators: &[AccountId],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"PGgov:regattest\x00");
    h.update(job_id);
    h.update(&(coordinators.len() as u32).to_le_bytes());
    let mut ids: Vec<&AccountId> = coordinators.iter().collect();
    ids.sort_by_key(|a| a.0);
    for id in ids {
        h.update(&id.0);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Canonical signing payload for a `SetGovernance` proof. Includes the
/// CBOR-canonical encoding of the new config so any future rotation is
/// bound to the exact payload it authorized.
pub fn set_governance_gov_payload(new_config: &GovernanceConfig) -> [u8; 32] {
    let mut buf = Vec::new();
    // Deterministic CBOR. ciborium isn't strictly canonical-CBOR
    // out of the box, but for fixed-shape structs the encoding is
    // stable across calls — good enough for a domain-tagged payload.
    let _ = ciborium::ser::into_writer(new_config, &mut buf);
    let mut h = blake3::Hasher::new();
    h.update(b"PGgov:setgov\x00");
    h.update(&(buf.len() as u32).to_le_bytes());
    h.update(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Errors specific to the governance threshold path. Surfaced from
/// `verify_governance_proof` and re-wrapped into [`ApplyError`] at the
/// call sites.
#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("governance proof below threshold: got {got}, need {need}")]
    BelowThreshold { got: u32, need: u32 },
}

/// Load the reflection record for a specific block height. Returns
/// `None` if that block hasn't been applied yet.
pub fn load_reflection_at(store: &dyn StateStore, height: u64) -> Option<Reflection> {
    let mut key = [0u8; 14];
    key[..6].copy_from_slice(b"block/");
    key[6..].copy_from_slice(&height.to_be_bytes());
    let bytes = store.get(Subtree::Reflect, &key)?;
    ciborium::de::from_reader(&bytes[..]).ok()
}

/// Coordinator-authority registry for an FL `job_id`. Once committed via a
/// `RegisterAttestCoordinator` tx, subsequent `AttestRound` (and
/// `AttestPedigree`) txs for the same `job_id` must come from one of the
/// listed accounts. Stored under `Subtree::Meta` at key
/// `[ATTEST_AUTH_KEY_PREFIX || job_id]` (CBOR-encoded).
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

/// DLA-shape supply-chain pedigree record. Same storage cadence as
/// `AttestRecord`: keyed by `(job_id, lot_id)` so a 2030 auditor can
/// reproduce a 2027 component's chain of custody bit-exactly.
///
/// Roadmap #7. Raytheon flagship (component-pedigree variant of
/// `AttestRound`). Reuses the `Subtree::Attest` subtree; key prefix
/// distinguishes pedigree records from FL-round records.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PedigreeRecord {
    pub job_id: [u8; 32],
    pub lot_id: [u8; 16],
    pub supplier: [u8; 32],
    pub cage_code: [u8; 5],
    pub attestation_authority: [u8; 32],
    pub attester: [u8; 20],
    pub block_height: u64,
    pub block_timestamp_ms: u64,
}

/// Key prefix for pedigree records in `Subtree::Attest`.
/// Full key: `[PEDIGREE_KEY_PREFIX || job_id || lot_id]` (4 + 32 + 16 = 52 bytes).
/// Distinguishes from `AttestRound` records (40 bytes, no prefix).
pub const PEDIGREE_KEY_PREFIX: &[u8] = b"ped/";

/// Build the `Subtree::Attest` storage key for a pedigree record.
pub fn pedigree_key(job_id: &[u8; 32], lot_id: &[u8; 16]) -> [u8; 52] {
    let mut key = [0u8; 52];
    key[..4].copy_from_slice(PEDIGREE_KEY_PREFIX);
    key[4..36].copy_from_slice(job_id);
    key[36..].copy_from_slice(lot_id);
    key
}

/// CAGE codes are 5-character alphanumeric identifiers per DoD 4100.39-M.
/// Pedigree apply rejects anything else.
fn is_valid_cage(cage: &[u8; 5]) -> bool {
    cage.iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
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
    #[error("tx[{idx}]: AttestPedigree cage_code must be 5 ASCII chars [A-Z0-9]")]
    PedigreeCageCodeInvalid { idx: usize },
    #[error("tx[{idx}]: governance proof required but missing")]
    GovernanceProofMissing { idx: usize },
    #[error("tx[{idx}]: governance proof failed verification: {reason}")]
    GovernanceProofInvalid { idx: usize, reason: String },
    #[error("tx[{idx}]: governance config is malformed: {reason}")]
    GovernanceConfigInvalid { idx: usize, reason: String },
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
                // No governance proof on AttestRound — gov gates the
                // *registry* update via RegisterAttestCoordinator below,
                // not the per-round attestation itself.
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
                gov_proof,
            } => {
                // If governance is configured, require a k-of-N proof
                // over the canonical (job_id, sorted coordinators)
                // payload. Bootstrap mode (no governance committed)
                // accepts any signer — preserves the v0.4 testnet-3
                // behavior until SetGovernance is published.
                if let Some(cfg) = load_governance(store) {
                    if gov_proof.is_empty() {
                        return Err(ApplyError::GovernanceProofMissing { idx: i });
                    }
                    let proof: GovernanceProof = ciborium::de::from_reader(&gov_proof[..])
                        .map_err(|e| ApplyError::GovernanceProofInvalid {
                            idx: i,
                            reason: format!("decode: {e}"),
                        })?;
                    let payload = register_attest_gov_payload(job_id, coordinators);
                    verify_governance_proof(&cfg, &proof, &payload).map_err(|e| {
                        ApplyError::GovernanceProofInvalid {
                            idx: i,
                            reason: e.to_string(),
                        }
                    })?;
                }
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
            TxCall::AttestPedigree {
                job_id,
                lot_id,
                supplier,
                cage_code,
                attestation_authority,
            } => {
                // Roadmap #7: DLA-shape supply-chain provenance.
                // Validate CAGE code as 5 ASCII alphanumeric chars.
                if !is_valid_cage(cage_code) {
                    return Err(ApplyError::PedigreeCageCodeInvalid { idx: i });
                }
                // Coordinator authority registry shared with AttestRound.
                if let Some(authority) = load_attest_authority(store, job_id) {
                    if !authority.coordinators.is_empty()
                        && !authority.coordinators.contains(&tx.from_account.0)
                    {
                        return Err(ApplyError::AttestCoordinatorNotAuthorized { idx: i });
                    }
                }
                let record = PedigreeRecord {
                    job_id: *job_id,
                    lot_id: *lot_id,
                    supplier: *supplier,
                    cage_code: *cage_code,
                    attestation_authority: *attestation_authority,
                    attester: tx.from_account.0,
                    block_height: block.header.height,
                    block_timestamp_ms: block.header.timestamp_ms,
                };
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&record, &mut buf)
                    .map_err(|_| ApplyError::WitnessHashMismatch(i))?;
                let key = pedigree_key(job_id, lot_id);
                store.put(Subtree::Attest, &key, &buf);
            }
            TxCall::UpgradeCrypto {
                target_height,
                sig_algo,
                hash_algo,
                gov_proof,
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
                // Governance threshold gate. Same pattern as
                // RegisterAttestCoordinator: bootstrap (no config) →
                // open; configured → require k-of-N proof over the
                // upgrade_crypto_gov_payload hash.
                if let Some(cfg) = load_governance(store) {
                    if gov_proof.is_empty() {
                        return Err(ApplyError::GovernanceProofMissing { idx: i });
                    }
                    let proof: GovernanceProof = ciborium::de::from_reader(&gov_proof[..])
                        .map_err(|e| ApplyError::GovernanceProofInvalid {
                            idx: i,
                            reason: format!("decode: {e}"),
                        })?;
                    let payload =
                        upgrade_crypto_gov_payload(*target_height, *sig_algo, *hash_algo);
                    verify_governance_proof(&cfg, &proof, &payload).map_err(|e| {
                        ApplyError::GovernanceProofInvalid {
                            idx: i,
                            reason: e.to_string(),
                        }
                    })?;
                }
                // Recorded so the chain has an observable rotation
                // event. Pre-governance: any account can announce
                // (bootstrap); post-governance: k-of-N gates.
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
            TxCall::SetGovernance {
                config_cbor,
                gov_proof,
            } => {
                // Decode + validate the new config first; bad configs
                // are refused even in bootstrap.
                let new_cfg: GovernanceConfig =
                    ciborium::de::from_reader(&config_cbor[..]).map_err(|e| {
                        ApplyError::GovernanceConfigInvalid {
                            idx: i,
                            reason: format!("decode: {e}"),
                        }
                    })?;
                new_cfg
                    .validate()
                    .map_err(|reason| ApplyError::GovernanceConfigInvalid {
                        idx: i,
                        reason: reason.into(),
                    })?;
                // If a config exists already, require k-of-N proof
                // from the current set over the new config's payload.
                // Bootstrap (no existing config) accepts any signer.
                if let Some(current) = load_governance(store) {
                    if gov_proof.is_empty() {
                        return Err(ApplyError::GovernanceProofMissing { idx: i });
                    }
                    let proof: GovernanceProof = ciborium::de::from_reader(&gov_proof[..])
                        .map_err(|e| ApplyError::GovernanceProofInvalid {
                            idx: i,
                            reason: format!("decode: {e}"),
                        })?;
                    let payload = set_governance_gov_payload(&new_cfg);
                    verify_governance_proof(&current, &proof, &payload).map_err(|e| {
                        ApplyError::GovernanceProofInvalid {
                            idx: i,
                            reason: e.to_string(),
                        }
                    })?;
                }
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&new_cfg, &mut buf)
                    .map_err(|_| ApplyError::WitnessHashMismatch(i))?;
                store.put(Subtree::Meta, b"governance", &buf);
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

    // Reflection write — the chain reading its own past.
    //
    // `apply_block` now emits a `Reflection` record per block to
    // `Subtree::Reflect`, both at `[b"block/" || height_be]` for
    // historical lookup and at `b"latest"` for the most-recent reading
    // (cheap chain_reflect_get target). Windowed stats (short/long/epoch)
    // are computed at query time by aggregating the per-block records.
    //
    // Each record's fields:
    //   - hashrate_proxy: header `bits` (the difficulty target encoding).
    //     A real hashrate estimate needs τ, the time interval, and the
    //     comparison to expected work; the consensus crate's reflection
    //     window walker (v0.5+) will derive that.
    //   - active_addresses: count of distinct `from_account` in this
    //     block's txs (sybil guards aren't applied here yet — the
    //     filtered version is computed during reflection-window rollup).
    //   - fee_sum: total fees collected in this block.
    //   - emission: coinbase + fees minted in this block.
    //   - r_h_q64, r_a_q64, stability_bias: zeroed at this layer.
    //     Computed by the consensus-side window walker that reads these
    //     records and produces the long-window accordion inputs.
    let mut active: BTreeSet<[u8; 20]> = BTreeSet::new();
    for tx in txs {
        active.insert(tx.from_account.0);
    }
    let reflection = Reflection {
        hashrate_proxy: block.header.bits as u128,
        active_addresses: active.len() as u64,
        fee_sum: fees_total,
        emission: total_minted,
        r_h_q64: 0,
        r_a_q64: 0,
        stability_bias: 0,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&reflection, &mut buf)
        .map_err(|_| ApplyError::CoinbaseOverflow)?;
    let mut block_key = [0u8; 14]; // b"block/" (6) + height u64-be (8)
    block_key[..6].copy_from_slice(b"block/");
    block_key[6..].copy_from_slice(&block.header.height.to_be_bytes());
    store.put(Subtree::Reflect, &block_key, &buf);
    store.put(Subtree::Reflect, b"latest", &buf);

    // UpgradeCrypto activation: if a pending rotation targets this
    // block's height, promote it from `pending` to `active`. Recorded
    // under `Subtree::Meta` at key `b"active_crypto"`. Consensus reads
    // this on the next block to know which algos apply going forward.
    //
    // Today the activation is just a record swap; future tx validation
    // will consult the active record to set the canonical sig/hash algo
    // for new transactions. The rotation is observable by anyone
    // walking the state.
    if let Some(pending_bytes) = store.get(Subtree::Meta, b"upgrade_crypto") {
        if let Ok(pending) = ciborium::de::from_reader::<PendingCryptoUpgrade, _>(&pending_bytes[..])
        {
            if pending.target_height == block.header.height {
                let active = ActiveCrypto {
                    sig_algo: pending.sig_algo,
                    hash_algo: pending.hash_algo,
                    activated_at_height: block.header.height,
                };
                let mut buf = Vec::new();
                if ciborium::ser::into_writer(&active, &mut buf).is_ok() {
                    store.put(Subtree::Meta, b"active_crypto", &buf);
                }
            }
        }
    }

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
        | TxCall::RegisterAttestCoordinator { .. }
        | TxCall::AttestPedigree { .. }
        | TxCall::SetGovernance { .. } => (
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

// State tests use `pygrove_crypto::ed25519_keypair`. We don't expose a `fips`
// feature on the state crate (see Cargo.toml note); `pygrove-crypto`'s default
// features include `ed25519`, so this test module always compiles. FIPS-mode
// dispatch tests live in `pygrove-crypto`.
#[cfg(test)]
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
                gov_proof: Vec::new(),
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
                gov_proof: Vec::new(),
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

    /// Roadmap #7: DLA-shape pedigree attestation. Same authority gate as
    /// AttestRound; record lands in Subtree::Attest under a distinct
    /// key prefix so it doesn't collide with FL-round records.
    #[test]
    fn attest_pedigree_writes_record_and_validates_cage() {
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
        let job_id = [0x11; 32]; // not registered → open to any attester
        let lot_id = [0x22; 16];

        // --- Block A: valid CAGE code "1ABC2".
        let mut tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::AttestPedigree {
                job_id,
                lot_id,
                supplier: [0x33; 32],
                cage_code: *b"1ABC2",
                attestation_authority: [0x44; 32],
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
        let block_a = Block {
            header: empty_header(),
            body: BlockBody {
                txs: vec![tx],
                witnesses: vec![witness],
            },
        };
        apply_block(&mut store, &block_a, 50).expect("valid pedigree applies");

        // Record landed under the distinguishing pedigree-key prefix.
        let key = pedigree_key(&job_id, &lot_id);
        let raw = store.get(Subtree::Attest, &key).expect("pedigree record");
        let rec: PedigreeRecord = ciborium::de::from_reader(&raw[..]).unwrap();
        assert_eq!(rec.job_id, job_id);
        assert_eq!(rec.lot_id, lot_id);
        assert_eq!(&rec.cage_code, b"1ABC2");
        assert_eq!(rec.attester, alice.0);

        // --- Block B: invalid CAGE code "abcde" (lowercase) → rejected.
        let mut bad_tx = TxBody {
            nonce: 1,
            from_account: alice,
            call: TxCall::AttestPedigree {
                job_id,
                lot_id: [0x55; 16],
                supplier: [0x33; 32],
                cage_code: *b"abcde", // lowercase, not allowed
                attestation_authority: [0x44; 32],
            },
            fee_sat: 0,
            gas_limit: 0,
            witness_hash: [0u8; 32],
        };
        let bad_sig = crypto::sign(3, &alice_sk, &bad_tx.signing_hash()).unwrap();
        let bad_witness = Witness {
            sig_algo: 3,
            sig: bad_sig,
            pubkey: PubKeyRef::Known(alice),
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
            Err(ApplyError::PedigreeCageCodeInvalid { .. })
        ));
    }

    /// Reflection write happens on every apply_block, even an empty one.
    /// The `latest` key holds the most recent block's reflection record.
    #[test]
    fn reflection_record_written_on_apply() {
        let mut store = crate::MemState::new();
        let mut header = empty_header();
        header.height = 5;
        header.bits = 0x1d00ffff;
        let block = Block {
            header,
            body: BlockBody::default(),
        };
        apply_block(&mut store, &block, 50_000_000_000).unwrap();

        let r = load_latest_reflection(&store).expect("latest reflection");
        assert_eq!(r.hashrate_proxy, 0x1d00ffff);
        assert_eq!(r.active_addresses, 0);
        assert_eq!(r.fee_sum, 0);
        assert_eq!(r.emission, 50_000_000_000);

        let r2 = load_reflection_at(&store, 5).expect("per-height reflection");
        assert_eq!(r2.hashrate_proxy, r.hashrate_proxy);
        assert_eq!(r2.emission, r.emission);
    }

    /// Roadmap follow-up: UpgradeCrypto rotation activates when
    /// `block.height == target_height`. Before activation, no
    /// `active_crypto` record exists; after, the record reflects the
    /// announced algos.
    #[test]
    fn upgrade_crypto_activates_at_target_height() {
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

        // Announce at height 1, target height 3.
        let mut tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::UpgradeCrypto {
                target_height: 3,
                sig_algo: 1, // Falcon-512
                hash_algo: 1,
                gov_proof: Vec::new(),
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

        let block_a = Block {
            header: {
                let mut h = empty_header();
                h.height = 1;
                h
            },
            body: BlockBody {
                txs: vec![tx],
                witnesses: vec![witness],
            },
        };
        apply_block(&mut store, &block_a, 50).expect("announce");

        // Before the target height, no active_crypto record yet.
        assert!(load_active_crypto(&store).is_none());

        // Empty block at height 2 — still no activation.
        let block_b = Block {
            header: {
                let mut h = empty_header();
                h.height = 2;
                h
            },
            body: BlockBody::default(),
        };
        apply_block(&mut store, &block_b, 50).expect("h=2");
        assert!(load_active_crypto(&store).is_none());

        // At height 3, the pending upgrade activates.
        let block_c = Block {
            header: {
                let mut h = empty_header();
                h.height = 3;
                h
            },
            body: BlockBody::default(),
        };
        apply_block(&mut store, &block_c, 50).expect("h=3 activates");
        let active = load_active_crypto(&store).expect("active_crypto record");
        assert_eq!(active.sig_algo, 1);
        assert_eq!(active.hash_algo, 1);
        assert_eq!(active.activated_at_height, 3);
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

    /// k-of-N governance threshold sig: bootstrap install, then enforce.
    ///
    /// 1. No governance exists. Alice's `SetGovernance` (with empty
    ///    proof) installs a 2-of-3 config — accepted as bootstrap.
    /// 2. Alice tries an `UpgradeCrypto` with no proof — rejected
    ///    (`GovernanceProofMissing`).
    /// 3. Alice signs the gov payload with her gov key, but that's
    ///    1-of-3 — rejected (`GovernanceProofInvalid` /
    ///    `BelowThreshold`).
    /// 4. Two of three gov keys sign — accepted, pending record lands.
    #[test]
    fn governance_threshold_gates_upgrade_crypto() {
        let mut store = crate::MemState::new();
        let mut rng = OsRng;

        // Alice as the tx sender. Three gov keypairs are a separate
        // namespace (the gov committee, not Alice).
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

        let (g1_sk, g1_pk) = crypto::ed25519_keypair(&mut rng);
        let (g2_sk, g2_pk) = crypto::ed25519_keypair(&mut rng);
        let (_g3_sk, g3_pk) = crypto::ed25519_keypair(&mut rng);
        let g1_id = [0xA1u8; 32];
        let g2_id = [0xA2u8; 32];
        let g3_id = [0xA3u8; 32];

        let gov_cfg = GovernanceConfig {
            epoch: 1,
            threshold: 2,
            signers: vec![
                GovernanceSigner {
                    signer_id: g1_id,
                    sig_algo: 3,
                    pubkey: g1_pk.to_vec(),
                },
                GovernanceSigner {
                    signer_id: g2_id,
                    sig_algo: 3,
                    pubkey: g2_pk.to_vec(),
                },
                GovernanceSigner {
                    signer_id: g3_id,
                    sig_algo: 3,
                    pubkey: g3_pk.to_vec(),
                },
            ],
        };

        // --- Step 1: bootstrap install via SetGovernance.
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&gov_cfg, &mut cbor).unwrap();
        let mut set_tx = TxBody {
            nonce: 0,
            from_account: alice,
            call: TxCall::SetGovernance {
                config_cbor: cbor,
                gov_proof: Vec::new(), // bootstrap: empty proof accepted
            },
            fee_sat: 0,
            gas_limit: 0,
            witness_hash: [0u8; 32],
        };
        let sig = crypto::sign(3, &alice_sk, &set_tx.signing_hash()).unwrap();
        let witness = Witness {
            sig_algo: 3,
            sig,
            pubkey: PubKeyRef::Known(alice),
        };
        set_tx.witness_hash = witness.hash();
        let block_install = Block {
            header: empty_header(),
            body: BlockBody {
                txs: vec![set_tx],
                witnesses: vec![witness],
            },
        };
        apply_block(&mut store, &block_install, 50).expect("bootstrap install");
        assert!(load_governance(&store).is_some());

        // --- Step 2: UpgradeCrypto WITHOUT proof — rejected.
        let mk_upgrade_tx = |alice_nonce: u64, gov_proof: Vec<u8>| {
            let mut tx = TxBody {
                nonce: alice_nonce,
                from_account: alice,
                call: TxCall::UpgradeCrypto {
                    target_height: 1_000,
                    sig_algo: 1, // Falcon-512 — in DEFAULT_ALLOWLIST_SIG
                    hash_algo: 1,
                    gov_proof,
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
            (tx, witness)
        };
        let (no_proof_tx, no_proof_w) = mk_upgrade_tx(1, Vec::new());
        let mut h2 = empty_header();
        h2.height = 2;
        let block_no_proof = Block {
            header: h2,
            body: BlockBody {
                txs: vec![no_proof_tx],
                witnesses: vec![no_proof_w],
            },
        };
        assert!(matches!(
            apply_block(&mut store, &block_no_proof, 50),
            Err(ApplyError::GovernanceProofMissing { .. })
        ));

        // --- Step 3: 1-of-3 proof — rejected as below threshold.
        let payload = upgrade_crypto_gov_payload(1_000, 1, 1);
        let g1_sig = crypto::sign(3, &g1_sk, &payload).unwrap();
        let proof_1of3 = GovernanceProof {
            signatures: vec![GovernanceSig {
                signer_id: g1_id,
                sig: g1_sig.clone(),
            }],
        };
        let mut proof_cbor = Vec::new();
        ciborium::ser::into_writer(&proof_1of3, &mut proof_cbor).unwrap();
        let (low_tx, low_w) = mk_upgrade_tx(1, proof_cbor);
        let mut h3 = empty_header();
        h3.height = 3;
        let block_1of3 = Block {
            header: h3,
            body: BlockBody {
                txs: vec![low_tx],
                witnesses: vec![low_w],
            },
        };
        assert!(matches!(
            apply_block(&mut store, &block_1of3, 50),
            Err(ApplyError::GovernanceProofInvalid { .. })
        ));

        // --- Step 4: 2-of-3 proof — accepted.
        let g2_sig = crypto::sign(3, &g2_sk, &payload).unwrap();
        let proof_2of3 = GovernanceProof {
            signatures: vec![
                GovernanceSig {
                    signer_id: g1_id,
                    sig: g1_sig,
                },
                GovernanceSig {
                    signer_id: g2_id,
                    sig: g2_sig,
                },
            ],
        };
        let mut proof_cbor = Vec::new();
        ciborium::ser::into_writer(&proof_2of3, &mut proof_cbor).unwrap();
        let (good_tx, good_w) = mk_upgrade_tx(1, proof_cbor);
        let mut h4 = empty_header();
        h4.height = 4;
        let block_2of3 = Block {
            header: h4,
            body: BlockBody {
                txs: vec![good_tx],
                witnesses: vec![good_w],
            },
        };
        apply_block(&mut store, &block_2of3, 50).expect("2-of-3 proof accepted");
        // The pending upgrade should be recorded.
        let pending_bytes = store.get(Subtree::Meta, b"upgrade_crypto").unwrap();
        let pending: PendingCryptoUpgrade =
            ciborium::de::from_reader(&pending_bytes[..]).unwrap();
        assert_eq!(pending.target_height, 1_000);
        assert_eq!(pending.sig_algo, 1);
    }
}

