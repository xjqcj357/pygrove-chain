//! Transaction types with signature-algorithm and hash-algorithm tag bytes.
//!
//! Phase A (`sig_algo = 3` = Ed25519): testnet bringup. Lets us prove the
//! account/tx/apply-block path end-to-end without the cost of wiring Falcon-512
//! at the same time as everything else.
//!
//! Phase B (`sig_algo = 1` = Falcon-512): activated by an `UpgradeCrypto`
//! governance tx on the live testnet — which itself is the first real-world
//! exercise of the crypto-agility layer the whitepaper promises.

use serde::{Deserialize, Serialize};

pub use crate::address::AccountId;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigAlgo {
    /// Falcon-512 / FN-DSA, integer sampler. PoQC headline algorithm.
    Falcon512 = 1,
    /// SLH-DSA-128s. Cold governance keys (`UpgradeCrypto` signer in mainnet).
    SlhDsa128s = 2,
    /// Ed25519 — Phase A bringup placeholder. Live on testnet today; rotates
    /// to Falcon-512 (tag = 1) via `UpgradeCrypto` in Phase B.
    Ed25519 = 3,
    /// ML-DSA-65 (FIPS 204). Added for the Raytheon FIPS-profile build —
    /// CMVP-validatable when the underlying primitive ships in `pqc-mldsa`.
    /// Plumbed via `UpgradeCrypto` so a FIPS-profile chain can rotate
    /// signature algos without forking the testnet identity.
    MlDsa65 = 4,
}

impl SigAlgo {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Falcon512),
            2 => Some(Self::SlhDsa128s),
            3 => Some(Self::Ed25519),
            4 => Some(Self::MlDsa65),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PubKeyRef {
    /// The pubkey is already committed to the accounts subtree — lookup by id.
    Known(AccountId),
    /// First tx from this account — full pubkey bytes inline, sized by algo.
    Inline(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxCall {
    Transfer {
        to: AccountId,
        amount: u128,
    },
    DeployContract {
        code_ref: [u8; 32],
        #[serde(with = "serde_bytes")]
        init_args: Vec<u8>,
    },
    CallContract {
        contract: AccountId,
        method: String,
        #[serde(with = "serde_bytes")]
        args: Vec<u8>,
    },
    UpgradeCrypto {
        target_height: u64,
        sig_algo: u8,
        hash_algo: u8,
        /// Hex-encoded CBOR of `pygrove_state::GovernanceProof`. Optional
        /// only while the chain is in bootstrap mode (no governance
        /// config committed). Once governance is set, every
        /// `UpgradeCrypto` apply requires a valid k-of-N proof over the
        /// `upgrade_crypto_gov_payload` hash.
        ///
        /// Lives on TxCall as opaque bytes — the `pygrove-core` crate
        /// can't depend on `pygrove-state` (cycle), so we carry the
        /// proof as CBOR and let `apply` decode it.
        #[serde(default, with = "serde_bytes")]
        gov_proof: Vec<u8>,
    },
    /// Federated-learning round attestation. Commits a hash of an aggregation
    /// round (post-FedAvg model hash + participant set + DP budget) to a
    /// dedicated reflect subtree. Lets a verifier in 2031 re-execute round N
    /// of a 2027 model bit-exactly against committed inputs, with no vendor
    /// cooperation.
    ///
    /// Sender pays `fee_sat` like any tx. Coordinator authority (who's
    /// allowed to attest for `job_id`) is registered out-of-band in v0.4
    /// (governance-key endorsed); v0.5 elects per-job authorities via stake.
    AttestRound {
        /// Stable identifier for the FL job — usually `blake3(program ||
        /// dataset_id || initial_model_hash)`.
        job_id: [u8; 32],
        /// Monotonic round counter within the job.
        round_id: u64,
        /// Post-aggregation global model hash (32 bytes).
        model_hash: [u8; 32],
        /// Differential-privacy ε × 1000 (so `epsilon = 1.5` → `1500`).
        /// Zero is a valid value meaning "no DP applied at this round".
        dp_epsilon_milli: u32,
    },
    /// Register the coordinator authority registry for an FL job. Once a
    /// registry exists for a `job_id`, only accounts in the `coordinators`
    /// list may emit `AttestRound` for that `job_id`. Jobs without a
    /// registry stay open (any account can attest), preserving testnet
    /// backward compatibility.
    ///
    /// In v0.5 this transaction will require a 2-of-3 SLH-DSA-128s
    /// governance threshold signature. v0.4 records the registry but
    /// doesn't gate the registration tx itself — same staging pattern as
    /// `UpgradeCrypto`.
    RegisterAttestCoordinator {
        /// FL job to scope the authority to.
        job_id: [u8; 32],
        /// Accounts permitted to emit `AttestRound { job_id, .. }` once
        /// this record is committed. An empty list re-opens the job to
        /// any attester (rarely useful, but explicit).
        coordinators: Vec<AccountId>,
        /// CBOR-encoded governance proof. Same staging pattern as
        /// `UpgradeCrypto.gov_proof` — bytes so `pygrove-core` doesn't
        /// reach into `pygrove-state` types.
        #[serde(default, with = "serde_bytes")]
        gov_proof: Vec<u8>,
    },
    /// Install (bootstrap) or rotate the governance config. The first
    /// `SetGovernance` tx in a chain's history is accepted with an
    /// empty `gov_proof` (bootstrap mode); subsequent ones require a
    /// k-of-N proof from the *current* config over a hash of the *new*
    /// config (`set_governance_gov_payload`).
    ///
    /// `config_cbor` is CBOR(`pygrove_state::GovernanceConfig`). The
    /// `core` crate can't depend on `state`, so we carry the config as
    /// bytes and let `apply` decode + validate.
    SetGovernance {
        #[serde(with = "serde_bytes")]
        config_cbor: Vec<u8>,
        #[serde(default, with = "serde_bytes")]
        gov_proof: Vec<u8>,
    },
    /// DLA-shape attestation: component-pedigree provenance for
    /// supply-chain artifacts. Same primitive as `AttestRound` but
    /// the schema is defense-acquisition-friendly: lot_id, supplier,
    /// CAGE code, attestation authority. A 2030 logistics auditor can
    /// reproduce a 2027 component's full chain of custody bit-exactly
    /// against the committed attestations.
    ///
    /// Roadmap #7. Raytheon flagship (the "DLA shape" — same primitive,
    /// different schema). Coordinator authority shares the same
    /// `RegisterAttestCoordinator` registry as `AttestRound`, scoped
    /// by `job_id` (here interpreted as the part-program identifier).
    AttestPedigree {
        /// Stable identifier for the supply-chain program (e.g. a
        /// part-number hash: `blake3(part_number || program_id)`).
        /// Reuses the `AttestRound` authority registry — calling code
        /// distinguishes FL jobs from supply-chain programs by the
        /// content of `job_id`.
        job_id: [u8; 32],
        /// Stable identifier for the manufacturing lot.
        lot_id: [u8; 16],
        /// Hash of the supplier's identity record (e.g.
        /// `blake3(supplier_name || cage_code || dunns)`).
        supplier: [u8; 32],
        /// Commercial and Government Entity code, 5 ASCII chars.
        /// Validated as `[A-Z0-9]{5}` at apply time.
        cage_code: [u8; 5],
        /// Hash of the attestation authority's identity (the
        /// certifying body, e.g. DCMA / NIST).
        attestation_authority: [u8; 32],
    },
}

/// The body of a transaction — everything that gets signed.
///
/// The witness `(sig, pubkey)` is segregated into a separate structure
/// per whitepaper §7.2; the body's `witness_hash` field commits to it
/// without storing the raw signature alongside the state-transition
/// payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBody {
    pub nonce: u64,
    pub from_account: AccountId,
    pub call: TxCall,
    /// Fee in sat (sat = 10⁻⁸ PYG). Paid to the block's coinbase recipient.
    pub fee_sat: u64,
    pub gas_limit: u32,
    pub witness_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub sig_algo: u8,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    pub pubkey: PubKeyRef,
}

impl Witness {
    /// Domain-tagged hash of the witness, used as `TxBody.witness_hash`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGwit\x00");
        h.update(&[self.sig_algo]);
        h.update(&(self.sig.len() as u32).to_le_bytes());
        h.update(&self.sig);
        match &self.pubkey {
            PubKeyRef::Known(id) => {
                h.update(&[0u8]); // discriminator
                h.update(&id.0);
            }
            PubKeyRef::Inline(bytes) => {
                h.update(&[1u8]);
                h.update(&(bytes.len() as u32).to_le_bytes());
                h.update(bytes);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..]);
        out
    }
}

/// Canonical encoding of a `TxCall` into a hasher. Field order is fixed forever —
/// changing it changes every signing hash and therefore every existing signature.
fn hash_call(h: &mut blake3::Hasher, call: &TxCall) {
    match call {
        TxCall::Transfer { to, amount } => {
            h.update(&[0u8]);
            h.update(&to.0);
            h.update(&amount.to_le_bytes());
        }
        TxCall::DeployContract { code_ref, init_args } => {
            h.update(&[1u8]);
            h.update(code_ref);
            h.update(&(init_args.len() as u32).to_le_bytes());
            h.update(init_args);
        }
        TxCall::CallContract { contract, method, args } => {
            h.update(&[2u8]);
            h.update(&contract.0);
            h.update(&(method.len() as u32).to_le_bytes());
            h.update(method.as_bytes());
            h.update(&(args.len() as u32).to_le_bytes());
            h.update(args);
        }
        TxCall::UpgradeCrypto {
            target_height,
            sig_algo,
            hash_algo,
            gov_proof: _, // proof excluded from sender-sig hash by design
        } => {
            h.update(&[3u8]);
            h.update(&target_height.to_le_bytes());
            h.update(&[*sig_algo, *hash_algo]);
        }
        TxCall::AttestRound {
            job_id,
            round_id,
            model_hash,
            dp_epsilon_milli,
        } => {
            h.update(&[4u8]);
            h.update(job_id);
            h.update(&round_id.to_le_bytes());
            h.update(model_hash);
            h.update(&dp_epsilon_milli.to_le_bytes());
        }
        TxCall::RegisterAttestCoordinator {
            job_id,
            coordinators,
            gov_proof: _, // excluded from sender-sig hash
        } => {
            h.update(&[5u8]);
            h.update(job_id);
            h.update(&(coordinators.len() as u32).to_le_bytes());
            // Sort by AccountId bytes for canonical encoding so two
            // signers who supply the same set in different orders
            // produce the same signing hash.
            let mut ids: Vec<&AccountId> = coordinators.iter().collect();
            ids.sort_by_key(|a| a.0);
            for id in ids {
                h.update(&id.0);
            }
        }
        TxCall::AttestPedigree {
            job_id,
            lot_id,
            supplier,
            cage_code,
            attestation_authority,
        } => {
            h.update(&[6u8]);
            h.update(job_id);
            h.update(lot_id);
            h.update(supplier);
            h.update(cage_code);
            h.update(attestation_authority);
        }
        TxCall::SetGovernance {
            config_cbor,
            gov_proof: _, // excluded from sender-sig hash
        } => {
            h.update(&[7u8]);
            h.update(&(config_cbor.len() as u32).to_le_bytes());
            h.update(config_cbor);
        }
    }
}

impl TxBody {
    /// Hash that the witness signs. Excludes `witness_hash` itself (which would be
    /// circular — it's a commitment to the signature) and the `gas_limit` (also a
    /// post-signing field, paid for separately). Domain tag `PGtxsign\0`.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGtxsign\x00");
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.from_account.0);
        hash_call(&mut h, &self.call);
        h.update(&self.fee_sat.to_le_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..]);
        out
    }

    /// Hash committed in `tx_root` of the block. Includes every field including
    /// `witness_hash` so the block header binds to a specific signature.
    pub fn body_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGtxbody\x00");
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.from_account.0);
        hash_call(&mut h, &self.call);
        h.update(&self.fee_sat.to_le_bytes());
        h.update(&self.gas_limit.to_le_bytes());
        h.update(&self.witness_hash);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..]);
        out
    }
}

/// Domain-tagged Merkle-ish root over a vector of leaves. v0.1: simple ordered
/// concatenation hash, deterministic. Production path swaps to a proper sparse
/// Merkle tree under the GroveDB rollout.
pub fn vec_root(domain: &[u8], leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(leaves.len() as u32).to_le_bytes());
    for leaf in leaves {
        h.update(leaf);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().as_bytes()[..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> TxBody {
        TxBody {
            nonce: 7,
            from_account: AccountId::new([1u8; 20]),
            call: TxCall::Transfer {
                to: AccountId::new([2u8; 20]),
                amount: 1_000,
            },
            fee_sat: 10,
            gas_limit: 21000,
            witness_hash: [9u8; 32],
        }
    }

    #[test]
    fn signing_hash_excludes_witness() {
        let mut a = sample_tx();
        let h_a = a.signing_hash();
        a.witness_hash = [0u8; 32];
        let h_b = a.signing_hash();
        assert_eq!(h_a, h_b, "signing_hash must not depend on witness_hash");
    }

    #[test]
    fn body_hash_includes_witness() {
        let mut a = sample_tx();
        let h_a = a.body_hash();
        a.witness_hash = [0u8; 32];
        let h_b = a.body_hash();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn signing_hash_changes_with_amount() {
        let a = sample_tx();
        let mut b = a.clone();
        if let TxCall::Transfer { amount, .. } = &mut b.call {
            *amount = 1_001;
        }
        assert_ne!(a.signing_hash(), b.signing_hash());
    }
}
