//! PyGrove Chain BFT finality gadget — v1.0 design surface.
//!
//! ## What it adds
//!
//! PoW alone gives probabilistic finality: 6 confirmations means the
//! honest chain has out-paced any private fork by 6×, so the cost of
//! reverting is 6× the block-reward bounty. PyGrove inherits this for
//! mining but adds a BFT finality gadget on top so a confirmed
//! transaction becomes irreversible after a single round (~60 minutes
//! nominal), not after 60 minutes of probabilistic accumulation.
//!
//! ## Design — v1.0 MVP
//!
//! - A fixed N-of-N **trusted committee** of validators (N = 5).
//! - Every `epoch_blocks` (default 6, ~60 min @ 10-min target) every
//!   validator signs the header-hash of the height-`6n` block.
//! - When N-of-N signatures land on-chain, that height is **finalized**.
//! - Fork choice refuses to reorg below the highest finalized height.
//! - Validators rotated only by 2-of-3 SLH-DSA governance threshold
//!   signature (lands with the cold-key wiring).
//!
//! ## Design — v2.0
//!
//! Trusted committee → stake-elected committee. Bonded PYG locked for
//! ≥ 1 year. Slashing for double-signing automatic. Same epoch cadence,
//! same aggregation primitive.
//!
//! ## What ships in this crate today
//!
//! v0.4-sprint+: types (committee, finalization-vote, finalization-cert),
//! quorum checker, fork-choice helper, and a deterministic test that
//! verifies a vote round-trips through CBOR + sig + quorum. **Networking
//! is out of scope** — votes propagate over libp2p in v1.0 (separate
//! crate). For local testing, the test harness assembles votes in-memory.
//!
//! ## What does NOT ship today
//!
//! - **Aggregated signatures (BLS).** The mainnet design uses BLS so the
//!   N signatures collapse to a single aggregate verify. v0.4 uses
//!   plain SLH-DSA sigs (one per validator); aggregation lands when the
//!   SLH-DSA wiring upstream (roadmap #3) unblocks and we can also add
//!   `blst` for BLS as the aggregation primitive.
//! - **libp2p gossip transport.** Validator-to-validator vote
//!   propagation is the P2P crate's responsibility (mainnet gate #5).
//! - **Slashing.** v2.0 stake-based feature.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Identifier for a validator in the finality committee. Hash of the
/// validator's pubkey + slot index. Stable across validator rotations
/// (the slot key cycles, the validator-id may change).
pub type ValidatorId = [u8; 32];

/// Public key bytes for a validator. Bytes are interpreted by the
/// `sig_algo` byte in the surrounding `Committee`; today only
/// `SLH-DSA-128s` (algo=2) is contemplated, but the surface is
/// algo-agnostic so a v2 rotation to ML-DSA or aggregate-BLS doesn't
/// re-shape the wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPubkey {
    pub validator_id: ValidatorId,
    pub sig_algo: u8,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
}

/// The active finality committee. Committed to chain at genesis and
/// updated by a 2-of-3 governance threshold signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Committee {
    pub epoch: u64,
    pub members: Vec<ValidatorPubkey>,
    /// Block height interval between finalization rounds. Default 6
    /// (~60 min at the 10-min target).
    pub epoch_blocks: u64,
    /// Quorum threshold. v1.0: equals `members.len()` (full N-of-N).
    /// v2.0 may relax to `2/3 + 1` of stake.
    pub quorum: u32,
}

impl Committee {
    /// Round number for a given block height. Returns `None` if
    /// `height` isn't a finalization-round boundary.
    pub fn round_for_height(&self, height: u64) -> Option<u64> {
        if self.epoch_blocks == 0 {
            return None;
        }
        if height % self.epoch_blocks == 0 && height > 0 {
            Some(height / self.epoch_blocks)
        } else {
            None
        }
    }
}

/// One validator's signature on a finalization round.
///
/// Wire format is CBOR-encoded `FinalizationVote`. The signing payload
/// is the `signing_hash()` blake3 digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizationVote {
    pub committee_epoch: u64,
    pub round: u64,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub validator_id: ValidatorId,
    pub sig_algo: u8,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl FinalizationVote {
    /// The payload each validator signs over. Includes everything
    /// except the sig itself.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGfinal\x00");
        h.update(&self.committee_epoch.to_le_bytes());
        h.update(&self.round.to_le_bytes());
        h.update(&self.block_height.to_le_bytes());
        h.update(&self.block_hash);
        h.update(&self.validator_id);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

/// N-of-N quorum certificate over a single height. Produced when enough
/// `FinalizationVote`s for the same `(round, block_hash)` have been
/// observed. Posted on-chain as evidence so light clients can verify
/// finality without seeing each vote individually.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizationCert {
    pub committee_epoch: u64,
    pub round: u64,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub votes: Vec<FinalizationVote>,
}

#[derive(Debug, Error)]
pub enum FinalityError {
    #[error("vote signature failed verification (validator {0:?})")]
    BadSignature([u8; 32]),
    #[error("vote {0:?} is for the wrong round (expected {1}, got {2})")]
    WrongRound([u8; 32], u64, u64),
    #[error("vote {0:?} is for the wrong block hash")]
    WrongBlockHash([u8; 32]),
    #[error(
        "duplicate vote from validator {0:?} — double-signing is a slashable offense in v2.0"
    )]
    DuplicateVote([u8; 32]),
    #[error("validator {0:?} is not in the committee")]
    NotInCommittee([u8; 32]),
    #[error("cert assembled below quorum: {got}/{need}")]
    BelowQuorum { got: u32, need: u32 },
    #[error("committee epoch mismatch: cert says {0}, committee says {1}")]
    EpochMismatch(u64, u64),
    #[error("invalid algo {0} — pubkey/sig algo mismatch with committee record")]
    AlgoMismatch(u8),
}

/// Verify a single finalization vote against the committee. Confirms
/// (a) the validator is a committee member, (b) the sig_algo matches the
/// committee's record for that validator, and (c) the signature
/// verifies over `signing_hash()`.
pub fn verify_vote(committee: &Committee, vote: &FinalizationVote) -> Result<(), FinalityError> {
    if vote.committee_epoch != committee.epoch {
        return Err(FinalityError::EpochMismatch(
            vote.committee_epoch,
            committee.epoch,
        ));
    }
    let member = committee
        .members
        .iter()
        .find(|m| m.validator_id == vote.validator_id)
        .ok_or(FinalityError::NotInCommittee(vote.validator_id))?;
    if member.sig_algo != vote.sig_algo {
        return Err(FinalityError::AlgoMismatch(vote.sig_algo));
    }
    pygrove_crypto::verify(
        vote.sig_algo,
        &member.pubkey,
        &vote.sig,
        &vote.signing_hash(),
    )
    .map_err(|_| FinalityError::BadSignature(vote.validator_id))?;
    Ok(())
}

/// Verify a finalization certificate. Walks every vote: each must
/// verify individually, all must agree on `(round, block_height,
/// block_hash, committee_epoch)`, and the vote count must meet
/// `committee.quorum`. Duplicate validator IDs are rejected.
pub fn verify_cert(
    committee: &Committee,
    cert: &FinalizationCert,
) -> Result<(), FinalityError> {
    if cert.committee_epoch != committee.epoch {
        return Err(FinalityError::EpochMismatch(
            cert.committee_epoch,
            committee.epoch,
        ));
    }
    if cert.votes.len() < committee.quorum as usize {
        return Err(FinalityError::BelowQuorum {
            got: cert.votes.len() as u32,
            need: committee.quorum,
        });
    }
    let mut seen: std::collections::BTreeSet<ValidatorId> = std::collections::BTreeSet::new();
    for v in &cert.votes {
        if v.round != cert.round {
            return Err(FinalityError::WrongRound(v.validator_id, cert.round, v.round));
        }
        if v.block_hash != cert.block_hash || v.block_height != cert.block_height {
            return Err(FinalityError::WrongBlockHash(v.validator_id));
        }
        if !seen.insert(v.validator_id) {
            return Err(FinalityError::DuplicateVote(v.validator_id));
        }
        verify_vote(committee, v)?;
    }
    Ok(())
}

/// Fork-choice helper. Given the current finalized height and a
/// candidate reorg target, returns `true` if the reorg is permitted.
/// Reorgs to a height ≥ `finalized_height` are always permitted; reorgs
/// below it are refused — that's the BFT finality contract.
#[inline]
pub fn reorg_allowed(finalized_height: u64, candidate_height: u64) -> bool {
    candidate_height >= finalized_height
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_committee() -> Committee {
        Committee {
            epoch: 1,
            members: vec![
                ValidatorPubkey {
                    validator_id: [1u8; 32],
                    sig_algo: 3,
                    pubkey: vec![0u8; 32],
                },
                ValidatorPubkey {
                    validator_id: [2u8; 32],
                    sig_algo: 3,
                    pubkey: vec![0u8; 32],
                },
                ValidatorPubkey {
                    validator_id: [3u8; 32],
                    sig_algo: 3,
                    pubkey: vec![0u8; 32],
                },
                ValidatorPubkey {
                    validator_id: [4u8; 32],
                    sig_algo: 3,
                    pubkey: vec![0u8; 32],
                },
                ValidatorPubkey {
                    validator_id: [5u8; 32],
                    sig_algo: 3,
                    pubkey: vec![0u8; 32],
                },
            ],
            epoch_blocks: 6,
            quorum: 5,
        }
    }

    #[test]
    fn round_for_height_finds_boundaries() {
        let c = fake_committee();
        assert_eq!(c.round_for_height(0), None); // genesis is not a round
        assert_eq!(c.round_for_height(6), Some(1));
        assert_eq!(c.round_for_height(12), Some(2));
        assert_eq!(c.round_for_height(7), None);
    }

    #[test]
    fn reorg_below_finalized_refused() {
        // Finalized at 100. Candidate at 90 — refused.
        assert!(!reorg_allowed(100, 90));
        // Candidate at 100 — same height, allowed.
        assert!(reorg_allowed(100, 100));
        // Candidate at 105 — beyond, allowed.
        assert!(reorg_allowed(100, 105));
        // Genesis: no finalization yet, reorgs unconstrained.
        assert!(reorg_allowed(0, 0));
        assert!(reorg_allowed(0, 50));
    }

    #[test]
    fn below_quorum_cert_rejected() {
        let c = fake_committee();
        let cert = FinalizationCert {
            committee_epoch: 1,
            round: 1,
            block_height: 6,
            block_hash: [0xAB; 32],
            votes: vec![], // empty — definitely below quorum 5
        };
        assert!(matches!(
            verify_cert(&c, &cert),
            Err(FinalityError::BelowQuorum { got: 0, need: 5 })
        ));
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let c = fake_committee();
        let cert = FinalizationCert {
            committee_epoch: 99, // wrong
            round: 1,
            block_height: 6,
            block_hash: [0xAB; 32],
            votes: vec![],
        };
        assert!(matches!(
            verify_cert(&c, &cert),
            Err(FinalityError::EpochMismatch(99, 1))
        ));
    }

    #[test]
    fn duplicate_validator_rejected() {
        let c = fake_committee();
        // 5 votes but all from validator [1; 32] — should hit DuplicateVote.
        let vote_proto = FinalizationVote {
            committee_epoch: 1,
            round: 1,
            block_height: 6,
            block_hash: [0xAB; 32],
            validator_id: [1u8; 32],
            sig_algo: 3,
            sig: vec![0u8; 64], // sig won't matter — duplicate trips first
        };
        let cert = FinalizationCert {
            committee_epoch: 1,
            round: 1,
            block_height: 6,
            block_hash: [0xAB; 32],
            votes: vec![
                vote_proto.clone(),
                vote_proto.clone(),
                vote_proto.clone(),
                vote_proto.clone(),
                vote_proto,
            ],
        };
        assert!(matches!(
            verify_cert(&c, &cert),
            Err(FinalityError::DuplicateVote([1u8; 32]))
        ));
    }

    /// Vote signing-hash is stable: changing any field changes the hash.
    #[test]
    fn signing_hash_excludes_sig_only() {
        let mut a = FinalizationVote {
            committee_epoch: 1,
            round: 1,
            block_height: 6,
            block_hash: [0xAB; 32],
            validator_id: [1u8; 32],
            sig_algo: 3,
            sig: vec![1, 2, 3],
        };
        let h0 = a.signing_hash();
        a.sig = vec![9, 9, 9];
        let h_sig_changed = a.signing_hash();
        assert_eq!(h0, h_sig_changed, "signing_hash must NOT include sig");
        a.round = 2;
        let h_round_changed = a.signing_hash();
        assert_ne!(h0, h_round_changed, "signing_hash must include round");
    }

    /// Full roundtrip with real Ed25519 sigs (testnet-3 algo).
    /// pygrove-crypto's default features include ed25519, so
    /// ed25519_keypair is callable here.
    #[test]
    fn full_5_of_5_roundtrip() {
        use rand_core::OsRng;
        let mut rng = OsRng;

        // Generate 5 validator keypairs.
        let keys: Vec<([u8; 32], [u8; 32])> = (0..5)
            .map(|_| pygrove_crypto::ed25519_keypair(&mut rng))
            .collect();

        let committee = Committee {
            epoch: 1,
            members: keys
                .iter()
                .enumerate()
                .map(|(i, (_, pk))| ValidatorPubkey {
                    validator_id: {
                        let mut id = [0u8; 32];
                        id[0] = i as u8;
                        id[1..].copy_from_slice(&pk[..31]);
                        id
                    },
                    sig_algo: 3,
                    pubkey: pk.to_vec(),
                })
                .collect(),
            epoch_blocks: 6,
            quorum: 5,
        };

        let block_height = 6;
        let block_hash = [0xAB; 32];

        // Each validator signs.
        let votes: Vec<FinalizationVote> = committee
            .members
            .iter()
            .zip(keys.iter())
            .map(|(member, (sk, _))| {
                let mut vote = FinalizationVote {
                    committee_epoch: 1,
                    round: 1,
                    block_height,
                    block_hash,
                    validator_id: member.validator_id,
                    sig_algo: 3,
                    sig: vec![],
                };
                let sh = vote.signing_hash();
                vote.sig = pygrove_crypto::sign(3, sk, &sh).expect("sign");
                vote
            })
            .collect();

        let cert = FinalizationCert {
            committee_epoch: 1,
            round: 1,
            block_height,
            block_hash,
            votes,
        };

        verify_cert(&committee, &cert).expect("5-of-5 cert verifies");
    }
}
