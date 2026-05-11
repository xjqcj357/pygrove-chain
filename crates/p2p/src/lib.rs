//! PyGrove Chain P2P protocol.
//!
//! ## Scope of this crate
//!
//! - **Wire protocol**: the CBOR-encoded `P2pMessage` envelope every
//!   peer exchange flows through. Versioned, domain-tagged, extensible.
//! - **Peer-id**: stable, content-addressed identifier for a node.
//!   Derived from the libp2p host key (Ed25519 today, Falcon-512 once
//!   the libp2p Falcon adapter lands).
//! - **Gossipsub topic constants**: the eight canonical pub/sub topics
//!   the libp2p layer will subscribe to.
//! - **In-process broker**: a synchronous, single-threaded
//!   `Broker` that routes messages between fake peers. Lets the
//!   consensus + finality crates exercise the full receive→validate
//!   →apply pipeline without an actual network.
//!
//! ## What this crate does NOT do (yet)
//!
//! - No libp2p, no TCP, no QUIC, no Noise handshake, no Kademlia DHT,
//!   no relay. The integration crate `pygrove-p2p-libp2p` will land
//!   when the libp2p 0.55 wiring is ready — this crate defines the
//!   protocol it implements, in isolation.
//!
//! ## Versioning
//!
//! `WIRE_VERSION = 1`. Every `P2pMessage` carries this byte at the
//! start. Bumps follow the same rules as `UpgradeCrypto`:
//!   - Backward-incompatible changes ship at a future activation height
//!   - The transition window allows both versions for a few epochs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Wire-protocol major version. Bumped on incompatible changes via an
/// activation-at-height transition (same pattern as `UpgradeCrypto`).
pub const WIRE_VERSION: u8 = 1;

/// Default P2P TCP port: testnet 8546, mainnet 9546. Matches the
/// chosen layout in `docs/mainnet-plan.md`. Hosts MAY bind to other
/// ports; these are the discovery defaults.
pub const TESTNET_P2P_PORT: u16 = 8546;
pub const MAINNET_P2P_PORT: u16 = 9546;

/// A peer's stable identifier. 32 bytes. Today derived as
/// `blake3("PGpeer\x00" || host_pubkey_bytes)`. When libp2p lands, the
/// libp2p host PeerId will be content-addressed onto this same hash so
/// nodes have one identity across both layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Derive a PeerId from the host's pubkey bytes.
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"PGpeer\x00");
        h.update(pubkey);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        PeerId(out)
    }

    /// Hex-encoded representation for logs / RPC.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Short prefix for human-readable logs.
        let s = self.hex();
        write!(f, "peer({}…)", &s[..8])
    }
}

/// The eight canonical gossipsub topics. Subscribed-to by the libp2p
/// layer; messages are routed to the consensus / finality / mempool
/// pipelines based on topic.
pub mod topics {
    /// New block headers — propagated immediately after PoW found.
    pub const BLOCK_HEADER: &str = "pg/v1/block-header";
    /// Compact block relay (BIP 152-style) — header + short-id list.
    pub const COMPACT_BLOCK: &str = "pg/v1/compact-block";
    /// Mempool transactions.
    pub const TX: &str = "pg/v1/tx";
    /// Per-validator finality vote (plain, non-aggregated).
    pub const FINALITY_VOTE: &str = "pg/v1/finality-vote";
    /// Aggregated finality certificate, posted by the round proposer.
    pub const FINALITY_CERT: &str = "pg/v1/finality-cert";
    /// Governance announcements (UpgradeCrypto + SetGovernance txs that
    /// haven't been mined yet — preview path for early validation).
    pub const GOVERNANCE: &str = "pg/v1/governance";
    /// Peer-discovery gossip (active addresses, head height).
    pub const PEER_INFO: &str = "pg/v1/peer-info";
    /// FL/DLA attestation rounds — separate topic for low-priority
    /// flow control.
    pub const ATTESTATION: &str = "pg/v1/attestation";

    /// Iterator over all topic constants. Lets a subscriber stand up
    /// the full topic set in one loop.
    pub const ALL: &[&str] = &[
        BLOCK_HEADER,
        COMPACT_BLOCK,
        TX,
        FINALITY_VOTE,
        FINALITY_CERT,
        GOVERNANCE,
        PEER_INFO,
        ATTESTATION,
    ];
}

/// The canonical envelope flowing across the wire. Every message —
/// regardless of topic — is CBOR(`P2pMessage`).
///
/// Versioned in two layers:
///   - `version`: the wire-protocol major (1 today). Bumped on
///     breaking changes.
///   - `payload`: a versioned enum, additive within a wire version.
///
/// Domain-tagged: the canonical signing-hash (for messages that need
/// peer-source authentication) lives in [`P2pMessage::signing_hash`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMessage {
    pub version: u8,
    pub from: PeerId,
    /// Topic the message was published on. One of [`topics::ALL`].
    pub topic: String,
    /// Monotonic per-peer message counter. Lets receivers de-dup and
    /// detect dropped messages without a full Merkle ack.
    pub seq: u64,
    pub payload: P2pPayload,
}

impl P2pMessage {
    /// Canonical hash for peer-source authentication. Excludes any
    /// peer-signature field (this is what the signature is over).
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGp2pmsg\x00");
        h.update(&[self.version]);
        h.update(&self.from.0);
        h.update(&(self.topic.len() as u32).to_le_bytes());
        h.update(self.topic.as_bytes());
        h.update(&self.seq.to_le_bytes());
        // Payload discriminator + the relevant header fields (CBOR is
        // not fully canonical, so we don't hash CBOR bytes directly —
        // we hash the *semantic* contents).
        match &self.payload {
            P2pPayload::BlockHeader { height, header_hash } => {
                h.update(&[1u8]);
                h.update(&height.to_le_bytes());
                h.update(header_hash);
            }
            P2pPayload::TxBytes { tx_hash, .. } => {
                h.update(&[2u8]);
                h.update(tx_hash);
            }
            P2pPayload::FinalityVote { vote_hash, .. } => {
                h.update(&[3u8]);
                h.update(vote_hash);
            }
            P2pPayload::FinalityCert { cert_hash, .. } => {
                h.update(&[4u8]);
                h.update(cert_hash);
            }
            P2pPayload::PeerInfo { head_height, .. } => {
                h.update(&[5u8]);
                h.update(&head_height.to_le_bytes());
            }
            P2pPayload::GovernanceAnnounce { tx_hash, .. } => {
                h.update(&[6u8]);
                h.update(tx_hash);
            }
            P2pPayload::Attestation { tx_hash, .. } => {
                h.update(&[7u8]);
                h.update(tx_hash);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

/// Versioned payload union. Extensible within a wire version (adding
/// new variants is backward-compatible; receivers ignore unknown
/// variants). Removing or restructuring an existing variant requires a
/// `WIRE_VERSION` bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pPayload {
    BlockHeader {
        height: u64,
        header_hash: [u8; 32],
    },
    TxBytes {
        tx_hash: [u8; 32],
        #[serde(with = "serde_bytes")]
        tx_cbor: Vec<u8>,
        #[serde(with = "serde_bytes")]
        witness_cbor: Vec<u8>,
    },
    FinalityVote {
        vote_hash: [u8; 32],
        /// CBOR of `pygrove_finality::FinalizationVote`.
        #[serde(with = "serde_bytes")]
        vote_cbor: Vec<u8>,
    },
    FinalityCert {
        cert_hash: [u8; 32],
        /// CBOR of `pygrove_finality::AggregatedFinalizationCert`.
        #[serde(with = "serde_bytes")]
        cert_cbor: Vec<u8>,
    },
    PeerInfo {
        head_height: u64,
        head_hash: [u8; 32],
        protocol_version: u32,
    },
    GovernanceAnnounce {
        tx_hash: [u8; 32],
        #[serde(with = "serde_bytes")]
        tx_cbor: Vec<u8>,
    },
    Attestation {
        tx_hash: [u8; 32],
        #[serde(with = "serde_bytes")]
        tx_cbor: Vec<u8>,
    },
}

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("unknown peer: {0}")]
    UnknownPeer(PeerId),
    #[error("wire version mismatch: got {got}, expected {expected}")]
    WireVersionMismatch { got: u8, expected: u8 },
    #[error("unknown topic: {0}")]
    UnknownTopic(String),
    #[error("malformed cbor: {0}")]
    MalformedCbor(String),
    #[error("subscription not found")]
    NoSubscription,
}

/// An in-process broker. Lets a test bring up N fake peers, subscribe
/// each to a set of topics, and publish messages — the broker routes
/// every publish to all subscribers of the matching topic. No
/// networking; everything happens synchronously through mutex-guarded
/// queues.
///
/// The contract here matches what the libp2p layer will implement
/// externally, so tests written against `Broker` will work unchanged
/// once libp2p is wired.
#[derive(Default)]
pub struct Broker {
    inner: Mutex<BrokerInner>,
}

#[derive(Default)]
struct BrokerInner {
    /// peer → set of subscribed topics.
    subscriptions: HashMap<PeerId, Vec<String>>,
    /// peer → inbox of (topic, message). Pulled by recv().
    inboxes: HashMap<PeerId, Vec<P2pMessage>>,
}

impl Broker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a peer with no subscriptions.
    pub fn join(&self, peer: PeerId) {
        let mut g = self.inner.lock().unwrap();
        g.subscriptions.entry(peer).or_default();
        g.inboxes.entry(peer).or_default();
    }

    /// Subscribe `peer` to `topic`. Idempotent.
    pub fn subscribe(&self, peer: PeerId, topic: &str) -> Result<(), P2pError> {
        if !topics::ALL.contains(&topic) {
            return Err(P2pError::UnknownTopic(topic.into()));
        }
        let mut g = self.inner.lock().unwrap();
        let subs = g.subscriptions.entry(peer).or_default();
        if !subs.iter().any(|t| t == topic) {
            subs.push(topic.into());
        }
        Ok(())
    }

    /// Publish `msg` from `msg.from`. Routed to every peer subscribed
    /// to `msg.topic` (excluding the publisher itself — gossipsub
    /// convention).
    pub fn publish(&self, msg: P2pMessage) -> Result<(), P2pError> {
        if msg.version != WIRE_VERSION {
            return Err(P2pError::WireVersionMismatch {
                got: msg.version,
                expected: WIRE_VERSION,
            });
        }
        if !topics::ALL.contains(&msg.topic.as_str()) {
            return Err(P2pError::UnknownTopic(msg.topic.clone()));
        }
        let mut g = self.inner.lock().unwrap();
        // Snapshot the recipient list.
        let recipients: Vec<PeerId> = g
            .subscriptions
            .iter()
            .filter(|(p, _)| **p != msg.from)
            .filter(|(_, ts)| ts.iter().any(|t| t == &msg.topic))
            .map(|(p, _)| *p)
            .collect();
        for r in recipients {
            g.inboxes.entry(r).or_default().push(msg.clone());
        }
        Ok(())
    }

    /// Drain the inbox for `peer`. Returns messages in arrival order.
    pub fn recv(&self, peer: PeerId) -> Vec<P2pMessage> {
        let mut g = self.inner.lock().unwrap();
        let inbox = g.inboxes.entry(peer).or_default();
        std::mem::take(inbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_peer(seed: u8) -> PeerId {
        PeerId([seed; 32])
    }

    #[test]
    fn peer_id_from_pubkey_is_deterministic() {
        let pk = [42u8; 32];
        let a = PeerId::from_pubkey(&pk);
        let b = PeerId::from_pubkey(&pk);
        assert_eq!(a, b);
        let c = PeerId::from_pubkey(&[43u8; 32]);
        assert_ne!(a, c);
    }

    #[test]
    fn topics_are_distinct() {
        // Cheap structural check: no duplicates in the canonical list.
        let mut sorted: Vec<&&str> = topics::ALL.iter().collect();
        sorted.sort();
        for w in sorted.windows(2) {
            assert_ne!(w[0], w[1]);
        }
        assert_eq!(topics::ALL.len(), 8);
    }

    #[test]
    fn unknown_topic_subscribe_rejected() {
        let b = Broker::new();
        let p = fake_peer(1);
        b.join(p);
        let r = b.subscribe(p, "pg/v1/not-a-real-topic");
        assert!(matches!(r, Err(P2pError::UnknownTopic(_))));
    }

    /// Publish-subscribe roundtrip: peer A publishes a block-header
    /// gossip, peer B receives it, peer C (subscribed to a different
    /// topic) does not.
    #[test]
    fn publish_routes_by_topic() {
        let b = Broker::new();
        let a = fake_peer(1);
        let recv_b = fake_peer(2);
        let recv_c = fake_peer(3);
        b.join(a);
        b.join(recv_b);
        b.join(recv_c);
        b.subscribe(recv_b, topics::BLOCK_HEADER).unwrap();
        b.subscribe(recv_c, topics::TX).unwrap();

        let msg = P2pMessage {
            version: WIRE_VERSION,
            from: a,
            topic: topics::BLOCK_HEADER.into(),
            seq: 0,
            payload: P2pPayload::BlockHeader {
                height: 6,
                header_hash: [0xAB; 32],
            },
        };
        b.publish(msg).unwrap();

        let got_b = b.recv(recv_b);
        let got_c = b.recv(recv_c);
        assert_eq!(got_b.len(), 1);
        assert_eq!(got_c.len(), 0);
        assert!(matches!(
            &got_b[0].payload,
            P2pPayload::BlockHeader { height: 6, .. }
        ));
    }

    /// Publisher does not receive its own message — gossipsub
    /// convention. Required because every peer is in the dst list
    /// by default.
    #[test]
    fn publisher_not_in_own_inbox() {
        let b = Broker::new();
        let a = fake_peer(1);
        b.join(a);
        b.subscribe(a, topics::TX).unwrap();
        let msg = P2pMessage {
            version: WIRE_VERSION,
            from: a,
            topic: topics::TX.into(),
            seq: 0,
            payload: P2pPayload::TxBytes {
                tx_hash: [0xCD; 32],
                tx_cbor: vec![1, 2, 3],
                witness_cbor: vec![4, 5, 6],
            },
        };
        b.publish(msg).unwrap();
        let got_a = b.recv(a);
        assert!(got_a.is_empty(), "publisher must not receive its own msg");
    }

    /// Wire-version mismatch is refused at the broker boundary.
    #[test]
    fn wrong_wire_version_rejected() {
        let b = Broker::new();
        let a = fake_peer(1);
        b.join(a);
        let bad = P2pMessage {
            version: 99,
            from: a,
            topic: topics::TX.into(),
            seq: 0,
            payload: P2pPayload::TxBytes {
                tx_hash: [0; 32],
                tx_cbor: vec![],
                witness_cbor: vec![],
            },
        };
        let r = b.publish(bad);
        assert!(matches!(r, Err(P2pError::WireVersionMismatch { .. })));
    }

    /// Signing-hash excludes nothing except the (future) per-peer
    /// signature itself, which isn't on the envelope today. Verify
    /// it's stable when CBOR bytes would shift due to map-order, by
    /// hashing two clones.
    #[test]
    fn signing_hash_is_stable() {
        let a = fake_peer(1);
        let msg = P2pMessage {
            version: WIRE_VERSION,
            from: a,
            topic: topics::BLOCK_HEADER.into(),
            seq: 7,
            payload: P2pPayload::BlockHeader {
                height: 6,
                header_hash: [0xAB; 32],
            },
        };
        let h0 = msg.signing_hash();
        let msg2 = msg.clone();
        let h1 = msg2.signing_hash();
        assert_eq!(h0, h1);
    }

    /// CBOR roundtrip of every payload variant.
    #[test]
    fn cbor_roundtrip_all_payloads() {
        let variants = vec![
            P2pPayload::BlockHeader {
                height: 1,
                header_hash: [1u8; 32],
            },
            P2pPayload::TxBytes {
                tx_hash: [2u8; 32],
                tx_cbor: vec![10, 20],
                witness_cbor: vec![30, 40],
            },
            P2pPayload::FinalityVote {
                vote_hash: [3u8; 32],
                vote_cbor: vec![50],
            },
            P2pPayload::FinalityCert {
                cert_hash: [4u8; 32],
                cert_cbor: vec![60],
            },
            P2pPayload::PeerInfo {
                head_height: 100,
                head_hash: [5u8; 32],
                protocol_version: 1,
            },
            P2pPayload::GovernanceAnnounce {
                tx_hash: [6u8; 32],
                tx_cbor: vec![70],
            },
            P2pPayload::Attestation {
                tx_hash: [7u8; 32],
                tx_cbor: vec![80],
            },
        ];
        for v in variants {
            let msg = P2pMessage {
                version: WIRE_VERSION,
                from: fake_peer(1),
                topic: topics::TX.into(),
                seq: 0,
                payload: v,
            };
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&msg, &mut buf).unwrap();
            let back: P2pMessage = ciborium::de::from_reader(&buf[..]).unwrap();
            assert_eq!(back.version, msg.version);
            assert_eq!(back.signing_hash(), msg.signing_hash());
        }
    }
}
