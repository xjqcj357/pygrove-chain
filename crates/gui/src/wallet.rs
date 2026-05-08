//! Local wallet — single Ed25519 keypair, address, on-disk persistence.
//!
//! v0.1 / Phase A: stored as plain JSON in the OS config directory. Adequate
//! for a public testnet whose coins have no real value. Phase B adds:
//!   - argon2 password encryption
//!   - mnemonic seed phrases (BIP-39)
//!   - Falcon-512 keys via UpgradeCrypto rotation
//!
//! File location:
//!   Windows : %APPDATA%/PyGrove/wallet.json
//!   macOS   : ~/Library/Application Support/PyGrove/wallet.json
//!   Linux   : ~/.config/pygrove/wallet.json

use anyhow::{anyhow, Context};
use pygrove_core::AccountId;
use pygrove_crypto as crypto;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Sig algo currently used for new wallet keypairs. Phase A = Ed25519 (3).
const WALLET_SIG_ALGO: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    pub version: u32,
    pub sig_algo: u8,
    pub secret_key_hex: String,
    pub public_key_hex: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct Wallet {
    pub sig_algo: u8,
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub address: AccountId,
}

impl Wallet {
    /// Create a new random wallet. Does not write to disk — caller decides.
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        let (sk, pk) = crypto::ed25519_keypair(&mut rng);
        let address = AccountId::from_pubkey(&pk);
        Self {
            sig_algo: WALLET_SIG_ALGO,
            secret_key: sk.to_vec(),
            public_key: pk.to_vec(),
            address,
        }
    }

    /// Default disk path. May not exist yet.
    pub fn default_path() -> PathBuf {
        if let Some(base) = dirs_path() {
            base.join("wallet.json")
        } else {
            // Fall back to current working directory.
            PathBuf::from("pygrove-wallet.json")
        }
    }

    /// Load wallet from disk, or create a new one and save it on first launch.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let w = Self::generate();
            w.save(path).context("save fresh wallet")?;
            Ok(w)
        }
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read_to_string(path).context("read wallet file")?;
        let f: WalletFile = serde_json::from_str(&bytes).context("parse wallet file")?;
        if f.version != 1 {
            return Err(anyhow!("unknown wallet version {}", f.version));
        }
        let sk = hex::decode(&f.secret_key_hex).context("decode secret key")?;
        let pk = hex::decode(&f.public_key_hex).context("decode public key")?;
        let address = AccountId::from_bech32(&f.address)
            .map_err(|e| anyhow!("decode wallet address: {e}"))?;
        Ok(Self {
            sig_algo: f.sig_algo,
            secret_key: sk,
            public_key: pk,
            address,
        })
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create wallet dir")?;
        }
        let f = WalletFile {
            version: 1,
            sig_algo: self.sig_algo,
            secret_key_hex: hex::encode(&self.secret_key),
            public_key_hex: hex::encode(&self.public_key),
            address: self.address.to_bech32(),
        };
        let s = serde_json::to_string_pretty(&f).context("serialize wallet")?;
        std::fs::write(path, s).context("write wallet file")?;
        Ok(())
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        crypto::sign(self.sig_algo, &self.secret_key, msg)
            .map_err(|e| anyhow!("sign: {e}"))
    }
}

fn dirs_path() -> Option<PathBuf> {
    // Match the platform conventions without pulling in a dirs crate.
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("PyGrove"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support/PyGrove"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|p| p.join("pygrove"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_roundtrip_to_disk() {
        let dir = std::env::temp_dir().join(format!("pyg-wallet-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        let w = Wallet::generate();
        w.save(&path).unwrap();
        let loaded = Wallet::load(&path).unwrap();
        assert_eq!(w.address, loaded.address);
        assert_eq!(w.public_key, loaded.public_key);
        assert_eq!(w.secret_key, loaded.secret_key);
    }

    #[test]
    fn signature_verifies_with_loaded_pubkey() {
        let w = Wallet::generate();
        let msg = b"phase A bringup";
        let sig = w.sign(msg).unwrap();
        crypto::verify(w.sig_algo, &w.public_key, &sig, msg).unwrap();
    }
}
