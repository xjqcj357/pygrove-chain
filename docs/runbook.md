# PyGrove Chain — Operations Runbook

**Audience:** on-call for `pygrove-node`, `str4w.com` frontend, and the upstream Vultr host.
**Companion:** [`mainnet-plan.md`](mainnet-plan.md) for design-level decisions, [`whitepaper.md`](whitepaper.md) for the protocol spec.

## Table of contents

1. [Severity tiers](#severity-tiers)
2. [Quick reference](#quick-reference)
3. [Common operations](#common-operations)
4. [Incident playbooks](#incident-playbooks)
5. [Observability](#observability)
6. [Software updates](#software-updates)
7. [Recovery](#recovery)
8. [Contacts](#contacts)

## Severity tiers

| Tier | Definition | Response time | Examples |
|---|---|---|---|
| **SEV-0** | Chain halted or about to halt | < 15 min | No new blocks for > 30 min after launch; `pygrove-node` container down; `pygrove_height` flatlined |
| **SEV-1** | BFT finality stalled, mempool unbounded, or RPC unreachable from outside | < 1 hr | `pygrove_genesis_offset_ms` stuck negative past launch; `pygrove_mempool_size > 50k`; public RPC 5xx for > 5 min |
| **SEV-2** | Degraded performance or non-critical subsystem | < 4 hr | Block time consistently 30+ min; Docker image publish failing on CI; explorer slow but RPC fine |
| **SEV-3** | Cosmetic / observational | < 24 hr | Stale README link; metric label typo; missing chart tick |

Page the on-call via [contacts](#contacts) for SEV-0 and SEV-1.

## Quick reference

### Production endpoints

| Service | URL |
|---|---|
| Mobile wallet | https://str4w.com/ |
| Block explorer | https://str4w.com/explorer/ |
| Emission monitor | https://str4w.com/info/ |
| Testnet RPC | https://str4w.com/api/testnet/rpc |
| (future) Mainnet RPC | https://str4w.com/api/mainnet/rpc |

### Production host

- **Vultr box:** `66.42.93.85` (named `homeeTEST`, Ubuntu 6.8)
- **SSH:** `ssh -p 2222 -i ~/.ssh/id_ed25519 root@66.42.93.85` (port 22 is closed)
- **Container:** `pygrove-node`, image `ghcr.io/xjqcj357/pygrove-chain:latest`, network `pygrove-net`
- **State volume:** `pygrove-data` (Docker volume, mounts at `/var/lib/pygrove`)
- **RPC port:** `8545` (testnet), reserved `9545` for mainnet

### Live metrics

`GET https://str4w.com/api/testnet/rpc/metrics` exposes Prometheus-format metrics:

- `pygrove_height` — current chain tip height
- `pygrove_genesis_offset_ms` — wall-clock ms past genesis (negative = lockout)
- `pygrove_mempool_size` — mempool depth
- `pygrove_block_reward_sat` — current reward
- `pygrove_bits` — current difficulty (compact form)
- `pygrove_minted_so_far_sat` — cumulative emission
- `pygrove_chain_info{chain_id,sig_algo,hash_algo}` — chain identity (always-1)
- `pygrove_build_info{version,git_sha}` — binary identity (always-1)

## Common operations

### Check node liveness

```sh
ssh -p 2222 root@66.42.93.85 \
  'docker ps --filter name=pygrove-node --format "{{.Names}}\t{{.Status}}"'
```

### Query chain state

```sh
curl -sS -X POST http://localhost:8545/rpc \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":{}}' \
  | python3 -m json.tool
```

### Tail node logs

```sh
ssh -p 2222 root@66.42.93.85 'docker logs -f --tail 100 pygrove-node'
```

### Restart node (preserves state)

```sh
ssh -p 2222 root@66.42.93.85 'docker restart pygrove-node'
```

### Pull a newer image and restart

```sh
ssh -p 2222 root@66.42.93.85 '
docker pull ghcr.io/xjqcj357/pygrove-chain:latest && \
docker stop pygrove-node && docker rm pygrove-node && \
docker run -d --name pygrove-node --restart unless-stopped \
  --network pygrove-net -p 8545:8545 \
  -v pygrove-data:/var/lib/pygrove \
  ghcr.io/xjqcj357/pygrove-chain:latest
'
```

### Verify str4w.com routing

```sh
curl -sS -o /dev/null -w "%{http_code}\n" https://str4w.com/explorer/
curl -sS -X POST https://str4w.com/api/testnet/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":{}}'
```

Both should return 200 / a JSON envelope.

## Incident playbooks

### SEV-0: `pygrove-node` container is down

**Detection:** `docker ps` shows nothing; public RPC returns 5xx or connection-refused; `pygrove_height` metric goes missing.

**Steps:**

1. SSH in and inspect:
   ```sh
   docker ps -a --filter name=pygrove-node
   docker logs --tail 200 pygrove-node 2>&1
   ```
2. If the container exited cleanly (exit 0): something restarted it manually. Restart with the standard relaunch command.
3. If the container OOMed or panicked: check `docker logs` for the trace. Common causes:
   - Disk full → `df -h` and clear logs
   - RAM exhaustion → `free -h`; check for memory leak across versions
   - Image-pull failure on auto-restart → manually pull `:latest`
4. Bring it back:
   ```sh
   docker rm pygrove-node 2>/dev/null
   docker run -d --name pygrove-node --restart unless-stopped \
     --network pygrove-net -p 8545:8545 \
     -v pygrove-data:/var/lib/pygrove \
     ghcr.io/xjqcj357/pygrove-chain:latest
   ```
5. Verify `get_info` returns expected `chain_id` and `height`.

### SEV-0: Chain halted (no new blocks > 30 min post-launch)

**Detection:** `pygrove_height` flatlined; `now - last_block_timestamp > 30 min`.

**Steps:**

1. Confirm node is up (above playbook).
2. Check if the in-process miner is alive:
   ```sh
   docker logs --tail 50 pygrove-node | grep -iE "mine|nonce|trying"
   ```
3. If miner is silent: restart node. If it's grinding but blocks aren't landing, difficulty is too high — check `pygrove_bits` and historical hashrate (`get_info`-derived).
4. If multiple peers exist (post-libp2p), confirm at least one other peer has the same tip. A fork would surface as height divergence.

### SEV-1: BFT finality stalled

**Detection:** `pygrove_height` is advancing but no `FinalizationCert` has been recorded for > 2 epoch_blocks intervals.

**Steps:**

1. Check the committee state via RPC: `get_account` for each committee member address.
2. If a committee member is offline, that's expected to halt 5-of-5 finality. Confirm the operator can be reached (see [contacts](#contacts)).
3. v2.0+: slashing or rotation via 2-of-3 governance threshold sig.

### SEV-1: Mempool flood

**Detection:** `pygrove_mempool_size > 50_000`.

**Steps:**

1. Inspect mempool composition via `get_mempool`.
2. Mempool admission is fee-density gated; a flood implies a fee-paying spammer. Cost-to-flood is finite — wait, or raise the floor.
3. Network-policy raises: NOT consensus. The fee floor lives in the node's mempool config (next release: expose via `--mempool-fee-floor` flag).

### SEV-2: CI / image publish failing

**Detection:** `gh run list --branch main` shows the `docker` job red repeatedly.

**Steps:**

1. View the failed run: `gh run view <id> --log-failed`.
2. Common causes:
   - Workspace test failure (look for `error[E`)
   - Rust toolchain bump → clippy lint changes
   - Cargo lock mismatch → delete + regenerate locally, push
3. Test fix locally before pushing: `cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
4. The production node will continue to run the last successfully-published image; image-publish failures aren't a chain emergency, just block new deploys.

### SEV-2: str4w.com 502 bad gateway

**Detection:** `curl https://str4w.com/` returns 502.

**Steps:**

1. Check the nginx reverse-proxy container: `docker ps --filter name=akiyafinder-frontend`.
2. If it's recently been recreated (`docker logs` for restart events), it may have lost the `pygrove-net` network attachment. Reattach:
   ```sh
   docker network connect pygrove-net akiyafinder-frontend
   ```
3. The systemd `pygrove-net-attach.timer` (60s interval) reattaches automatically on most failures. Confirm it's enabled: `systemctl status pygrove-net-attach.timer`.

## Observability

### Prometheus scrape config

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: pygrove-testnet
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ['66.42.93.85:8545']
```

### Recommended alerts

```yaml
groups:
  - name: pygrove-sev0
    rules:
      - alert: PygroveNodeDown
        expr: absent(pygrove_height)
        for: 5m
        labels:
          severity: sev0
        annotations:
          summary: "pygrove-node /metrics has stopped responding"
      - alert: PygroveHeightStalled
        expr: rate(pygrove_height[20m]) == 0 and pygrove_genesis_offset_ms > 0
        for: 30m
        labels:
          severity: sev0
        annotations:
          summary: "No new blocks for 30 min past genesis"
  - name: pygrove-sev1
    rules:
      - alert: PygroveMempoolFlood
        expr: pygrove_mempool_size > 50000
        for: 10m
        labels:
          severity: sev1
        annotations:
          summary: "Mempool depth above flood threshold"
```

### Log aggregation

Today: `docker logs` on the host. Future: ship to Loki via the systemd journal.

## Software updates

### Pre-launch (announce window)

The chain has not yet emitted block 1. Any consensus-affecting change is fine. Push, wait for CI green, redeploy via the standard pull-and-relaunch command.

### Post-launch (chain is live)

- **Backwards-compatible bug fixes** (clippy fixes, doc changes, non-consensus code): ship as `v0.5.x` patch tag. Operators pull `:latest` at their leisure.
- **Protocol parameter changes** (ASERT τ, bootstrap_height, accordion betas, etc.): ship as `v0.6.0+` and require an `UpgradeCrypto`-style governance announcement (2-of-3 SLH-DSA threshold).
- **Security patches**: embargo period varies by severity. SEV-0/1 vuln: 24h private disclosure to validator operators, then public release. SEV-2: 14-day embargo. SEV-3: ship via the normal flow.

### Rolling a node update

```sh
# Step 1: read the release notes in RELEASES.md
# Step 2: pull the new image
ssh -p 2222 root@66.42.93.85 'docker pull ghcr.io/xjqcj357/pygrove-chain:vX.Y.Z'

# Step 3: stop the running container, but PRESERVE the state volume
ssh -p 2222 root@66.42.93.85 'docker stop pygrove-node && docker rm pygrove-node'

# Step 4: relaunch on the new tag — same -v pygrove-data flag
ssh -p 2222 root@66.42.93.85 'docker run -d --name pygrove-node \
  --restart unless-stopped --network pygrove-net -p 8545:8545 \
  -v pygrove-data:/var/lib/pygrove \
  ghcr.io/xjqcj357/pygrove-chain:vX.Y.Z'

# Step 5: tail logs, confirm replay completed and chain advances
ssh -p 2222 root@66.42.93.85 'docker logs --tail 50 pygrove-node'
```

## Recovery

### State loss (Docker volume corruption)

The `chain.log` in `/var/lib/pygrove` is the source of truth — accounts and reflection are replayed from it at startup. Backing it up:

```sh
ssh -p 2222 root@66.42.93.85 \
  'docker run --rm -v pygrove-data:/data -v /tmp:/backup alpine \
   tar czf /backup/pygrove-data-$(date +%Y%m%d-%H%M%S).tar.gz -C /data .'
```

Restore:

```sh
ssh -p 2222 root@66.42.93.85 \
  'docker run --rm -v pygrove-data:/data -v /tmp:/backup alpine \
   tar xzf /backup/pygrove-data-YYYYMMDD-HHMMSS.tar.gz -C /data'
```

Backup cadence: daily until mainnet, then hourly snapshots to off-host storage (S3 or B2).

### Chain decommissioning (worst case)

If the threat model fails post-launch and a hard-fork-or-die situation arises:

1. Halt mining: governance committee posts a `FinalizationCert` for the last-valid height and refuses to sign any further. Fork-choice on the rest of the network refuses to reorg past that height — the chain is permanently frozen at the last finalized block.
2. Tag a `vX.Y.Z-EOL` release with the exact halt height committed in `governance/eol.toml`.
3. v2 chain bootstraps with a snapshot of accounts above some dust threshold ported in via the genesis seed.

This is a worst case. v1.0 is intended to run unchanged for 127 years.

## Contacts

On-call rotation:
- **Primary:** the operator running `66.42.93.85` (Palantir-aligned, see governance metadata)
- **Secondary:** TBD
- **Watchtower:** TBD (community)

Communication channels: TBD — Matrix, Discord, or Signal once the operator slate is settled (per `docs/mainnet-plan.md` open question #2).
