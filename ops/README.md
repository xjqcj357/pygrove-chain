# PyGrove Chain — Operations

Deployment templates + production hardening for `pygrove-node`. Companion to [`docs/runbook.md`](../docs/runbook.md).

## Contents

| File | What it is |
|---|---|
| [`pygrove-node.service`](pygrove-node.service) | Systemd unit for managed Docker-container deploy. Capability-dropped, read-only rootfs, no-new-privileges, memory + CPU limits, pids limit. |
| [`prometheus-alerts.yml`](prometheus-alerts.yml) | Recommended alert rules for SEV-0/SEV-1 conditions. |
| [`backup.sh`](backup.sh) | Cron-friendly state-volume tarball backup. |

## Installation

### 1. Drop the unit in place

```sh
sudo cp ops/pygrove-node.service /etc/systemd/system/pygrove-node.service
sudo systemctl daemon-reload
```

### 2. Pre-create the Docker network + state volume

```sh
docker network create pygrove-net 2>/dev/null || true
docker volume create pygrove-data
```

### 3. Enable + start

```sh
sudo systemctl enable --now pygrove-node.service
sudo systemctl status pygrove-node.service
```

### 4. Verify

```sh
curl -sS http://localhost:8545/healthz
curl -sS http://localhost:8545/metrics | grep pygrove_height
```

## Hardening notes

The systemd unit goes beyond `docker run --restart unless-stopped` in three ways:

1. **Container runs `--read-only`** — the rootfs is read-only inside the container. State writes are scoped to the `pygrove-data` volume mounted at `/var/lib/pygrove`. A compromised process can't tamper with the binary or its dependencies.
2. **All capabilities dropped** — `--cap-drop=ALL`. The node doesn't need to ptrace, mount, sniff networks, or bind to privileged ports. If it somehow needs more, fail loudly and grant the specific cap.
3. **`--security-opt no-new-privileges:true`** — even a setuid binary inside the container can't escalate. Combined with `--cap-drop=ALL`, the container's privilege ceiling is "user mode, your namespace only."

The host-side `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, and `SystemCallFilter` constrain the **systemd-wrapped Docker client itself** — a defense against a compromised Docker socket that's separate from the container's own confinement.

## Production tag policy

For testnet, the unit pulls `:latest`. For mainnet, pin to a specific `:vX.Y.Z` tag and re-deploy via the runbook's rolling-update procedure. Never run mainnet on `:latest` — a CI hiccup that pushes a broken image would otherwise be a SEV-0 incident.

## Resource limits

The defaults in the unit (`--memory=2g --cpus=2 --pids-limit=256`) target a single-tenant Vultr VPS. Adjust for your host:

| Host class | `--memory` | `--cpus` | Notes |
|---|---|---|---|
| 4 GB VPS | 2g | 2 | Default. Comfortable for testnet load. |
| 8 GB VPS | 4g | 4 | Reasonable for low-traffic mainnet. |
| 32 GB+ | 16g | 8+ | Validator / archival node with high tx churn. |

`pygrove-node`'s current memory footprint is ~80 MB resident at the testnet load level; the 2g limit is well above that, leaving headroom for the WASM VM's per-contract working sets.
