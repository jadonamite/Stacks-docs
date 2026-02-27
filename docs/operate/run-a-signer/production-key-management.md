# Production Signer Key Management

**Level:** Advanced / Operations / Security

---

## Overview

While setting up a Stacks Signer node takes only a few commands, securing the identity of that node is a complex operational challenge. A compromised Signer key allows an attacker to sign malicious block assertions, disrupt consensus, and potentially drain rewards.

This guide builds on the [OpSec Best Practices](opsec-best-practices.md) page and goes deeper into multi-tiered key management strategies — from secure environment injection to enterprise-grade Hardware Security Modules (HSMs) and Cloud KMS integrations.

---

## Threat Modeling: The Signer Attack Surface

To properly secure a Signer, we need to define the risks. The following tiers represent increasing levels of attacker sophistication.

### Tier 1: Accidental Leak (Human Error)

**Vector:** Committing a `.env` file or `signer-config.toml` to a public GitHub repository.

**Mechanism:** Automated bots continuously scan public repositories for strings matching the 64-character hex pattern of Stacks private keys.

**Mitigation:** Strict `.gitignore` policies and pre-commit hooks that block secrets from entering version control.

### Tier 2: Lateral Movement (OS Compromise)

**Vector:** An attacker exploits a vulnerability in a co-located service (such as a web server or Prometheus exporter) running on the same host.

**Mechanism:** The attacker reads `/proc/[pid]/environ` or searches the disk for `config.toml` to extract key material.

**Mitigation:** Process isolation, running the signer as a non-root unprivileged user, and mounting secrets into RAM-only (`tmpfs`) paths rather than persistent disk.

### Tier 3: Supply Chain Attack (Software Poisoning)

**Vector:** A malicious dependency in a Docker image or a helper script.

**Mechanism:** Malicious code exfiltrates any environment variable containing "PRIVATE_KEY" to a remote Command & Control (C2) server.

**Mitigation:** Image signing, minimal base images (Alpine or Distroless), and network egress filtering to restrict outbound connections.

### Tier 4: Physical or Hypervisor Breach

**Vector:** Direct access to the physical server or the underlying VM hypervisor.

**Mechanism:** Memory dumping (RAM scraping) extracts keys in plaintext while the signer process is running.

**Mitigation:** Hardware Security Modules (HSMs) or Cloud KMS solutions that ensure the raw private key material never exists in accessible memory.

---

## Phase 1: Environment-Based Security

The first rule of production key management is that config and secrets must be separate. Your `signer-config.toml` should describe *how* the node runs — network settings, ports, storage paths — but should never contain the private key itself.

### Hardening the Configuration File

```toml
# /etc/stacks-signer/signer-config.toml

[network]
mode = "mainnet"
local_bind_address = "0.0.0.0:30000"

[storage]
path = "/var/lib/stacks-signer"

# stacks_private_key is intentionally absent.
# The binary reads it from the STACKS_SIGNER_PRIVATE_KEY environment variable.
```

### Shell Hygiene

Never run `export STACKS_SIGNER_PRIVATE_KEY=...` directly in a shell session. The value will be persisted in `~/.bash_history`, which is readable by any process that can access the home directory.

**Secure injection pattern:**

```bash
# 1. Disable history recording for the current session
set +o history

# 2. Read the key from a protected file into a temporary variable, export it, then clear it
TEMP_KEY=$(cat /etc/stacks-signer/signer.key)
export STACKS_SIGNER_PRIVATE_KEY="$TEMP_KEY"
unset TEMP_KEY

# 3. Re-enable history logging
set -o history
```

The key file (`signer.key`) should be owned by the signer service user and set to `chmod 400` — readable only by the owner.

---

## Phase 2: Docker Secrets (Production Standard)

Default Docker setups that pass secrets as plain environment variables in `docker-compose.yml` are insecure — the value is stored in plaintext in the Compose file itself and can be inspected via `docker inspect`.

Docker Secrets solve this by storing the secret in the Docker manager's encrypted store and mounting it inside the container as a file at `/run/secrets/`. The secret never appears in the container's environment variable list and is not written to disk in unencrypted form.

### Step 1: Create the Secret

Run this on your Docker manager node. The key value is piped directly — it is never written to any file.

```bash
printf '%s' "your-64-character-hex-private-key" | docker secret create stacks_signer_key -
```

### Step 2: Configure the Compose File

```yaml
version: '3.8'

services:
  stacks-signer:
    image: hirosystems/stacks-signer:latest
    secrets:
      - stacks_signer_key
    environment:
      - SIGNER_CONFIG_PATH=/etc/stacks-signer/config.toml
    # The entrypoint reads the secret file into memory and injects it as an
    # environment variable only for the duration of the process.
    entrypoint: >
      /bin/sh -c "
        export STACKS_SIGNER_PRIVATE_KEY=$(cat /run/secrets/stacks_signer_key) &&
        exec /bin/stacks-signer run --config $$SIGNER_CONFIG_PATH
      "
    deploy:
      resources:
        limits:
          memory: 2G

secrets:
  stacks_signer_key:
    external: true
```

> **Note:** The `external: true` declaration means Docker expects this secret to already exist in the swarm (created via `docker secret create`). It will not be defined inline in the Compose file, which is intentional.

---

## Phase 3: Systemd Hardening (Bare Metal / VPS)

If you are running the signer directly on a host without Docker, systemd provides robust process isolation through Linux namespaces and security directives.

> The [OpSec Best Practices](opsec-best-practices.md) page covers the basics of running the signer as a dedicated non-root user and setting restrictive file permissions. This section extends those practices with the full set of systemd security directives.

Create `/etc/systemd/system/stacks-signer.service`:

```ini
[Unit]
Description=Stacks Signer Production Service
After=network-online.target
Wants=network-online.target

[Service]
# Run as a dedicated, non-privileged user and group
User=stacks-signer
Group=stacks-signer

# Load the private key from an EnvironmentFile with chmod 400 permissions.
# This file should contain: STACKS_SIGNER_PRIVATE_KEY=your-key-here
EnvironmentFile=/etc/stacks-signer/signer.env
ExecStart=/usr/local/bin/stacks-signer run --config /etc/stacks-signer/config.toml

# --- SYSTEMD SECURITY DIRECTIVES ---

# Restrict filesystem access to the minimum required paths
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

# Allow write access only to the signer's data directory
ReadWritePaths=/var/lib/stacks-signer

# Prevent the process from acquiring new privileges via setuid binaries
NoNewPrivileges=true

# Restrict socket families to IPv4, IPv6, and Unix domain sockets only
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Prevent the process from creating executable memory mappings
MemoryDenyWriteExecute=true

# Restrict system calls to a safe set
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

After creating this file, reload systemd and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now stacks-signer
```

Verify the security score of the unit with:

```bash
systemd-analyze security stacks-signer
```

---

## Phase 4: Cloud KMS Integration (Enterprise / Institutional)

For institutional stackers managing significant STX positions, software-level key storage on disk is insufficient. Cloud Key Management Services (KMS) ensure that the raw private key bytes are never written to disk and are only accessible to authorized workloads via cryptographic attestation.

The pattern below shows integration with AWS Secrets Manager, but the same approach applies to GCP Secret Manager or Azure Key Vault.

### AWS Secrets Manager

First, store the key in AWS:

```bash
aws secretsmanager create-secret \
  --name StacksSignerKey \
  --secret-string '{"key":"your-64-character-hex-private-key"}'
```

Then use a wrapper script as the `ExecStart` for your systemd unit or Docker entrypoint:

```bash
#!/bin/bash
# /usr/local/bin/fetch-and-run.sh
set -euo pipefail

# Fetch the secret from AWS Secrets Manager.
# The IAM role attached to this instance must have secretsmanager:GetSecretValue permission.
SECRET_JSON=$(aws secretsmanager get-secret-value \
  --secret-id StacksSignerKey \
  --query SecretString \
  --output text)

# Parse the key from the JSON payload and export it into the process environment.
# The variable exists only in memory for the lifetime of this process.
export STACKS_SIGNER_PRIVATE_KEY
STACKS_SIGNER_PRIVATE_KEY=$(echo "$SECRET_JSON" | jq -r .key)

# Unset the raw JSON immediately after extracting the key
unset SECRET_JSON

# Replace this shell process with the signer binary (exec, not subshell)
exec /usr/local/bin/stacks-signer run --config /etc/stacks-signer/config.toml
```

Make the script executable and restrict access:

```bash
chmod 500 /usr/local/bin/fetch-and-run.sh
chown stacks-signer:stacks-signer /usr/local/bin/fetch-and-run.sh
```

> **IAM Principle of Least Privilege:** The IAM role or instance profile attached to your server should only have `secretsmanager:GetSecretValue` permission scoped to the specific secret ARN — nothing broader.

---

## Operational Monitoring

A secure signer is also a monitored signer. If key injection silently fails, the signer will stop signing blocks and fall out of the active signer set without immediately obvious errors.

### Prometheus Metrics to Watch

The [How to Monitor a Signer](how-to-monitor-signer.md) guide covers full Grafana setup. Pay particular attention to these metrics in the context of key management:

- `stacks_signer_current_reward_cycle` — if this stops incrementing relative to the chain, the signer process may have failed to initialize.
- `stacks_signer_block_responses_sent` — a flatline here while the chain is producing blocks indicates the signer is not participating, which is the primary symptom of a failed key load.

### Log Alerting

Set up an alert for the following log string, which is emitted when the signer binary cannot initialize its identity:

```
"level":"error","msg":"Could not initialize signer identity"
```

This is the most direct indicator that `STACKS_SIGNER_PRIVATE_KEY` was not present or was malformed at startup.

---

## Disaster Recovery Protocol

If you have reason to believe your `STACKS_SIGNER_PRIVATE_KEY` has been exposed:

1. **Stop the signer immediately.** Kill the signer container or process to prevent any further block signing under the compromised identity.

2. **Generate a new keypair.** Use `stacks-cli` to generate a fresh account:
   ```bash
   npx @stacks/cli make_keychain
   ```

3. **Update your stacking authorization.** You will need to submit a new stacking transaction authorizing the new signer key in the PoX contract. This requires the STX wallet that controls the stacking position.

4. **Rotate all adjacent secrets.** Change your AWS/GCP credentials, rotate SSH keys on the compromised server, and audit access logs for the period of potential exposure.

5. **Conduct a post-mortem.** Trace back how the key may have been exposed — commit history, process environment inspection, log scraping — and close that vector before redeploying.

---

## Security Checklist

Before going live on mainnet, verify each of the following:

- [ ] `stacks_private_key` does not appear anywhere in `signer-config.toml`
- [ ] The signer process runs as a dedicated non-root user (not `root` or a shared account)
- [ ] `signer.env` or `signer.key` files are `chmod 400` and owned by the signer service user
- [ ] Private key is not printed to `stdout` or `stderr` in any log output
- [ ] A monitoring alert exists for the signer falling silent (no block responses)
- [ ] A documented key rotation procedure exists and has been tested
- [ ] (If using Cloud KMS) IAM permissions are scoped to the minimum required — `GetSecretValue` on the specific secret only
