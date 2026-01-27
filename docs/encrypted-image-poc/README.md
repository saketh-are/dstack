<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>

SPDX-License-Identifier: Apache-2.0
-->

# Encrypted Image POC (dstack init_script + pre_launch_script)

This POC shows how to pull an **encrypted** container image, decrypt it inside a dstack CVM using an ocicrypt key provider, and import the decrypted image into the local Docker image store before `docker compose up` runs.

The fake KMS here is intentionally minimal and **not secure**. It exists only to validate the flow (pull -> unwrap -> decrypt -> import) and to match the *real* API shape you'll need later.

## Files in this directory

- `init_script.sh`: creates persistent cache dirs (no secrets).
- `pre_launch_script.sh`: pulls + decrypts + imports the image using ocicrypt.
- `keyprovider.py`: ocicrypt key provider **command** (invoked by skopeo).
- `fake_kms.py`: toy KMS HTTP server (`/wrap`, `/unwrap`).
- `encrypt-image.sh`: helper to create/push an encrypted image.
- `docker-compose.yaml`: minimal workload that uses the decrypted image.

## POC steps (end-to-end)

### 1) Start a registry (host)

```bash
sudo docker run -d --name registry -p 5000:5000 registry:2
```

### 2) Start the fake KMS (host)

```bash
cd docs/encrypted-image-poc
export FAKE_KMS_MASTER_KEY_B64=$(openssl rand -base64 32)
python3 fake_kms.py --listen 0.0.0.0 --port 9090
```

Leave it running.

### 3) Encrypt and push an image (host)

```bash
cd docs/encrypted-image-poc
export FAKE_KMS_URL=http://<HOST_IP>:9090
export FAKE_KMS_KID=poc
export KEYPROVIDER_BIN=$PWD/keyprovider.py
export PLAINTEXT_IMAGE_REF=alpine:3.20
export ENCRYPTED_IMAGE_REF=localhost:5000/poc:encrypted
./encrypt-image.sh
```

This will push an **encrypted** image into your local registry.

### 4) Stage the key provider inside the CVM

The pre-launch script expects the key provider command at:

```
/run/ocicrypt/keyprovider.py
```

The simplest POC path is to embed it in `init_script` (no secrets involved). Add this snippet **after** the directory setup in `init_script.sh`:

```bash
cat > /run/ocicrypt/keyprovider.py <<'PY'
# (paste the contents of keyprovider.py here)
PY
chmod 700 /run/ocicrypt/keyprovider.py
```

### 5) Set required env vars for pre_launch

Edit `pre_launch_script.sh` to set the required values **near the top** (or inject them via app-compose envs if you prefer):

```bash
export ENCRYPTED_IMAGE_REF=localhost:5000/poc:encrypted
export LOCAL_IMAGE_REF=localhost:5000/poc:decrypted
export FAKE_KMS_URL=http://<HOST_IP>:9090
export FAKE_KMS_KID=poc
```

### 6) Build the app-compose.json

You need to embed the scripts and compose YAML as JSON strings. A quick way:

```bash
cd docs/encrypted-image-poc
INIT_SCRIPT=$(jq -Rs . init_script.sh)
PRE_LAUNCH_SCRIPT=$(jq -Rs . pre_launch_script.sh)
COMPOSE_FILE=$(jq -Rs . docker-compose.yaml)

cat > app-compose.json <<EOF
{
  "manifest_version": 2,
  "name": "encrypted-image-poc",
  "runner": "docker-compose",
  "docker_compose_file": ${COMPOSE_FILE},
  "init_script": ${INIT_SCRIPT},
  "pre_launch_script": ${PRE_LAUNCH_SCRIPT},
  "gateway_enabled": false,
  "public_logs": true,
  "public_sysinfo": true,
  "allowed_envs": [],
  "secure_time": false
}
EOF
```

### 7) Run the CVM with dstack

Use your normal dstack CVM launch flow (CLI or UI). Point it at the generated `app-compose.json` and boot the VM on your TDX host.

### 8) Verify

Inside the CVM:

```bash
docker images | grep poc
```

You should see `localhost:5000/poc:decrypted` present **before** `docker compose up` runs. The container should start without pulling from the registry.

## Notes

- The fake KMS only models *unwrap this wrapped key*; it is insecure by design.
- If you restart the fake KMS without a stable `FAKE_KMS_MASTER_KEY_B64`, old images will fail to decrypt (expected for this POC).
- To enforce the "fail closed" behavior, `pre_launch_script.sh` exits non-zero on any decrypt/import failure.
- For storage placement validation, set `REQUIRE_ENCRYPTED_STORAGE=1` in `pre_launch_script.sh`.
