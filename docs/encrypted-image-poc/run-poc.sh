#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

log() {
  printf '%s\n' "$*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "error: missing required command '$1'"
    exit 1
  }
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

require_cmd docker
require_cmd skopeo
require_cmd jq
require_cmd python3

if ! skopeo copy --help 2>/dev/null | grep -q -- '--encryption-key'; then
  log "error: skopeo build lacks ocicrypt encryption support (--encryption-key)"
  exit 1
fi

HOST_IP="${HOST_IP:-}"
if [[ -z "${HOST_IP}" ]]; then
  if command -v ip >/dev/null 2>&1; then
    HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}')
  fi
fi
if [[ -z "${HOST_IP}" ]]; then
  if command -v hostname >/dev/null 2>&1; then
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
fi
if [[ -z "${HOST_IP}" ]]; then
  log "error: unable to determine HOST_IP; set HOST_IP explicitly"
  exit 1
fi

REGISTRY_PORT="${REGISTRY_PORT:-5000}"
KMS_PORT="${KMS_PORT:-9090}"
REGISTRY_NAME="${REGISTRY_NAME:-dstack-poc-registry}"
KMS_PID_FILE="${KMS_PID_FILE:-/tmp/fake_kms.pid}"
KMS_LOG="${KMS_LOG:-${SCRIPT_DIR}/fake_kms.log}"
SKOPEO_PORT="${SKOPEO_PORT:-9100}"
SKOPEO_BIN_DIR="${SKOPEO_BIN_DIR:-${SCRIPT_DIR}/poc-bins}"
SKOPEO_BIN_NAME="${SKOPEO_BIN_NAME:-skopeo}"
SKOPEO_SRC_PATH="${SKOPEO_SRC_PATH:-}"
LIBSUBID_PATH="${LIBSUBID_PATH:-}"
LIBECONF_PATH="${LIBECONF_PATH:-}"
LIBCRYPT_PATH="${LIBCRYPT_PATH:-}"
SKOPEO_PID_FILE="${SKOPEO_PID_FILE:-/tmp/skopeo_http.pid}"
SKOPEO_LOG="${SKOPEO_LOG:-${SCRIPT_DIR}/skopeo_http.log}"

FAKE_KMS_KID="${FAKE_KMS_KID:-poc}"
PLAINTEXT_IMAGE_REF="${PLAINTEXT_IMAGE_REF:-alpine:3.20}"
LOCAL_IMAGE_REF="${LOCAL_IMAGE_REF:-poc:decrypted}"
ENCRYPTED_IMAGE_REF="${ENCRYPTED_IMAGE_REF:-${HOST_IP}:${REGISTRY_PORT}/poc:encrypted}"

if [[ -n "${SKOPEO_SRC_PATH}" ]]; then
  SKOPEO_BIN="${SKOPEO_SRC_PATH}"
else
  SKOPEO_BIN="$(command -v skopeo)"
fi
if [[ ! -x "${SKOPEO_BIN}" ]]; then
  log "error: skopeo binary not found or not executable at ${SKOPEO_BIN}"
  exit 1
fi
mkdir -p "${SKOPEO_BIN_DIR}"
cp "${SKOPEO_BIN}" "${SKOPEO_BIN_DIR}/${SKOPEO_BIN_NAME}"
mkdir -p "${SKOPEO_BIN_DIR}/lib"
if [[ -n "${LIBSUBID_PATH}" ]]; then
  cp "${LIBSUBID_PATH}" "${SKOPEO_BIN_DIR}/lib/$(basename "${LIBSUBID_PATH}")"
  if [[ "${LIBSUBID_PATH}" == *libsubid.so.5.0.0 ]]; then
    ln -sf "${SKOPEO_BIN_DIR}/lib/libsubid.so.5.0.0" "${SKOPEO_BIN_DIR}/lib/libsubid.so.5"
  elif [[ "${LIBSUBID_PATH}" == *libsubid.so.5 ]]; then
    ln -sf "${SKOPEO_BIN_DIR}/lib/libsubid.so.5" "${SKOPEO_BIN_DIR}/lib/libsubid.so.5"
  fi
fi
if [[ -n "${LIBECONF_PATH}" ]]; then
  cp "${LIBECONF_PATH}" "${SKOPEO_BIN_DIR}/lib/$(basename "${LIBECONF_PATH}")"
  if [[ "${LIBECONF_PATH}" == *libeconf.so.0.* ]]; then
    ln -sf "${SKOPEO_BIN_DIR}/lib/$(basename "${LIBECONF_PATH}")" "${SKOPEO_BIN_DIR}/lib/libeconf.so.0"
  elif [[ "${LIBECONF_PATH}" == *libeconf.so.0 ]]; then
    ln -sf "${SKOPEO_BIN_DIR}/lib/libeconf.so.0" "${SKOPEO_BIN_DIR}/lib/libeconf.so.0"
  fi
fi
if [[ -n "${LIBCRYPT_PATH}" ]]; then
  cp "${LIBCRYPT_PATH}" "${SKOPEO_BIN_DIR}/lib/$(basename "${LIBCRYPT_PATH}")"
  if [[ "${LIBCRYPT_PATH}" == *libcrypt.so.2.* ]]; then
    ln -sf "${SKOPEO_BIN_DIR}/lib/$(basename "${LIBCRYPT_PATH}")" "${SKOPEO_BIN_DIR}/lib/libcrypt.so.2"
  elif [[ "${LIBCRYPT_PATH}" == *libcrypt.so.2 ]]; then
    ln -sf "${SKOPEO_BIN_DIR}/lib/libcrypt.so.2" "${SKOPEO_BIN_DIR}/lib/libcrypt.so.2"
  fi
fi
SKOPEO_URL="http://${HOST_IP}:${SKOPEO_PORT}/${SKOPEO_BIN_NAME}"
LIBSUBID_URL=""
LIBECONF_URL=""
LIBCRYPT_URL=""
if [[ -f "${SKOPEO_BIN_DIR}/lib/libsubid.so.5" ]]; then
  LIBSUBID_URL="http://${HOST_IP}:${SKOPEO_PORT}/lib/libsubid.so.5"
fi
if [[ -f "${SKOPEO_BIN_DIR}/lib/libeconf.so.0" ]]; then
  LIBECONF_URL="http://${HOST_IP}:${SKOPEO_PORT}/lib/libeconf.so.0"
fi
if [[ -f "${SKOPEO_BIN_DIR}/lib/libcrypt.so.2" ]]; then
  LIBCRYPT_URL="http://${HOST_IP}:${SKOPEO_PORT}/lib/libcrypt.so.2"
fi

if docker ps -a --format '{{.Names}}' | grep -qx "${REGISTRY_NAME}"; then
  if ! docker ps --format '{{.Names}}' | grep -qx "${REGISTRY_NAME}"; then
    log "starting registry container ${REGISTRY_NAME}"
    docker start "${REGISTRY_NAME}" >/dev/null
  fi
else
  log "starting registry container ${REGISTRY_NAME}"
  docker run -d --name "${REGISTRY_NAME}" -p "${REGISTRY_PORT}:5000" registry:2 >/dev/null
fi

if [[ -f "${KMS_PID_FILE}" ]] && kill -0 "$(cat "${KMS_PID_FILE}")" 2>/dev/null; then
  log "fake KMS already running (pid $(cat "${KMS_PID_FILE}"))"
else
  if [[ -z "${FAKE_KMS_MASTER_KEY_B64:-}" ]]; then
    FAKE_KMS_MASTER_KEY_B64=$(python3 - <<'PY'
import base64
import os
print(base64.b64encode(os.urandom(32)).decode("utf-8"))
PY
    )
  fi
  export FAKE_KMS_MASTER_KEY_B64
  log "starting fake KMS on 0.0.0.0:${KMS_PORT}"
  python3 "${SCRIPT_DIR}/fake_kms.py" --listen 0.0.0.0 --port "${KMS_PORT}" >"${KMS_LOG}" 2>&1 &
  echo $! >"${KMS_PID_FILE}"
fi

if [[ -f "${SKOPEO_PID_FILE}" ]] && kill -0 "$(cat "${SKOPEO_PID_FILE}")" 2>/dev/null; then
  log "skopeo file server already running (pid $(cat "${SKOPEO_PID_FILE}"))"
else
  log "starting skopeo file server on 0.0.0.0:${SKOPEO_PORT}"
  python3 -m http.server "${SKOPEO_PORT}" --directory "${SKOPEO_BIN_DIR}" >"${SKOPEO_LOG}" 2>&1 &
  echo $! >"${SKOPEO_PID_FILE}"
fi

FAKE_KMS_URL="http://${HOST_IP}:${KMS_PORT}"

chmod +x "${SCRIPT_DIR}/keyprovider.py" "${SCRIPT_DIR}/encrypt-image.sh"

export FAKE_KMS_URL
export FAKE_KMS_KID
export KEYPROVIDER_BIN="${SCRIPT_DIR}/keyprovider.py"
export PLAINTEXT_IMAGE_REF
export ENCRYPTED_IMAGE_REF
export SKOPEO_DEST_TLS_VERIFY="${SKOPEO_DEST_TLS_VERIFY:-false}"

log "encrypting and pushing image"
"${SCRIPT_DIR}/encrypt-image.sh"

INIT_GEN="${SCRIPT_DIR}/init_script.generated.sh"
PRE_GEN="${SCRIPT_DIR}/pre_launch_script.generated.sh"
APP_COMPOSE="${SCRIPT_DIR}/app-compose.json"

{
  cat "${SCRIPT_DIR}/init_script.sh"
  echo ""
  echo "cat > /run/ocicrypt/keyprovider.py <<'PY'"
  cat "${SCRIPT_DIR}/keyprovider.py"
  echo "PY"
  echo "chmod 700 /run/ocicrypt/keyprovider.py"
} >"${INIT_GEN}"

awk -v enc="${ENCRYPTED_IMAGE_REF}" -v local="${LOCAL_IMAGE_REF}" -v kms="${FAKE_KMS_URL}" -v kid="${FAKE_KMS_KID}" -v skurl="${SKOPEO_URL}" -v suburl="${LIBSUBID_URL}" -v ecurl="${LIBECONF_URL}" -v lcurl="${LIBCRYPT_URL}" '
{
  print
  if ($0 == "set -euo pipefail") {
    print ""
    print "export ENCRYPTED_IMAGE_REF=" enc
    print "export LOCAL_IMAGE_REF=" local
    print "export FAKE_KMS_URL=" kms
    print "export FAKE_KMS_KID=" kid
    print "export SKOPEO_SRC_TLS_VERIFY=false"
    print "export SKOPEO_URL='"'"'" skurl "'"'"'"
    if (suburl != "") {
      print "export LIBSUBID_URL='"'"'" suburl "'"'"'"
    }
    if (ecurl != "") {
      print "export LIBECONF_URL='"'"'" ecurl "'"'"'"
    }
    if (lcurl != "") {
      print "export LIBCRYPT_URL='"'"'" lcurl "'"'"'"
    }
  }
}' "${SCRIPT_DIR}/pre_launch_script.sh" >"${PRE_GEN}"

chmod +x "${INIT_GEN}" "${PRE_GEN}"

INIT_SCRIPT=$(jq -Rs . "${INIT_GEN}")
PRE_LAUNCH_SCRIPT=$(jq -Rs . "${PRE_GEN}")
COMPOSE_FILE=$(jq -Rs . "${SCRIPT_DIR}/docker-compose.yaml")

cat >"${APP_COMPOSE}" <<EOF
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

log "generated app-compose.json: ${APP_COMPOSE}"
log "next: launch the CVM with this app-compose.json, then verify in the CVM:"
log "  docker images | grep poc"
log "fake KMS pid: $(cat "${KMS_PID_FILE}") (log: ${KMS_LOG})"
log "registry container: ${REGISTRY_NAME} (${HOST_IP}:${REGISTRY_PORT})"
log "skopeo file server: 0.0.0.0:${SKOPEO_PORT} (pid: $(cat "${SKOPEO_PID_FILE}") log: ${SKOPEO_LOG})"
