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

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    log "error: missing required env var '$name'"
    exit 1
  fi
}

require_cmd skopeo

require_var PLAINTEXT_IMAGE_REF
require_var ENCRYPTED_IMAGE_REF
require_var FAKE_KMS_URL
require_var KEYPROVIDER_BIN

KEYPROVIDER_NAME="${KEYPROVIDER_NAME:-fakekms}"
KEYPROVIDER_PARAMS="${KEYPROVIDER_PARAMS:-kid=${FAKE_KMS_KID:-poc}}"

SRC_REF="${PLAINTEXT_IMAGE_REF}"
DST_REF="${ENCRYPTED_IMAGE_REF}"
if [[ "${SRC_REF}" != *"://"* ]]; then
  SRC_REF="docker-daemon:${SRC_REF}"
fi
if [[ "${DST_REF}" != *"://"* ]]; then
  DST_REF="docker://${DST_REF}"
fi

OCICRYPT_DIR="${OCICRYPT_DIR:-/tmp/ocicrypt}"
OCICRYPT_CONFIG="${OCICRYPT_CONFIG:-${OCICRYPT_DIR}/ocicrypt.conf}"
mkdir -p "${OCICRYPT_DIR}"
chmod 700 "${OCICRYPT_DIR}"

cat >"${OCICRYPT_CONFIG}" <<EOF_CONFIG
{
  "key-providers": {
    "${KEYPROVIDER_NAME}": {
      "cmd": {
        "path": "${KEYPROVIDER_BIN}",
        "args": []
      }
    }
  }
}
EOF_CONFIG

export OCICRYPT_KEYPROVIDER_CONFIG="${OCICRYPT_CONFIG}"
export FAKE_KMS_URL
export FAKE_KMS_KID="${FAKE_KMS_KID:-poc}"
export KEYPROVIDER_NAME

SKOPEO_ARGS=(--insecure-policy)
if [[ -n "${REGISTRY_AUTH_FILE:-}" ]]; then
  SKOPEO_ARGS+=(--authfile "${REGISTRY_AUTH_FILE}")
fi
if [[ -n "${SKOPEO_SRC_TLS_VERIFY:-}" ]]; then
  SKOPEO_ARGS+=(--src-tls-verify "${SKOPEO_SRC_TLS_VERIFY}")
fi
if [[ -n "${SKOPEO_DEST_TLS_VERIFY:-}" ]]; then
  SKOPEO_ARGS+=(--dest-tls-verify "${SKOPEO_DEST_TLS_VERIFY}")
fi

log "encrypting ${SRC_REF} -> ${DST_REF}"

skopeo copy "${SKOPEO_ARGS[@]}" \
  --encryption-key "provider:${KEYPROVIDER_NAME}:${KEYPROVIDER_PARAMS}" \
  "${SRC_REF}" \
  "${DST_REF}"

log "done"
