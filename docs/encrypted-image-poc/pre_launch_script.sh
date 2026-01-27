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

sanitize_ref() {
  printf '%s' "$1" | tr '/:@' '___'
}

require_cmd docker
require_cmd skopeo

require_var ENCRYPTED_IMAGE_REF
require_var LOCAL_IMAGE_REF
require_var FAKE_KMS_URL

KEYPROVIDER_NAME="${KEYPROVIDER_NAME:-fakekms}"
KEYPROVIDER_PARAMS="${KEYPROVIDER_PARAMS:-kid=${FAKE_KMS_KID:-poc}}"
KEYPROVIDER_BIN="${KEYPROVIDER_BIN:-/run/ocicrypt/keyprovider.py}"

if [[ ! -x "${KEYPROVIDER_BIN}" ]]; then
  log "error: key provider not found at ${KEYPROVIDER_BIN}"
  log "hint: stage keyprovider.py in init_script or bake it into the base image"
  exit 1
fi

LOCK_FILE="${LOCK_FILE:-/run/dstack/pull-decrypt.lock}"
mkdir -p "$(dirname "${LOCK_FILE}")"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  log "another pull/decrypt is already running; exiting"
  exit 0
fi

OCICRYPT_DIR="${OCICRYPT_DIR:-/run/ocicrypt}"
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

if [[ -n "${REGISTRY_AUTH_B64:-}" ]]; then
  AUTH_FILE="${OCICRYPT_DIR}/registry-auth.json"
  printf '%s' "${REGISTRY_AUTH_B64}" | base64 -d >"${AUTH_FILE}"
  chmod 600 "${AUTH_FILE}"
  export REGISTRY_AUTH_FILE="${AUTH_FILE}"
fi

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

DOCKER_ROOT=$(docker info -f '{{.DockerRootDir}}' || true)
if [[ -n "${DOCKER_ROOT}" ]]; then
  DOCKER_ROOT_SRC=$(findmnt -n -o SOURCE -T "${DOCKER_ROOT}" 2>/dev/null || true)
  log "docker root: ${DOCKER_ROOT} (mount source: ${DOCKER_ROOT_SRC})"
  if [[ "${REQUIRE_ENCRYPTED_STORAGE:-0}" == "1" ]]; then
    if [[ "${DOCKER_ROOT_SRC}" != /dev/mapper/* && "${DOCKER_ROOT_SRC}" != /dev/dm-* ]]; then
      log "error: docker root not on encrypted mapper device"
      exit 1
    fi
  fi
fi

MARKER_DIR="${OCI_CACHE_DIR:-/dstack/persistent/oci-cache}"
mkdir -p "${MARKER_DIR}"
MARKER_FILE="${MARKER_DIR}/$(sanitize_ref "${ENCRYPTED_IMAGE_REF}").digest"

REMOTE_DIGEST=""
if REMOTE_DIGEST=$(skopeo inspect "${SKOPEO_ARGS[@]}" --format '{{.Digest}}' "docker://${ENCRYPTED_IMAGE_REF}" 2>/dev/null); then
  if [[ -f "${MARKER_FILE}" ]]; then
    CACHED_DIGEST=$(cat "${MARKER_FILE}" || true)
    if [[ -n "${CACHED_DIGEST}" && "${CACHED_DIGEST}" == "${REMOTE_DIGEST}" ]]; then
      if docker image inspect "${LOCAL_IMAGE_REF}" >/dev/null 2>&1; then
        log "image already imported for digest ${REMOTE_DIGEST}; skipping"
        exit 0
      fi
    fi
  fi
fi

if docker image inspect "${LOCAL_IMAGE_REF}" >/dev/null 2>&1; then
  if [[ "${FORCE_REIMPORT:-0}" != "1" ]]; then
    log "image ${LOCAL_IMAGE_REF} already present; skipping (set FORCE_REIMPORT=1 to override)"
    exit 0
  fi
fi

log "pulling + decrypting ${ENCRYPTED_IMAGE_REF} -> ${LOCAL_IMAGE_REF}"

skopeo copy "${SKOPEO_ARGS[@]}" \
  --decryption-key "provider:${KEYPROVIDER_NAME}:${KEYPROVIDER_PARAMS}" \
  "docker://${ENCRYPTED_IMAGE_REF}" \
  "docker-daemon:${LOCAL_IMAGE_REF}"

if ! docker image inspect "${LOCAL_IMAGE_REF}" >/dev/null 2>&1; then
  log "error: docker image not found after import"
  exit 1
fi

if [[ -n "${REMOTE_DIGEST}" ]]; then
  printf '%s' "${REMOTE_DIGEST}" >"${MARKER_FILE}"
fi

log "pre-launch decrypt/import complete"
