#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

log() {
  printf '%s\n' "$*" >&2
}

SKOPEO_BIN_DIR="${SKOPEO_BIN_DIR:-/run/ocicrypt/bin}"
SKOPEO_LIB_DIR="${SKOPEO_LIB_DIR:-/run/ocicrypt/lib}"
export PATH="${SKOPEO_BIN_DIR}:${PATH}"
export LD_LIBRARY_PATH="${SKOPEO_LIB_DIR}:${LD_LIBRARY_PATH:-}"

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
require_cmd flock

download_url() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${url}" -o "${dest}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${dest}" "${url}"
  elif command -v busybox >/dev/null 2>&1; then
    busybox wget -qO "${dest}" "${url}"
  else
    log "error: missing curl/wget/busybox for download"
    exit 1
  fi
}

ensure_skopeo() {
  if [[ -z "${SKOPEO_URL:-}" ]]; then
    log "error: skopeo missing and SKOPEO_URL not set"
    exit 1
  fi

  mkdir -p "${SKOPEO_BIN_DIR}"
  if [[ -n "${LIBSUBID_URL:-}" || -n "${LIBECONF_URL:-}" || -n "${LIBCRYPT_URL:-}" ]]; then
    mkdir -p "${SKOPEO_LIB_DIR}"
    if [[ -n "${LIBSUBID_URL:-}" && ! -s "${SKOPEO_LIB_DIR}/libsubid.so.5" ]]; then
      download_url "${LIBSUBID_URL}" "${SKOPEO_LIB_DIR}/libsubid.so.5"
    fi
    if [[ -n "${LIBECONF_URL:-}" && ! -s "${SKOPEO_LIB_DIR}/libeconf.so.0" ]]; then
      download_url "${LIBECONF_URL}" "${SKOPEO_LIB_DIR}/libeconf.so.0"
    fi
    if [[ -n "${LIBCRYPT_URL:-}" && ! -s "${SKOPEO_LIB_DIR}/libcrypt.so.2" ]]; then
      download_url "${LIBCRYPT_URL}" "${SKOPEO_LIB_DIR}/libcrypt.so.2"
    fi
  fi

  if command -v skopeo >/dev/null 2>&1; then
    return 0
  fi
  log "skopeo missing; downloading from ${SKOPEO_URL}"
  download_url "${SKOPEO_URL}" "${SKOPEO_BIN_DIR}/skopeo"
  chmod 755 "${SKOPEO_BIN_DIR}/skopeo"
}

b64decode() {
  if command -v base64 >/dev/null 2>&1; then
    if base64 -d </dev/null >/dev/null 2>&1; then
      tr -d '\n\r ' | base64 -d
    else
      tr -d '\n\r ' | base64 -D
    fi
  elif command -v jq >/dev/null 2>&1; then
    tr -d '\n\r ' | jq -Rr '@base64d'
  else
    log "error: missing base64 or jq for decode"
    exit 1
  fi
}

ensure_skopeo
require_cmd skopeo

SKOPEO_HELP=$(skopeo copy --help 2>&1) || {
  log "error: failed to run skopeo: ${SKOPEO_HELP}"
  exit 1
}
if ! printf '%s' "${SKOPEO_HELP}" | grep -q -- '--decryption-key'; then
  log "error: skopeo build lacks ocicrypt decryption support (--decryption-key)"
  exit 1
fi

require_var ENCRYPTED_IMAGE_REF
require_var LOCAL_IMAGE_REF
require_var FAKE_KMS_URL

KEYPROVIDER_NAME="${KEYPROVIDER_NAME:-fakekms}"
KEYPROVIDER_PARAMS="${KEYPROVIDER_PARAMS:-kid=${FAKE_KMS_KID:-poc}}"
KEYPROVIDER_BIN="${KEYPROVIDER_BIN:-/run/ocicrypt/keyprovider.sh}"

if [[ ! -x "${KEYPROVIDER_BIN}" ]]; then
  log "error: key provider not found at ${KEYPROVIDER_BIN}"
  log "hint: stage keyprovider.sh in init_script or bake it into the base image"
  exit 1
fi
LOCK_FILE="${LOCK_FILE:-/run/dstack/pull-decrypt.lock}"
LOCK_TIMEOUT="${LOCK_TIMEOUT:-0}"
mkdir -p "$(dirname "${LOCK_FILE}")"
exec 9>"${LOCK_FILE}"
if [[ "${LOCK_TIMEOUT}" -gt 0 ]]; then
  if ! flock -w "${LOCK_TIMEOUT}" 9; then
    log "error: timed out waiting for pull/decrypt lock"
    exit 1
  fi
else
  flock 9
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
  printf '%s' "${REGISTRY_AUTH_B64}" | b64decode >"${AUTH_FILE}"
  chmod 600 "${AUTH_FILE}"
  export REGISTRY_AUTH_FILE="${AUTH_FILE}"
fi

SKOPEO_ARGS=(--insecure-policy)
if [[ -n "${REGISTRY_AUTH_FILE:-}" ]]; then
  SKOPEO_ARGS+=(--authfile "${REGISTRY_AUTH_FILE}")
fi
if [[ -n "${SKOPEO_SRC_TLS_VERIFY:-}" ]]; then
  SKOPEO_ARGS+=(--src-tls-verify="${SKOPEO_SRC_TLS_VERIFY}")
fi
if [[ -n "${SKOPEO_DEST_TLS_VERIFY:-}" ]]; then
  SKOPEO_ARGS+=(--dest-tls-verify="${SKOPEO_DEST_TLS_VERIFY}")
fi

DOCKER_ROOT=$(docker info -f '{{.DockerRootDir}}' || true)
if [[ -n "${DOCKER_ROOT}" ]]; then
  if command -v findmnt >/dev/null 2>&1; then
    DOCKER_ROOT_SRC=$(findmnt -n -o SOURCE -T "${DOCKER_ROOT}" 2>/dev/null || true)
    log "docker root: ${DOCKER_ROOT} (mount source: ${DOCKER_ROOT_SRC})"
    if [[ "${REQUIRE_ENCRYPTED_STORAGE:-0}" == "1" ]]; then
      if [[ "${DOCKER_ROOT_SRC}" != /dev/mapper/* && "${DOCKER_ROOT_SRC}" != /dev/dm-* ]]; then
        log "error: docker root not on encrypted mapper device"
        exit 1
      fi
    fi
  else
    if [[ "${REQUIRE_ENCRYPTED_STORAGE:-0}" == "1" ]]; then
      log "error: findmnt missing; cannot verify encrypted storage"
      exit 1
    fi
    log "warning: findmnt missing; skipping storage placement check"
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
    if [[ -z "${REMOTE_DIGEST}" ]]; then
      log "image ${LOCAL_IMAGE_REF} already present; remote digest unknown, skipping (set FORCE_REIMPORT=1 to override)"
      exit 0
    fi
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
