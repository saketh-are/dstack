#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

log() {
  printf '%s\n' "$*" >&2
}

PERSIST_DIR="${PERSIST_DIR:-/dstack/persistent}"
OCI_CACHE_DIR="${OCI_CACHE_DIR:-${PERSIST_DIR}/oci-cache}"

log "init: creating persistent dirs"
mkdir -p "${OCI_CACHE_DIR}"
chmod 700 "${OCI_CACHE_DIR}"

log "init: done"
