#!/bin/sh
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -eu

log() {
  printf '%s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "keyprovider error: missing required command '$1'"
    exit 1
  }
}

need_cmd jq

b64dec() {
  printf '%s' "$1" | tr -d '\n\r ' | jq -Rr '@base64d'
}

b64enc() {
  jq -Rs -r '@base64' | tr -d '\n'
}

http_post_json() {
  url="$1"
  payload="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -H 'Content-Type: application/json' -d "$payload" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- --header='Content-Type: application/json' --post-data="$payload" "$url"
  elif command -v busybox >/dev/null 2>&1; then
    busybox wget -qO- --header='Content-Type: application/json' --post-data="$payload" "$url"
  else
    log "keyprovider error: missing curl/wget for HTTP"
    exit 1
  fi
}

extract_params() {
  cfg_json="$1"
  provider="${KEYPROVIDER_NAME:-fakekms}"
  PARAM_KMS_URL=""
  PARAM_KID=""
  entries=$(printf '%s' "$cfg_json" | jq -r --arg provider "$provider" '.parameters[$provider][]? // empty')
  for entry in $entries; do
    [ -z "$entry" ] && continue
    decoded=$(b64dec "$entry" 2>/dev/null || true)
    [ -z "$decoded" ] && continue
    case "$decoded" in
      *=*)
        key=${decoded%%=*}
        val=${decoded#*=}
        case "$key" in
          kms_url) PARAM_KMS_URL="$val" ;;
          kid) PARAM_KID="$val" ;;
        esac
        ;;
      *)
        if [ -z "${PARAM_KID:-}" ]; then
          PARAM_KID="$decoded"
        fi
        ;;
    esac
  done
}

request=$(cat)
op=$(printf '%s' "$request" | jq -r '.op // empty' | tr '[:upper:]' '[:lower:]')

case "$op" in
  keywrap)
    optsdata=$(printf '%s' "$request" | jq -r '.keywrapparams.optsdata // empty')
    [ -n "$optsdata" ] || {
      log "keyprovider error: missing optsdata for keywrap"
      exit 1
    }

    ec=$(printf '%s' "$request" | jq -c '.keywrapparams.ec // {}')
    extract_params "$ec"

    kms_url="${PARAM_KMS_URL:-${FAKE_KMS_URL:-}}"
    [ -n "$kms_url" ] || {
      log "keyprovider error: missing FAKE_KMS_URL"
      exit 1
    }
    kid="${PARAM_KID:-${FAKE_KMS_KID:-poc}}"

    payload=$(jq -n --arg kid "$kid" --arg dek_b64 "$optsdata" '{kid:$kid, dek_b64:$dek_b64}')
    resp=$(http_post_json "${kms_url%/}/wrap" "$payload")

    wrapped_key_b64=$(printf '%s' "$resp" | jq -r '.wrapped_key_b64 // empty')
    [ -n "$wrapped_key_b64" ] || {
      log "keyprovider error: kms response missing wrapped_key_b64"
      exit 1
    }
    wrap_type=$(printf '%s' "$resp" | jq -r '.wrap_type // "toy"')

    annotation=$(jq -n \
      --arg kid "$kid" \
      --arg wrap_type "$wrap_type" \
      --arg wrapped_key_b64 "$wrapped_key_b64" \
      --arg key_url "fakekms://$kid" \
      '{kid:$kid, wrap_type:$wrap_type, wrapped_key_b64:$wrapped_key_b64, key_url:$key_url}')

    annotation_b64=$(printf '%s' "$annotation" | b64enc)
    jq -n --arg annotation "$annotation_b64" '{keywrapresults:{annotation:$annotation}}'
    ;;

  keyunwrap)
    annotation_b64=$(printf '%s' "$request" | jq -r '.keyunwrapparams.annotation // empty')
    [ -n "$annotation_b64" ] || {
      log "keyprovider error: missing annotation for keyunwrap"
      exit 1
    }
    annotation_json=$(b64dec "$annotation_b64" 2>/dev/null || true)
    [ -n "$annotation_json" ] || {
      log "keyprovider error: invalid annotation payload"
      exit 1
    }

    wrapped_key_b64=$(printf '%s' "$annotation_json" | jq -r '.wrapped_key_b64 // empty')
    [ -n "$wrapped_key_b64" ] || {
      log "keyprovider error: annotation missing wrapped_key_b64"
      exit 1
    }

    dc=$(printf '%s' "$request" | jq -c '.keyunwrapparams.dc // {}')
    extract_params "$dc"

    kms_url="${PARAM_KMS_URL:-${FAKE_KMS_URL:-}}"
    [ -n "$kms_url" ] || {
      log "keyprovider error: missing FAKE_KMS_URL"
      exit 1
    }

    kid=$(printf '%s' "$annotation_json" | jq -r '.kid // empty')
    if [ -z "$kid" ]; then
      kid="${PARAM_KID:-${FAKE_KMS_KID:-poc}}"
    fi

    payload=$(jq -n --arg kid "$kid" --arg wrapped_key_b64 "$wrapped_key_b64" '{kid:$kid, wrapped_key_b64:$wrapped_key_b64}')
    resp=$(http_post_json "${kms_url%/}/unwrap" "$payload")

    dek_b64=$(printf '%s' "$resp" | jq -r '.dek_b64 // empty')
    [ -n "$dek_b64" ] || {
      log "keyprovider error: kms response missing dek_b64"
      exit 1
    }

    jq -n --arg optsdata "$dek_b64" '{keyunwrapresults:{optsdata:$optsdata}}'
    ;;

  *)
    log "keyprovider error: unsupported op '${op}'"
    exit 1
    ;;
esac
