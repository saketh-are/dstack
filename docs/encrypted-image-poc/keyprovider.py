#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import os
import sys
import urllib.error
import urllib.request


def log(message):
    sys.stderr.write(message + "\n")


def b64decode(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return base64.b64decode(value.encode("utf-8"), validate=True)


def b64encode(value):
    return base64.b64encode(value).decode("utf-8")


def extract_params(config):
    params = {}
    if not config:
        return params
    raw_params = config.get("parameters") or {}
    provider_name = os.getenv("KEYPROVIDER_NAME", "fakekms")
    entries = raw_params.get(provider_name) or []
    for entry in entries:
        try:
            decoded = b64decode(entry).decode("utf-8")
        except Exception:
            continue
        if "=" in decoded:
            key, value = decoded.split("=", 1)
            params[key.strip()] = value.strip()
        elif decoded and "kid" not in params:
            params["kid"] = decoded.strip()
    return params


def kms_request(kms_url, path, payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        kms_url.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read()
    return json.loads(body.decode("utf-8"))


def handle_keywrap(request):
    params = request.get("keywrapparams") or {}
    encrypt_config = params.get("ec") or {}
    provider_params = extract_params(encrypt_config)

    kms_url = provider_params.get("kms_url") or os.getenv("FAKE_KMS_URL")
    kid = provider_params.get("kid") or os.getenv("FAKE_KMS_KID", "poc")
    if not kms_url:
        raise ValueError("missing FAKE_KMS_URL")

    opts_data = params.get("optsdata")
    if not opts_data:
        raise ValueError("missing optsdata for keywrap")

    dek = b64decode(opts_data)
    response = kms_request(
        kms_url,
        "/wrap",
        {
            "kid": kid,
            "dek_b64": b64encode(dek),
        },
    )

    wrapped_key_b64 = response.get("wrapped_key_b64")
    if not wrapped_key_b64:
        raise ValueError("kms response missing wrapped_key_b64")

    annotation = {
        "kid": kid,
        "wrap_type": response.get("wrap_type", "toy"),
        "wrapped_key_b64": wrapped_key_b64,
        "key_url": f"fakekms://{kid}",
    }

    return {
        "keywrapresults": {
            "annotation": b64encode(json.dumps(annotation).encode("utf-8")),
        }
    }


def handle_keyunwrap(request):
    params = request.get("keyunwrapparams") or {}
    decrypt_config = params.get("dc") or {}
    provider_params = extract_params(decrypt_config)

    kms_url = provider_params.get("kms_url") or os.getenv("FAKE_KMS_URL")
    if not kms_url:
        raise ValueError("missing FAKE_KMS_URL")

    annotation_b64 = params.get("annotation")
    if not annotation_b64:
        raise ValueError("missing annotation for keyunwrap")

    annotation_raw = b64decode(annotation_b64)
    annotation = json.loads(annotation_raw.decode("utf-8"))

    wrapped_key_b64 = annotation.get("wrapped_key_b64")
    if not wrapped_key_b64:
        raise ValueError("annotation missing wrapped_key_b64")

    kid = (
        annotation.get("kid")
        or provider_params.get("kid")
        or os.getenv("FAKE_KMS_KID", "poc")
    )

    response = kms_request(
        kms_url,
        "/unwrap",
        {
            "kid": kid,
            "wrapped_key_b64": wrapped_key_b64,
        },
    )

    dek_b64 = response.get("dek_b64")
    if not dek_b64:
        raise ValueError("kms response missing dek_b64")

    return {
        "keyunwrapresults": {
            "optsdata": dek_b64,
        }
    }


def main():
    try:
        data = sys.stdin.buffer.read()
        if not data:
            raise ValueError("no input received")
        request = json.loads(data.decode("utf-8"))
        op = (request.get("op") or "").lower()
        if op == "keywrap":
            response = handle_keywrap(request)
        elif op == "keyunwrap":
            response = handle_keyunwrap(request)
        else:
            raise ValueError(f"unsupported op '{op}'")
        sys.stdout.write(json.dumps(response))
    except Exception as exc:
        log(f"keyprovider error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
