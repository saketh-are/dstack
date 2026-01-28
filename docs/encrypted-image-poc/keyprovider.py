#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import sys
import socket


def log(message):
    sys.stderr.write(message + "\n")


def b64decode(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    value = "".join(value.split())
    value = value.rstrip("=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    index = {c: i for i, c in enumerate(alphabet)}
    out = bytearray()
    buf = 0
    bits = 0
    for ch in value:
        if ch not in index:
            continue
        buf = (buf << 6) | index[ch]
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def b64encode(value):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = []
    for i in range(0, len(value), 3):
        chunk = value[i : i + 3]
        pad = 3 - len(chunk)
        n = 0
        for b in chunk:
            n = (n << 8) | b
        n <<= pad * 8
        for shift in (18, 12, 6, 0):
            out.append(alphabet[(n >> shift) & 0x3F])
        if pad:
            out[-pad:] = "=" * pad
    return "".join(out)


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


def _parse_http_url(url):
    if not url.startswith("http://"):
        raise ValueError("only http:// URLs are supported")
    rest = url[len("http://") :]
    host_port, _, _path = rest.partition("/")
    path = "/" + _path if _path else "/"
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = host_port, 80
    return host, port, path


def _http_post_json(url, path, payload):
    host, port, _ = _parse_http_url(url)
    body = json.dumps(payload).encode("utf-8")
    request = (
        f"POST {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii") + body

    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(request)
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()

    header, _, body = data.partition(b"\r\n\r\n")
    status_line = header.split(b"\r\n", 1)[0]
    if not status_line.startswith(b"HTTP/"):
        raise ValueError("invalid HTTP response from KMS")
    parts = status_line.split()
    code = int(parts[1]) if len(parts) > 1 else 0
    if code >= 300:
        raise ValueError(f"KMS returned HTTP {code}")
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
    response = _http_post_json(
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

    response = _http_post_json(
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
