#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import base64
import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256


def b64decode(value):
    return base64.b64decode(value.encode("utf-8"), validate=True)


def b64encode(value):
    return base64.b64encode(value).decode("utf-8")


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def get_master_key():
    encoded = os.getenv("FAKE_KMS_MASTER_KEY_B64")
    if encoded:
        return b64decode(encoded)
    return secrets.token_bytes(32)


MASTER_KEY = get_master_key()


def derive_kek(kid):
    return hmac.new(MASTER_KEY, kid.encode("utf-8"), sha256).digest()


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        return json.loads(body.decode("utf-8"))

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/wrap", "/unwrap"):
            self._send_json(404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
            kid = payload.get("kid")
            if not kid:
                raise ValueError("missing kid")
            kek = derive_kek(kid)
            if self.path == "/wrap":
                dek_b64 = payload.get("dek_b64")
                if not dek_b64:
                    raise ValueError("missing dek_b64")
                dek = b64decode(dek_b64)
                wrapped = xor_bytes(dek, kek)
                self._send_json(
                    200,
                    {
                        "kid": kid,
                        "wrapped_key_b64": b64encode(wrapped),
                        "wrap_type": "xor",
                    },
                )
                return
            wrapped_key_b64 = payload.get("wrapped_key_b64")
            if not wrapped_key_b64:
                raise ValueError("missing wrapped_key_b64")
            wrapped = b64decode(wrapped_key_b64)
            dek = xor_bytes(wrapped, kek)
            self._send_json(200, {"kid": kid, "dek_b64": b64encode(dek)})
        except Exception as exc:
            self._send_json(400, {"error": str(exc)})


def main():
    parser = argparse.ArgumentParser(description="toy KMS for ocicrypt POC")
    parser.add_argument("--listen", default="127.0.0.1", help="listen address")
    parser.add_argument("--port", type=int, default=9090, help="listen port")
    args = parser.parse_args()

    server = HTTPServer((args.listen, args.port), Handler)
    print(f"fake KMS listening on {args.listen}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
