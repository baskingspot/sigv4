#!/usr/bin/env python3
"""Write the reference vectors the official suite does not cover.

The official suite (test/fixtures/aws-signing-suite) has no case for a header the
signer sees but must not sign, duplicate header lines, an empty query
parameter, a path that needs a second escape, or a session token handed to the
signer out of band. This script signs one of each with botocore, the signer AWS
ships in its own Python SDK, and writes the result in the suite's file layout so
`test/suite.zig` runs both roots with the same code.

Run it from the repository root, with botocore on the interpreter:

    nix shell --impure --expr \
      'with import (builtins.getFlake "nixpkgs") {}; python3.withPackages (ps: [ ps.botocore ])' \
      -c python3 test/fixtures/generate.py

The vectors are checked in. Regenerate them only when the shapes change, and
record the botocore version in test/fixtures/README.md when they do.
"""

import json
import os
import sys

import botocore
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TIMESTAMP = "20150830T123600Z"
HOST = "example.amazonaws.com"
TOKEN = "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267"

OUT_ROOT = os.path.join(os.path.dirname(__file__), "vectors", "v4")


def sign(case, method, path, params, headers, region="us-east-1", service="service", token=None):
    """Sign one request with botocore and write the suite's files.

    `headers` are the (name, value) pairs the caller sends, in order, and a
    repeated name is a second line. botocore adds X-Amz-Date, the session token
    when it is passed as a credential, and the Authorization field; the files
    record the request as sent and the three stages of the signature.
    """
    url = f"https://{HOST}{path}"
    request = AWSRequest(
        method=method,
        url=url,
        params=dict(params) if params else None,
        data=None,
    )
    for name, value in headers:
        request.headers.add_header(name, value)
    request.context["timestamp"] = TIMESTAMP
    request.context["payload_signing_enabled"] = True

    signer = SigV4Auth(Credentials(ACCESS_KEY, SECRET_KEY, token), service, region)
    signer._modify_request_before_signing(request)
    canonical_request = signer.canonical_request(request)
    string_to_sign = signer.string_to_sign(request, canonical_request)
    signature = signer.signature(string_to_sign, request)
    signer._inject_signature_to_request(request, signature)

    directory = os.path.join(OUT_ROOT, case)
    os.makedirs(directory, exist_ok=True)

    target = path if not params else f"{path}?{wire_query(params)}"

    request_lines = [f"{method} {target} HTTP/1.1"]
    request_lines.extend(f"{name}:{value}" for name, value in headers)
    request_text = "\n".join(request_lines) + "\n\n"

    signed_lines = [f"{method} {target} HTTP/1.1"]
    signed_lines.extend(
        f"{name}:{value}"
        for name, value in request.headers.items()
        if name.lower() != "authorization"
    )
    signed_lines.append(f"Authorization:{request.headers['Authorization']}")
    signed_text = "\n".join(signed_lines) + "\n"

    context = {
        "credentials": {
            "access_key_id": ACCESS_KEY,
            "secret_access_key": SECRET_KEY,
        },
        "expiration_in_seconds": 3600,
        "normalize": True,
        "region": region,
        "service": service,
        "sign_body": False,
        "timestamp": "2015-08-30T12:36:00Z",
    }
    if token is not None:
        context["credentials"]["token"] = TOKEN

    write(directory, "request.txt", request_text)
    write(directory, "context.json", json.dumps(context, indent=4) + "\n")
    write(directory, "header-canonical-request.txt", canonical_request)
    write(directory, "header-string-to-sign.txt", string_to_sign)
    write(directory, "header-signature.txt", signature)
    write(directory, "header-signed-request.txt", signed_text)


def wire_query(params):
    return "&".join(f"{key}={value}" for key, value in params)


def write(directory, name, text):
    with open(os.path.join(directory, name), "w", encoding="utf-8", newline="\n") as file:
        file.write(text)


def main():
    # A header the request sends and the signature does not cover. botocore
    # drops user-agent on its own, which is the case a caller hits when its
    # HTTP client adds one.
    sign(
        "header-excluded",
        "GET",
        "/",
        None,
        [("Host", HOST), ("User-Agent", "sigv4-vector/1.0"), ("X-Custom", "keep-me")],
    )

    # Two lines of one header name, in the order they arrived.
    sign(
        "header-duplicate",
        "GET",
        "/",
        None,
        [("Host", HOST), ("X-Dupe", "b"), ("X-Dupe", "a")],
    )

    # An empty value and a bare name are both `key=`.
    sign(
        "empty-query-parameter",
        "GET",
        "/",
        [("a", "1"), ("empty", ""), ("flag", "")],
        [("Host", HOST)],
    )

    # A literal percent in the object key, escaped once on the wire and once
    # again in the canonical URI.
    sign("double-encoded-path", "GET", "/a%25b", None, [("Host", HOST)], service="s3")

    # A token from STS: botocore adds the header and signs it, and the caller
    # never holds a second copy of it.
    sign("session-token", "GET", "/", None, [("Host", HOST)], token=TOKEN)

    print(f"botocore {botocore.__version__}")
    print(f"wrote {len(os.listdir(OUT_ROOT))} cases to {OUT_ROOT}")


if __name__ == "__main__":
    sys.exit(main())
