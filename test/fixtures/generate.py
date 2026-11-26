#!/usr/bin/env python3
"""Write the reference vectors the official suite does not cover.

The official suite (test/fixtures/aws-signing-suite) has no case for a header the
signer sees but must not sign, duplicate header lines, an empty query
parameter, a path that needs a second escape, a session token handed to the
signer out of band, or an S3 presigned URL. This script signs one of each with
botocore, the signer AWS ships in its own Python SDK, and writes the result in
the suite's file layout so `test/suite.zig` runs both roots with the same code.

Run it from the repository root, with botocore on the interpreter:

    nix shell --impure --expr \
      'with import (builtins.getFlake "nixpkgs") {}; python3.withPackages (ps: [ ps.botocore ])' \
      -c python3 test/fixtures/generate.py

The vectors are checked in. Regenerate them only when the shapes change, and
record the botocore version in test/fixtures/README.md when they do.
"""

import datetime
import json
import os
import sys
from unittest import mock

import botocore
from botocore.auth import S3SigV4Auth, S3SigV4QueryAuth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.session import Session
from botocore.signers import RequestSigner

ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TIMESTAMP = "20150830T123600Z"
HOST = "example.amazonaws.com"
REGION = "us-east-1"
TOKEN = "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267"
EXPIRES = 3600

OUT_ROOT = os.path.join(os.path.dirname(__file__), "vectors", "v4")


def sign(case, method, path, params, headers, region=REGION, service="service", token=None, s3=False, wire=None):
    """Sign one request with botocore and write the suite's files.

    `headers` are the (name, value) pairs the caller sends, in order, and a
    repeated name is a second line. botocore adds X-Amz-Date, the session token
    when it is passed as a credential, and the Authorization field; the files
    record the request as sent and the three stages of the signature.

    `path` is the wire path. The S3 signer adds X-Amz-Content-SHA256 and leaves
    the path alone; the generic signer normalizes and escapes it again. The
    context records which signer ran, so the Zig runner uses the same path
    mode.
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

    signer_type = S3SigV4Auth if s3 else SigV4Auth
    signer = signer_type(Credentials(ACCESS_KEY, SECRET_KEY, token), service, region)
    signer._modify_request_before_signing(request)
    canonical_request = signer.canonical_request(request)
    string_to_sign = signer.string_to_sign(request, canonical_request)
    signature = signer.signature(string_to_sign, request)
    signer._inject_signature_to_request(request, signature)

    directory = os.path.join(OUT_ROOT, case)
    os.makedirs(directory, exist_ok=True)

    target = path if not params else f"{path}?{wire_query(params)}"
    if wire is not None:
        target = f"{path}?{wire}"

    signed_lines = [f"{method} {target} HTTP/1.1"]
    signed_lines.extend(
        f"{name}:{value}"
        for name, value in request.headers.items()
        if name.lower() != "authorization"
    )
    signed_lines.append(f"Authorization:{request.headers['Authorization']}")
    signed_text = "\n".join(signed_lines) + "\n"

    write(directory, "request.txt", request_text(method, target, headers))
    write(directory, "context.json", context(region, service, token, s3))
    write(directory, "header-canonical-request.txt", canonical_request)
    write(directory, "header-string-to-sign.txt", string_to_sign)
    write(directory, "header-signature.txt", signature)
    write(directory, "header-signed-request.txt", signed_text)


def presign_case(case, path, token=None, expires=EXPIRES):
    """Write one presigned S3 case: the query form only.

    `generate_presigned_url` is the call a botocore user makes. It picks the S3
    query signer, which leaves the canonical URI as the wire path, signs
    `UNSIGNED-PAYLOAD`, and puts the session token in the query. The same
    signer driven step by step gives the canonical request, the string to sign,
    and the signature the suite records; the two URLs must agree, or the files
    would describe a request botocore does not make.

    There is no header form: `S3SigV4Auth` signs the body hash unless the
    request carries a checksum header, so the same request cannot be written
    with `UNSIGNED-PAYLOAD` on its own.
    """
    credentials = Credentials(ACCESS_KEY, SECRET_KEY, token)
    session = Session()
    model = session.get_service_model("s3")
    request_dict = {
        "url": f"https://{HOST}{path}",
        "method": "GET",
        "headers": {"Host": HOST},
        "body": b"",
        "context": {},
    }

    # `generate_presigned_url` reads the clock, and a fixture cannot.
    frozen = datetime.datetime.strptime(TIMESTAMP, "%Y%m%dT%H%M%SZ")
    signer = RequestSigner(
        model.service_id,
        REGION,
        "s3",
        "s3v4",
        credentials,
        session.get_component("event_emitter"),
    )
    with mock.patch("botocore.auth.get_current_datetime", return_value=frozen):
        url = signer.generate_presigned_url(
            request_dict, operation_name="GetObject", expires_in=expires, region_name=REGION
        )

    request = AWSRequest(method="GET", url=f"https://{HOST}{path}", data=None)
    request.headers.add_header("Host", HOST)
    request.context["timestamp"] = TIMESTAMP
    query_auth = S3SigV4QueryAuth(credentials, "s3", REGION, expires=expires)
    query_auth._modify_request_before_signing(request)
    canonical_request = query_auth.canonical_request(request)
    string_to_sign = query_auth.string_to_sign(request, canonical_request)
    signature = query_auth.signature(string_to_sign, request)
    query_auth._inject_signature_to_request(request, signature)
    assert request.url == url, (request.url, url)

    directory = os.path.join(OUT_ROOT, case)
    os.makedirs(directory, exist_ok=True)
    target = url.split(f"https://{HOST}", 1)[1]
    signed_lines = [f"GET {target} HTTP/1.1", f"Host:{HOST}"]
    write(directory, "request.txt", request_text("GET", path, [("Host", HOST)]))
    write(
        directory,
        "context.json",
        context(REGION, "s3", token, s3=True, payload_hash="UNSIGNED-PAYLOAD"),
    )
    write(directory, "query-canonical-request.txt", canonical_request)
    write(directory, "query-string-to-sign.txt", string_to_sign)
    write(directory, "query-signature.txt", signature)
    write(directory, "query-signed-request.txt", "\n".join(signed_lines) + "\n")


def request_text(method, target, headers):
    lines = [f"{method} {target} HTTP/1.1"]
    lines.extend(f"{name}:{value}" for name, value in headers)
    return "\n".join(lines) + "\n\n"


def context(region, service, token=None, s3=False, payload_hash=None):
    context = {
        "credentials": {
            "access_key_id": ACCESS_KEY,
            "secret_access_key": SECRET_KEY,
        },
        "expiration_in_seconds": EXPIRES,
        "normalize": True,
        "region": region,
        "service": service,
        "sign_body": False,
        "timestamp": "2015-08-30T12:36:00Z",
    }
    if token is not None:
        context["credentials"]["token"] = TOKEN
    if s3:
        context["path_mode"] = "s3"
    if payload_hash is not None:
        context["payload_hash"] = payload_hash
    return json.dumps(context, indent=4) + "\n"


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

    # A key with no `=` at all.
    sign("bare-query-key", "GET", "/?flag", None, [("Host", HOST)])

    # Wire escapes the canonical query decodes and re-encodes: %7e is ~, %2f
    # is %2F, %41 is A, and %25 stays %25.
    sign(
        "query-wire-escapes",
        "GET",
        "/",
        [("tilde", "~"), ("slash", "/"), ("alpha", "A"), ("percent", "%")],
        [("Host", HOST)],
        wire="tilde=%7e&slash=%2f&alpha=%41&percent=%25",
    )

    # A literal percent in the path, escaped once on the wire and once again
    # by the service path mode.
    sign("service-double-encoded-path", "GET", "/a%25b", None, [("Host", HOST)])

    # An S3 key with a space, a plus, a percent, and an equals sign. The wire
    # path is the canonical URI, and S3 also requires x-amz-content-sha256.
    sign("s3-key-escapes", "GET", "/a%20b%2Bc%25d%3De", None, [("Host", HOST)], service="s3", s3=True)

    # A token from STS: botocore adds the header and signs it, and the caller
    # never holds a second copy of it.
    sign("session-token", "GET", "/", None, [("Host", HOST)], token=TOKEN)

    # An S3 GET presigned with a session token. The key holds a space, a plus,
    # a percent, and an equals sign, which the S3 signer leaves as the wire
    # path; the body is UNSIGNED-PAYLOAD, and the token is a query parameter.
    presign_case("s3-presigned-url", "/a%20b%2Bc%25d%3De", token=TOKEN)

    print(f"botocore {botocore.__version__}")
    print(f"wrote {len(os.listdir(OUT_ROOT))} cases to {OUT_ROOT}")


if __name__ == "__main__":
    sys.exit(main())
