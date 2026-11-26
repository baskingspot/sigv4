# sigv4

AWS Signature Version 4 request signing in Zig: the canonical request, the
string to sign, and the HMAC-SHA256 signing key, with no I/O.

Every AWS API from Zig signs its requests first. AWS Signature Version 4 is
four strings and a chain of HMACs. The chain is mechanical; the strings are
where implementations fail: headers that sort case-folded and join their
duplicates, a query string that sorts by its encoded form and not its text, a
path escaped a second time, a scope date that has to agree with the timestamp.

This package is that layer. `canonical` builds the text the signature covers
and `signing` derives the key chain, writes the `Authorization` field, and
writes the query string of a presigned URL. There is no allocator, no clock, no
credentials store, and no HTTP client: the timestamp is a string you supply, and
every output goes into a buffer you own.

```zig
const sigv4 = @import("sigv4");

/// Writes the Authorization field value for a signed S3 GET.
fn authorize(field: []u8, creq: []u8) sigv4.signing.SignError![]const u8 {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-content-sha256", .value = sigv4.empty_payload_hash },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    return sigv4.signing.writeAuthorization(field, creq, .{
        .method = "GET",
        .path = "/",
        .path_mode = .s3,
        .headers = &headers,
        .payload_hash = sigv4.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
    });
}
```

`test/examples.zig` holds that function and asserts the field value botocore
computes for it. S3 needs `x-amz-content-sha256` in the signed headers, so the
caller puts it there; the library never adds it.

The project is incubating: the API will move, so pin a commit.

## API

Two namespaces, `canonical` and `signing`. A function writes into a buffer the
caller owns and returns a slice of it. `error.NoSpaceLeft` means the buffer was
too small. Nothing allocates.

### canonical

`canonical.Request` is the request in the terms the signature is defined over.

- `method` is written in upper case, which is the form botocore signs.
- `path` is the path from the request target as it goes on the wire, and `path_mode` says how the canonical URI treats it. `.service` normalizes dot segments and escapes the wire path again, so a wire `%25` becomes `%2525`. `.unnormalized` escapes without the dot-segment pass. `.s3` takes the wire path as the canonical URI, with no normalization and no second escape. An empty path signs as `/`.
- `query` is the pairs as they go on the wire. A valid `%XX` is decoded and re-encoded, so `%7e` becomes `~` and `%2f` becomes `%2F`. Every byte outside the unreserved set becomes uppercase `%XX`, and a literal `%` must arrive as `%25`. Pairs sort by canonical name and then canonical value, and a pair with no `=` writes as `key=`.
- `headers` holds the headers to sign and nothing else. Names sort case-folded, duplicates join in arrival order, and every run of ASCII whitespace in a value collapses to one space. A header the request sends but does not sign stays out of the slice. `host` must be in it, or the call returns `error.MissingHost`.
- `payload_hash` is 64 lowercase hex characters, `UNSIGNED-PAYLOAD`, or a `STREAMING-` form. Anything else returns `error.InvalidPayloadHash`, so uppercase hex and a raw digest do not sign in silence. `sigv4.empty_payload_hash` is the hash of an empty body.

`canonical.writeRequest(out, request)` writes the six newline-separated parts
and sorts `headers` and `query` in place. `writeRequestWith(out, request, extra)`
adds one header that is not in the slice.

The parts are public on their own: `writeUri(out, path, mode)`,
`writeQuery(out, params)`, `writeHeaders(out, headers, extra)`,
`writeNames(out, headers, extra)`, `find(headers, name)`,
`contains(headers, name)`, and `validPayloadHash(hash)`. `sortQuery(params)`
and `sortHeaders(headers)` sort in place in canonical order. `writeQueryPair(w,
param)`, `writeMethodInto(w, method)`, `writeHeadersInto(w, headers, extra)`,
`writeNamesInto(w, headers, extra)`, and `writeQueryNamesInto(w, headers,
extra)` write one piece into a `std.Io.Writer` the caller already holds, which
is what `signing.presign` does with a hasher.

### signing

`signing.Credentials` holds `access_key`, `secret_key`, `region`, `service`,
`timestamp`, and an optional `session_token`. The timestamp is
`YYYYMMDDTHHMMSSZ`; nothing reads a clock.

`signing.Scope` is `date/region/service/aws4_request`. `Scope.init` copies the
date out of the timestamp so the two cannot disagree, and returns
`error.InvalidTimestamp` unless the timestamp is sixteen bytes in the basic
form.

- `signing.writeScope(out, scope)` writes the credential scope.
- `signing.writeStringToSign(out, timestamp, scope, canonical_request_hash)` writes the string to sign from the 32-byte hash.
- `signing.signingKey(secret_key, scope)` runs the four HMACs and zeroes the key material before it returns. A secret longer than one SHA-256 block is hashed first, as HMAC does.
- `signing.signature(key, string_to_sign)` is the MAC over the string to sign.

`signing.writeAuthorization(out, creq, request, credentials)` writes the field
value. `creq` is scratch for the canonical request and holds no result. The
call returns `error.CreqTooSmall` or `error.OutTooSmall` when one of the two
buffers is short, so the name says which one.

The request must carry an `x-amz-date` equal to `credentials.timestamp`, or a
`Date` header, and `error.TimestampMismatch` says when it does not. An unsigned
`x-amz-date` is not a caller's choice: AWS rejects it, so the library does too.

With `session_token` set, the token joins the signed headers as
`x-amz-security-token`, and the request still has to send that header. A
request that lists the header and also carries the token returns
`error.DuplicateSessionToken`.

S3 also requires `x-amz-content-sha256` on every header-signed request. The
caller puts it in `headers` with the body hash. For a service named `s3` or one
that starts with `s3`, `writeAuthorization` refuses a request that leaves it
out or signs another value with `error.ContentSha256Mismatch`, and refuses a
path mode other than `.s3` with `error.PathModeMismatch`.

### presigning

`signing.presign(out, request, credentials, options)` writes the query string
of a presigned URL: the caller's parameters in the order it holds them, then
`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-SignedHeaders`,
`X-Amz-Expires`, `X-Amz-Security-Token` when a token is present, and
`X-Amz-Signature` last. The signature covers the same parameters sorted, with
no signature, so a caller's parameters enter the canonical query encoded and
the URL as the wire text they arrived as.

```zig
const sigv4 = @import("sigv4");

/// Writes the query string of a presigned S3 GET.
fn presign(query: []u8) sigv4.signing.SignError![]const u8 {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    return sigv4.signing.presign(query, .{
        .method = "GET",
        .path = "/",
        .path_mode = .s3,
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
    }, .{ .expires_seconds = 3600 });
}
```

`test/examples.zig` holds that function and asserts the query botocore computes
for it.

`options.expires_seconds` is 1 to 604800; anything else returns
`error.InvalidExpires`. The credential scope is the header form's,
`date/region/service/aws4_request`, with the date taken from the timestamp.

`request.headers` is the set of headers the signature covers, exactly as it is
for the header form. Pass `host` alone for the ordinary URL, and add a header
only when the recipient must send it, because a signed header the recipient
leaves out fails the signature. `host` is required, and its absence returns
`error.MissingHost`. The `X-Amz-SignedHeaders` value names the same set.

The signature covers `request.payload_hash` as given. S3 presigning is the
exception: S3 canonicalizes `UNSIGNED-PAYLOAD` for every presigned request, so
an S3 service with any other hash returns `error.ContentSha256Mismatch`, and a
path mode other than `.s3` returns `error.PathModeMismatch`. The query form
carries no `x-amz-content-sha256` header, and none is written.

A caller parameter whose name starts with `X-Amz-` returns
`error.ReservedQueryParameter`, case-folded and after decoding, because the
presigned form owns those names.

`out` also holds the escaped canonical URI while the signature is computed: a
`..` segment removes bytes an earlier segment wrote, so the URI cannot be
streamed. Size `out` for the escaped path and the query; `error.OutTooSmall`
covers both.

## Limits

- Presigning: the headers in `Request.headers` are the ones signed, and `host`
  is required. A session token is signed when the credentials carry one;
  nothing writes a token into a URL unsigned, which is the shape the suite's
  `post-sts-header-after` records.
- Streaming signatures: nothing writes `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` or the chunk signatures below it. A body with a streaming hash arrives as a string in `Request.payload_hash`.
- SigV4a: `sigv4.algorithm` is `AWS4-HMAC-SHA256`, and the chain for `AWS4-ECDSA-P256-SHA256` is not here.
- S3 headers: the library does not add `x-amz-content-sha256`. `writeAuthorization` refuses an S3 request that leaves it out or signs a different value; `presign` writes no such header and refuses an S3 payload hash other than `UNSIGNED-PAYLOAD`.
- Retries and skew: no clock and no backoff. `Scope.init` checks the shape of the timestamp, and `writeAuthorization` checks that `x-amz-date` equals it.
- Credentials: no profile, no STS call, no refresh. `signing.Credentials` holds strings.
- HTTP: no client, no request type, no header parsing. `Request` is four slices, a hash, and a path mode; nothing parses a message.

## Install

```sh
zig fetch --save git+https://github.com/baskingspot/sigv4
```

Add the module in `build.zig`:

```zig
const sigv4 = b.dependency("sigv4", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("sigv4", sigv4.module("sigv4"));
```

`sigv4` is its own namespace; nothing in `std` shares the name. The library
builds with Zig 0.17.

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) records what moved in the API.
- [`THIRD_PARTY.md`](THIRD_PARTY.md) records where the vendored fixtures came from and their license.
- [`AGENTS.md`](AGENTS.md) has the working notes for the repository.

## Work on it

```sh
just ci
```

`nix develop` provides the toolchain. `just` lists the recipes. `just test`
runs the unit tests, the AWS signing test suite and the reference vectors under
`test/fixtures/`, and `test/examples.zig`.

The suite is vendored unmodified at the commit recorded in
[`THIRD_PARTY.md`](THIRD_PARTY.md), and the reference vectors were signed with
botocore. Every case in both roots runs: `just test` fails on the first
canonical request, string to sign, signature, `Authorization` field, or
presigned query that does not match.

## License

MIT. See [`LICENSE`](LICENSE). The AWS signing test suite in
`test/fixtures/aws-signing-suite/` is Apache-2.0, and its `LICENSE` and
`NOTICE` travel with it. See [`THIRD_PARTY.md`](THIRD_PARTY.md).

## How it's made

Built with LLM assistance. [How, in detail](https://github.com/baskingspot/.github/blob/main/docs/AI.md).

<a href="https://github.com/baskingspot"><img src="https://raw.githubusercontent.com/baskingspot/.github/main/brand/assets/badge.svg" alt="baskingspot" height="24"></a>
