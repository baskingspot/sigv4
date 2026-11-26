# sigv4

AWS Signature Version 4 request signing in Zig: the canonical request, the
string to sign, and the HMAC-SHA256 signing key, with no I/O.

Every AWS API from Zig signs its requests first. AWS Signature Version 4 is
four strings and a chain of HMACs. The chain is mechanical; the strings are
where implementations fail: headers that sort case-folded and join their
duplicates, a query string that encodes after it decodes, a path escaped a
second time, a scope date that has to agree with the timestamp.

This package is that layer. `canonical` builds the text the signature covers
and `signing` derives the key chain and writes the `Authorization` field. There
is no allocator, no clock, no credentials store, and no HTTP client: the
timestamp is a string you supply, and every output goes into a buffer you own.

```zig
const sigv4 = @import("sigv4");

/// Writes the Authorization field value for a signed GET.
fn authorize(
    field: []u8,
    creq: []u8,
    headers: []sigv4.canonical.Header,
) sigv4.signing.SignError![]const u8 {
    return sigv4.signing.writeAuthorization(field, creq, .{
        .method = "GET",
        .path = "/",
        .headers = headers,
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
computes for it. The project is incubating: the API will move, so pin a commit.

## API

Two namespaces, `canonical` and `signing`. A function writes into a buffer the
caller owns, returns a slice of it, and returns `error.NoSpaceLeft` if the
buffer was too small. Nothing allocates.

### canonical

`canonical.Request` is the request in the terms the signature is defined over.

- `method` and `path` are the request target. `path` takes the decoded path, and the canonical URI is encoded from those bytes: every byte outside the unreserved set becomes uppercase `%XX`, and `/` stays literal. An escaped path is escaped again, `%25` to `%2525`.
- `query` is the pairs. Each name and value is percent-decoded and re-encoded, and the pairs sort by encoded name and then encoded value.
- `headers` holds the headers to sign and nothing else. Names sort case-folded, duplicates join in arrival order, values are trimmed, and runs of spaces and tabs collapse to one space. A header the request sends but does not sign stays out of the slice. `host` and `x-amz-date` must be in it.
- `payload_hash` is the lowercase hex SHA-256 of the body, or `UNSIGNED-PAYLOAD`. `sigv4.empty_payload_hash` is the hash of an empty body.
- `normalize_path` removes `.`, `..`, and empty path segments. Every service but S3 signs the normalized path, so S3 sets it false.

`canonical.writeRequest(out, request)` writes the six newline-separated parts
and sorts `headers` and `query` in place. `writeRequestWith(out, request, extra)`
adds one header that is not in the slice.

The parts are public on their own: `writeUri(out, path, normalize)`,
`writeQuery(out, params)`, `writeHeaders(out, headers, extra)`,
`writeNames(out, headers, extra)`, and `contains(headers, name)`.

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
- `signing.signingKey(secret_key, scope)` runs the four HMACs, `kDate`, `kRegion`, `kService`, and `kSigning`. A secret longer than one SHA-256 block is hashed first, as HMAC does.
- `signing.signature(key, string_to_sign)` is the MAC over the string to sign.

`signing.writeAuthorization(out, creq, request, credentials)` writes the field
value. `creq` is scratch for the canonical request and holds no result. With
`session_token` set, the token joins the signed headers as
`x-amz-security-token`, and the request still has to send that header. A
request that lists the header and also carries the token returns
`error.DuplicateSessionToken`.

## Limits

- Presigning: `X-Amz-Signature` in a query string is not built here. `canonical.writeQuery` sorts and encodes the parameters you give it.
- Streaming signatures: nothing writes `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` or the chunk signatures below it. A body with a streaming hash arrives as a string in `Request.payload_hash`.
- SigV4a: `sigv4.algorithm` is `AWS4-HMAC-SHA256`, and the chain for `AWS4-ECDSA-P256-SHA256` is not here.
- Retries and skew: no clock, no `Date` header, no backoff. `Scope.init` checks the shape of the timestamp and nothing else.
- Credentials: no profile, no STS call, no refresh. `signing.Credentials` holds strings.
- HTTP: no client, no request type, no header parsing. `Request` is four slices, a hash, and a flag; nothing parses a message.

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
canonical request, string to sign, signature, or `Authorization` field that
does not match.

## License

MIT. See [`LICENSE`](LICENSE). The AWS signing test suite in
`test/fixtures/aws-signing-suite/` is Apache-2.0, and its `LICENSE` and
`NOTICE` travel with it. See [`THIRD_PARTY.md`](THIRD_PARTY.md).

## How it's made

Built with LLM assistance. [How, in detail](https://github.com/baskingspot/.github/blob/main/docs/AI.md).

<a href="https://github.com/baskingspot"><img src="https://raw.githubusercontent.com/baskingspot/.github/main/brand/assets/badge.svg" alt="baskingspot" height="24"></a>
