+++
title = "sigv4"
+++

AWS Signature Version 4 request signing in Zig: the canonical request, the
string to sign, and the HMAC-SHA256 signing key, with no I/O.

Every AWS API from Zig signs its requests first. AWS Signature Version 4 is
four strings and a chain of HMACs. The chain is mechanical; the strings are
where implementations fail: headers that sort case-folded and join their
duplicates, a query string that encodes after it decodes, a path escaped a
second time, a scope date that has to agree with the timestamp.

The library is two namespaces over caller-owned buffers. `canonical` builds the
text the signature covers, and `signing` derives the key chain and writes the
`Authorization` field. No allocator, no clock, no credentials store, no HTTP
client: the timestamp is a string you supply.

- [The canonical request](#the-canonical-request): `canonical.writeRequest` writes the method, the URI, the query, the headers, the signed names, and the payload hash into one buffer, sorting the header and query slices in place.
- [The key chain](#the-key-chain): `signing.signingKey` runs `kDate` to `kRegion` to `kService` to `kSigning`, and `signing.Scope` takes its date from the timestamp.
- [Signing a request](#signing-a-request): `signing.writeStringToSign` and `signing.signature` are the two stages below `signing.writeAuthorization`, which writes the field value and signs a session token.
- [Limits](#limits): presigning, streaming signatures, retries, and SigV4a are not here.

The API reference is the doc comments in `src/`, one for every public symbol.

# Getting started

## Install

```sh
zig fetch --save git+https://github.com/baskingspot/sigv4
```

Then in `build.zig`:

```zig
const sigv4 = b.dependency("sigv4", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("sigv4", sigv4.module("sigv4"));
```

## Import it

```zig
const sigv4 = @import("sigv4");
```

`sigv4` is its own namespace. Nothing in `std` shares the name, so there is no
binding to rename.

## Read the examples

[`docs/examples/root.zig`](https://github.com/baskingspot/sigv4/blob/main/docs/examples/root.zig)
is the code this guide shows, compiled against the public module and run by
`just test`. The same run executes the AWS signing test suite in
`tests/aws-signing-test-suite/` and the reference vectors in `tests/vectors/`:
every case checks the canonical request, the string to sign, the signature, and
the `Authorization` value.

# The canonical request

The canonical request is six newline-separated parts: the method, the URI, the
query, the headers, the signed names, and the payload hash.
`canonical.writeRequest` lays them out in one call:

```zig
var headers = [_]sigv4.canonical.Header{
    .{ .name = "host", .value = "example.amazonaws.com" },
    .{ .name = "x-amz-date", .value = "20260826T000000Z" },
};
var buffer: [2048]u8 = undefined;

const canonical = try sigv4.canonical.writeRequest(&buffer, .{
    .method = "GET",
    .path = "/",
    .headers = &headers,
    .payload_hash = sigv4.empty_payload_hash,
});
```

It returns a slice of the buffer it was given. If the buffer was too small, it
returns `error.NoSpaceLeft` and no partial output.

## The method and the target

`Request.method` and `Request.path` are the request line. `path` takes the
path's bytes, not its wire text: the canonical URI is encoded from them, every
byte outside the unreserved set becomes uppercase `%XX`, and `/` stays literal.

Pass the decoded path. A path that arrives already percent-encoded is encoded a
second time, `%25` to `%2525`, and a caller that hands over wire text should
expect that.

`Request.normalize_path` removes `.`, `..`, and empty segments. Every service
but S3 signs the normalized path, so set it false for S3.

```zig
var buffer: [64]u8 = undefined;
try sigv4.canonical.writeUri(&buffer, "/example/..", true); // "/"
```

## The headers

`Request.headers` holds the headers you sign and nothing else. A header the
request sends but the signature does not cover stays out of the slice; the
request still sends it.

The slice is sorted in place by case-folded name. Duplicate names are one line
with the values comma-joined in arrival order, values are trimmed, and runs of
spaces and tabs collapse to one space. The values are written once; the names
are walked again to build the `SignedHeaders` line and nothing else.

For a header signature, `host` and `x-amz-date` must be in the list. The
library never adds them: a header that is signed and not sent, or sent and not
signed, fails at AWS.

## The query

`Request.query` is the query string split into pairs, in wire order. Each name
and value is decoded and re-encoded, so `a%20b` and `a b` reach the same
canonical bytes. The pairs are sorted by encoded name and then by encoded
value, which is not the same as sorting the raw bytes: `.` is the smaller byte,
but it sorts after `/`, because `/` encodes to `%2F` and `%` is smaller than
`.`

```zig
var params = [_]sigv4.canonical.Param{
    .{ .name = "b", .value = "2" },
    .{ .name = "a b", .value = "" },
    .{ .name = "a", .value = "1" },
};
var buffer: [128]u8 = undefined;
try sigv4.canonical.writeQuery(&buffer, &params); // "a=1&a%20b=&b=2"
```

The caller splits the query on `&` and the first `=`. A pair with no `=` has an
empty value, and an empty value is still `key=`. The split is the caller's
because the slice has to be sorted in place and the library allocates nothing
to hold a second copy.

# The key chain

## The scope

The credential scope is `date/region/service/aws4_request`. `signing.Scope`
holds the three parts, and `Scope.init` takes the date from the timestamp, so
the two cannot disagree:

```zig
const scope = try sigv4.signing.Scope.init("20260826T000000Z", "us-east-1", "s3");
var buffer: [64]u8 = undefined;
try sigv4.signing.writeScope(&buffer, scope);
// "20260826/us-east-1/s3/aws4_request"
```

The timestamp is `YYYYMMDDTHHMMSSZ`, sixteen bytes, digits in both runs.
`Scope.init` returns `error.InvalidTimestamp` for anything else, which catches
an ISO 8601 string with dashes and colons before it becomes a signature that
does not verify.

## Derive the key

`signing.signingKey` is the four-step chain the specification names: HMAC of
the date under `AWS4` + secret, then the region, then the service, then
`aws4_request` over the scope terminator.

```zig
const secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const key = sigv4.signing.signingKey(secret_access_key, scope);
```

The secret is a slice with no length limit. A secret that does not fit one
SHA-256 block is hashed first, which is what HMAC does with a long key.

# Signing a request

## The four stages

Each stage is a public function, and the stages compose in the order the
specification lists them.

```zig
var headers = [_]sigv4.canonical.Header{
    .{ .name = "host", .value = "example.amazonaws.com" },
    .{ .name = "x-amz-date", .value = "20260826T000000Z" },
};
var creq: [2048]u8 = undefined;

const canonical = try sigv4.canonical.writeRequest(&creq, .{
    .method = "GET",
    .path = "/",
    .headers = &headers,
    .payload_hash = sigv4.empty_payload_hash,
});

var digest: [32]u8 = undefined;
std.crypto.hash.sha2.Sha256.hash(canonical, &digest, .{});

const scope = try sigv4.signing.Scope.init("20260826T000000Z", "us-east-1", "s3");
var sts_buffer: [512]u8 = undefined;
const string_to_sign = try sigv4.signing.writeStringToSign(
    &sts_buffer,
    "20260826T000000Z",
    scope,
    digest,
);

const secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const key = sigv4.signing.signingKey(secret_access_key, scope);
const mac: [32]u8 = sigv4.signing.signature(key, string_to_sign);
```

The payload hash is a string: lowercase hex SHA-256 of the body, or
`UNSIGNED-PAYLOAD`. `sigv4.empty_payload_hash` is the hex hash of an empty body,
which is what every request with no body signs. Hashing a body the caller still
owns is the caller's job, so the library never reads one.

## One call

`signing.writeAuthorization` writes the field value. It takes two buffers: the
field, and scratch for the canonical request. The scratch holds no result, so
size it like a canonical request.

```zig
var field: [512]u8 = undefined;
var creq: [2048]u8 = undefined;

const value = try sigv4.signing.writeAuthorization(&field, &creq, .{
    .method = "GET",
    .path = "/",
    .headers = &headers,
    .payload_hash = sigv4.empty_payload_hash,
}, .{
    .access_key = "AKIDEXAMPLE",
    .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    .region = "us-east-1",
    .service = "s3",
    .timestamp = "20260826T000000Z",
});
```

`value` reads
`AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260826/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=89d28d80...`.
Send it as the `Authorization` field value.

## A session token

A token from STS goes in `Credentials.session_token`. The header array has no
slot for a header the caller did not declare, so the signer merges the token
into the canonical headers itself:

```zig
const value = try sigv4.signing.writeAuthorization(&field, &creq, request, .{
    .access_key = access_key,
    .secret_key = secret_access_key,
    .region = "us-east-1",
    .service = "s3",
    .timestamp = "20260826T000000Z",
    .session_token = token,
});
```

The `x-amz-security-token` header still has to be sent, and the signer does not
send anything. A request that lists that header and also carries the token in
the credentials is refused with `error.DuplicateSessionToken`, because only one
of the two values can be the one that is signed.

To sign a header that is not in `Request.headers` for another reason, use
`canonical.writeRequestWith`, which writes the field into the canonical request
at its sorted place.

# Limits

- Presigning: `X-Amz-Signature` in a query string is not built here. `canonical.writeQuery` sorts and encodes the parameters you give it, and the `X-Amz-*` parameters are yours to set.
- Streaming signatures: nothing writes `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` or the chunk signatures below it; a body with a streaming hash arrives as a string in `Request.payload_hash`.
- SigV4a: `sigv4.algorithm` is `AWS4-HMAC-SHA256`, and the key chain for `AWS4-ECDSA-P256-SHA256` is not here.
- Retries and skew: there is no clock and no `Date` header. `Scope.init` rejects a timestamp that is not sixteen bytes in the basic form and stops there.
- Credentials: no profile, no STS call, no refresh. `signing.Credentials` holds strings.
- HTTP: no client, no request type, no header parsing. `Request` is four slices, a hash, and a flag; nothing parses a message.
