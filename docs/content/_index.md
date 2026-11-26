+++
title = "sigv4"
+++

AWS Signature Version 4 in Zig: the canonical request, the string to sign, and
the HMAC-SHA256 signing key. It writes the `Authorization` field value into a
buffer you own, with no allocator, no clock, and no HTTP client.

Every request to an AWS API carries a signature over its method, path, headers,
and body hash. The algorithm is fixed and small. The failures are in the
strings: a header list that sorts case-folded and joins its duplicates, a query
that sorts by its encoded bytes, a path escaped a second time for every service
except S3, and a scope date that has to agree with the timestamp.

This package builds those strings and the key chain. It does not send
anything, store credentials, read a clock, or retry.

- [The request](#the-request): `canonical.Request` is the signature's view of a request: a method, a wire path with a `PathMode`, query pairs, the headers to sign, and a payload hash.
- [The canonical request](#the-canonical-request): `canonical.writeRequest` writes the six parts the signature covers, sorting the caller's slices in place.
- [The string to sign](#the-string-to-sign): `Scope.init` takes the date from the timestamp, and `writeStringToSign` covers the canonical request's hash.
- [The signing key](#the-signing-key): `signingKey` runs four HMACs over the secret and zeroes the intermediate keys.
- [The Authorization field](#the-authorization-field): `writeAuthorization` writes the field value, checks the timestamp, and refuses an S3 request it knows AWS will reject.
- [Presigning](#presigning): `presign` builds the `X-Amz-*` query and the signature for a URL that carries its own credentials.
- [Limits](#limits): what is deliberately not here.

The [API reference](api/) documents every public symbol.

# Getting started

## Install

```sh
zig fetch --save git+https://github.com/baskingspot/sigv4
```

Add the module in `build.zig`:

```zig
const sigv4 = b.dependency("sigv4", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("sigv4", sigv4.module("sigv4"));
```

`sigv4` builds with Zig 0.17.

## Import it

```zig
const sigv4 = @import("sigv4");
```

Two namespaces: `canonical` builds the text, `signing` derives the key and
writes the field. `sigv4.empty_payload_hash` and `sigv4.algorithm` are
re-exported at the root.

## Read the examples

[`docs/examples/root.zig`](https://github.com/baskingspot/sigv4/blob/main/docs/examples/root.zig)
is the code this guide shows, compiled against the public module and run by
`just test`. [`test/examples.zig`](https://github.com/baskingspot/sigv4/blob/main/test/examples.zig)
holds the checks that a signature matches a signer AWS ships.

# The request

`canonical.Request` is what the signature is defined over. The fields are the
request in the terms SigV4 names; the library never parses an HTTP message, so
the caller fills this in from the request it is about to send.

```zig
const sigv4 = @import("sigv4");

var headers = [_]sigv4.canonical.Header{
    .{ .name = "host", .value = "example.amazonaws.com" },
    .{ .name = "x-amz-date", .value = "20150830T123600Z" },
};

const request: sigv4.canonical.Request = .{
    .method = "GET",
    .path = "/",
    .headers = &headers,
    .payload_hash = sigv4.empty_payload_hash,
};
```

`method`, `path`, `payload_hash`, and `headers` have no defaults. `query`
defaults to empty and `path_mode` to `.service`.

## The path

`path` is the path from the request target as it goes on the wire, not a
decoded key. `path_mode` says how the canonical URI treats it.

- `.service` normalizes dot segments the way RFC 3986 section 5.2.4 does, then
  escapes the wire path again. A wire `%25` becomes `%2525`, which is what
  every service except S3 expects.
- `.unnormalized` escapes without the dot-segment pass. The AWS test suite
  ships service cases in both forms.
- `.s3` takes the wire path as the canonical URI: no normalization, no second
  escape. An object key is single-encoded on the wire, so signing it again
  would break every key with a space or a plus.

An empty path signs as `/`.

## The query

`query` is the pairs as they go on the wire. A valid `%XX` is decoded and then
re-encoded, so `%7e` and `~` are the same parameter, and `%2f` becomes `%2F`.
Every byte outside the unreserved set becomes uppercase `%XX`, and a literal
`%` must arrive as `%25`. A pair with an empty value writes as `key=`.

Pairs sort by canonical name and then canonical value, byte for byte. The sort
compares the same stream that is written, so the order and the bytes cannot
disagree.

## The headers

`headers` holds the headers to sign and nothing else. A header the request
sends but does not sign stays out of the slice; that is the only way to leave
it unsigned.

Names sort case-folded. Two lines with the same name join with a comma in the
order they arrived, which is the order the receiver sees. Every run of ASCII
whitespace in a value collapses to one space, and leading and trailing
whitespace goes, so a value cannot write a second canonical line.

`host` is required. A request without it returns `error.MissingHost` from every
builder, because AWS rejects a signature that omits it.

## The payload hash

`payload_hash` is 64 lowercase characters, `UNSIGNED-PAYLOAD`, or a
`STREAMING-` form. Anything else returns `error.InvalidPayloadHash`, so an
uppercase digest or the raw 32 bytes do not sign in silence.
`sigv4.empty_payload_hash` is the hash of an empty body.

# The canonical request

`canonical.writeRequest` writes the six newline-separated parts: the method,
the canonical URI, the canonical query, the header block, the signed-header
names, and the payload hash. The method is written in upper case.

The call sorts `request.headers` and `request.query` in place, so the slices
must be mutable and the caller sees them reordered. That is the only state a
builder needs.

`writeRequestWith` adds one header that is not in the slice. A session token
joins the signature that way, because the caller's header array has no room for
a slot it did not declare.

The parts are public when a caller needs one on its own: `writeUri(out, path,
mode)`, `writeQuery(out, params)`, `writeHeaders(out, headers, extra)`,
`writeNames(out, headers, extra)`, `find(headers, name)`, and
`contains(headers, name)`.

Every function returns a slice of the buffer it was given, and
`error.NoSpaceLeft` means that buffer was too small. Nothing is allocated, and
nothing partial is returned.

# The string to sign

The string to sign names the algorithm, the timestamp, the credential scope,
and the hash of the canonical request.

`signing.Scope` is `date/region/service/aws4_request`. `Scope.init` copies the
date out of the timestamp, so the scope and the signature cannot disagree about
the day. A timestamp that is not sixteen bytes in the basic form
`YYYYMMDDTHHMMSSZ` returns `error.InvalidTimestamp`; the shape is checked, not
the calendar, because the library has no clock.

```zig
const scope = try sigv4.signing.Scope.init("20150830T123600Z", "us-east-1", "iam");
var scope_buffer: [128]u8 = undefined;
const scope_text = try sigv4.signing.writeScope(&scope_buffer, scope);
```

`writeStringToSign(out, timestamp, scope, canonical_request_hash)` takes the
32-byte SHA-256 of the canonical request. The library does not hash it for you,
because a caller that builds the canonical request in one buffer and signs it in
two steps should not pay for a second copy. `std.crypto.hash.sha2.Sha256` is
one line.

# The signing key

The key is four HMAC-SHA256 rounds over the secret: `AWS4` + secret over the
date, then the region, then the service, then `aws4_request`. `signingKey`
returns the result and zeroes the intermediate keys and the HMAC contexts
before it returns. A secret longer than one SHA-256 block is hashed first, as
HMAC itself does.

```zig
const key = sigv4.signing.signingKey(
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    scope,
);
```

`signing.signature(key, string_to_sign)` is the MAC over the string to sign.
The two steps are separate because a caller signing many requests for one scope
derives the key once.

# The Authorization field

`signing.writeAuthorization(out, creq, request, credentials)` writes the field
value in one call. `creq` is scratch for the canonical request and holds no
result the caller asked for; size it like the canonical request, a few KiB for
a normal request. `error.CreqTooSmall` and `error.OutTooSmall` say which buffer
was short.

`signing.Credentials` holds the access key, the secret, the region, the
service, the timestamp, and an optional session token.

The request must carry an `x-amz-date` equal to `credentials.timestamp`, or a
`Date` header. `error.TimestampMismatch` says when it does not. An unsigned
`x-amz-date` is not a caller's choice: AWS rejects the signature, so the
library refuses to write one.

With `session_token` set, the token joins the signed headers as
`x-amz-security-token`, and the request still has to send that header. A
request that lists the header and also carries the token returns
`error.DuplicateSessionToken`.

S3 requires `x-amz-content-sha256` on every header-signed request. The caller
puts it in `headers` with the body hash. For a service named `s3`, or one that
starts with `s3` such as `s3express`, `writeAuthorization` refuses a request
that leaves the header out or signs a different value with
`error.ContentSha256Mismatch`, and refuses a path mode other than `.s3` with
`error.PathModeMismatch`.

`writeRequest` and the other primitives do not make those checks. They write
what they are given; the convenience refuses the two contradictions AWS will
answer with `SignatureDoesNotMatch`.

# Presigning

Presigning puts the signature in the query string, so a URL can be handed to a
process that holds no credentials. `signing.presign` writes the final query,
including `X-Amz-Signature`, into a buffer you own.

```zig
const query = try sigv4.signing.presign(&buffer, .{
    .method = "GET",
    .path = "/",
    .path_mode = .s3,
    .headers = &headers, // host alone
    .payload_hash = "UNSIGNED-PAYLOAD",
}, credentials, .{ .expires_seconds = 3600 });
```

The caller's own query parameters stay in the canonical query. Six parameters
join them: `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
`X-Amz-Expires`, `X-Amz-SignedHeaders`, and `X-Amz-Security-Token` when a
token is present. The canonical query sorts all of them; the emitted query
uses the order above and appends `X-Amz-Signature` last.

Only `host` is signed unless the caller adds more headers to the request, so
the canonical header block is smaller than a header-auth request's. A header
the recipient must send can be added; a signed header it leaves out fails the
signature.

S3 presigning requires `UNSIGNED-PAYLOAD`: S3 canonicalizes that line for every
presigned request, so an S3 service with any other hash returns
`error.ContentSha256Mismatch`, and a path mode other than `.s3` returns
`error.PathModeMismatch`. A caller parameter whose name starts with `X-Amz-`
returns `error.ReservedQueryParameter`, because the presigned form owns those
names.

`expires_seconds` must be between 1 and 604800 (`error.InvalidExpires`). AWS
caps the value and rejects a URL that outlives its credential, and the rejection
arrives in another process, later, which is why the open-ended form is not
offered. `out` holds the escaped canonical URI while the signature is computed,
so size it for the path and the query; `error.OutTooSmall` covers both.

# Limits

- **No clock.** The timestamp is a string. `Scope.init` checks its shape;
  deciding that it is the current second is the caller's job, and so is the
  clock skew allowance.
- **No HTTP.** No client, no request type, no header parsing. `Request` is
  slices, a hash, and a path mode. Folding a multi-line header field is the
  parser's job; this library collapses whitespace and stops there.
- **No credentials store.** No profile file, no IMDS, no STS call, no refresh.
  `Credentials` holds strings that live at least as long as the call.
- **No retries.** A refused request is the caller's to retry, with the backoff
  and the clock the AWS API asks for.
- **SigV4a is not here.** `sigv4.algorithm` is `AWS4-HMAC-SHA256`. The
  `AWS4-ECDSA-P256-SHA256` chain needs a signing curve and a different key
  format.
- **Streaming signatures are not here.** A body with a streaming hash arrives
  as a string in `Request.payload_hash`; nothing writes the chunk chain below
  it.
- **A `+` in a query stays a plus.** The signer canonicalizes the bytes it is
  given and AWS canonicalizes the bytes it receives. A query encoder that
  writes a raw `+` where the receiver reads a space will sign a different
  string than the one on the wire. Encode it as `%2B`.
- **The signed-header order is asserted in debug builds.** `writeNames` and the
  builders sort for you; a caller that writes the names by hand gets an
  assertion in Debug and a wrong field in ReleaseFast.
