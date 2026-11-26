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
var headers = [_]sigv4.canonical.Header{
    .{ .name = "host", .value = "example.amazonaws.com" },
    .{ .name = "x-amz-date", .value = "20260826T000000Z" },
};
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

The project is incubating. The API will move, so pin a commit.

## What is in it

- [The canonical request](docs/content/_index.md#the-canonical-request): `canonical.writeRequest` writes the method, the URI, the query, the headers, the signed names, and the payload hash into one buffer, sorting the header and query slices in place.
- [The key chain](docs/content/_index.md#the-key-chain): `signing.signingKey` runs `kDate` to `kRegion` to `kService` to `kSigning` from `AWS4` and the secret, and `signing.Scope` takes its date from the timestamp so the two cannot disagree.
- [Signing a request](docs/content/_index.md#signing-a-request): `signing.writeStringToSign` and `signing.signature` are the two stages below `signing.writeAuthorization`, which writes the field value and signs an `x-amz-security-token` that the header array has no slot for.

Not implemented:

- Presigned URLs: `writeQuery` sorts and encodes the parameters you give it, and nothing adds `X-Amz-Signature`.
- Streaming signatures: `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and the chunk signatures below it are absent.
- Retries: no clock, no skew correction, no backoff. `Scope.init` rejects a timestamp that is not `YYYYMMDDTHHMMSSZ` and stops there.
- Credentials: no profile, no STS call, no refresh. `signing.Credentials` holds strings.
- SigV4a: one algorithm, `AWS4-HMAC-SHA256`.

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

- The [guide](docs/content/_index.md) shows each stage with the code, and says which function to reach for.
- [`CHANGELOG.md`](CHANGELOG.md) records what moved in the API.
- [`THIRD_PARTY.md`](THIRD_PARTY.md) records where the vendored fixtures came from and their license.
- [`AGENTS.md`](AGENTS.md) has the working notes for the repository.

## Work on it

```sh
just ci
```

`nix develop` provides the toolchain. `just` lists the recipes. `just test`
runs the unit tests, the AWS signing test suite in `tests/`, and the guide's
examples. `just lint` runs ziglint, `zig fmt --check`, and the rest of the
house checks.

The official suite is vendored at the commit recorded in
[`THIRD_PARTY.md`](THIRD_PARTY.md), and the reference vectors in
`tests/vectors/` were signed with botocore. Every case in both roots runs:
`just test` fails on the first canonical request, string to sign, signature, or
`Authorization` field that does not match.

## License

MIT. See [`LICENSE`](LICENSE). The AWS signing test suite in
`tests/aws-signing-test-suite/` is Apache-2.0, and its `LICENSE` and `NOTICE`
travel with it. See [`THIRD_PARTY.md`](THIRD_PARTY.md).

## How it's made

Built with LLM assistance. [How, in detail](https://github.com/baskingspot/.github/blob/main/docs/AI.md).

<a href="https://github.com/baskingspot"><img src="https://raw.githubusercontent.com/baskingspot/.github/main/brand/assets/badge.svg" alt="baskingspot" height="24"></a>
