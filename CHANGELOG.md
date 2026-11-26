# Changelog

All notable changes to sigv4 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `canonical.writeRequest` builds the canonical request from a method, a wire path, query pairs, a header slice, and a payload hash. `path_mode` picks `.service` (normalize and escape again), `.unnormalized` (escape only), or `.s3` (the wire path is the canonical URI).
- `canonical.writeUri`, `writeQuery`, `writeHeaders`, and `writeNames` write one part each, `find` and `contains` look up a header, and `writeRequestWith` signs a header that is not in the slice.
- `canonical.writeRequest` returns `error.MissingHost` when `host` is absent and `error.InvalidPayloadHash` when the payload hash is not 64 lowercase hex, `UNSIGNED-PAYLOAD`, or a `STREAMING-` form.
- `signing.signingKey` derives `kDate`, `kRegion`, `kService`, and `kSigning` and zeroes the key material before it returns. `signing.writeScope` and `writeStringToSign` write the two credential strings, and `signing.signature` is the HMAC over the string to sign.
- `signing.writeAuthorization` writes the `Authorization` field value. It returns `error.TimestampMismatch` when the request has no `x-amz-date` equal to the timestamp and no `Date` header, `error.DuplicateSessionToken` when the header slice already carries the token, and `error.CreqTooSmall` or `error.OutTooSmall` when one of its two buffers is short.
- `sigv4.empty_payload_hash` is the hex SHA-256 of an empty body.
