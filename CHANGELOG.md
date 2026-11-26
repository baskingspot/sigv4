# Changelog

All notable changes to sigv4 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `canonical.writeRequest` builds the canonical request from a method, path, query pairs, a header slice, and a payload hash. `canonical.writeUri`, `writeQuery`, `writeHeaders`, and `writeNames` write one part each, and `writeRequestWith` signs a header that is not in the slice.
- `signing.signingKey` derives `kDate`, `kRegion`, `kService`, and `kSigning`, `signing.writeScope` and `writeStringToSign` write the two credential strings, and `signing.signature` is the HMAC over the string to sign.
- `signing.writeAuthorization` writes the `Authorization` field value. With `Credentials.session_token` set it signs `x-amz-security-token` too, and returns `error.DuplicateSessionToken` if the header slice already carries that header.
- `sigv4.empty_payload_hash` is the hex SHA-256 of an empty body.
