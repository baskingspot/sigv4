//! AWS Signature Version 4 request signing in Zig: the canonical request, the
//! string to sign, and the HMAC-SHA256 signing key, with no I/O.
//!
//! `canonical` builds the text the signature is defined over, from a request
//! whose headers and query the caller already holds. `signing` derives the key
//! chain, the signature, and the `Authorization` field value. Both write into
//! caller-owned buffers, take no allocator, and read no clock: the timestamp
//! arrives as a string.

pub const canonical = @import("canonical.zig");
pub const signing = @import("signing.zig");

/// The algorithm both signed artefacts name. SigV4a is another algorithm.
pub const algorithm = signing.algorithm;

/// The lowercase hex SHA-256 of an empty body. Every request with no body
/// signs this string as its payload hash.
pub const empty_payload_hash = canonical.empty_payload_hash;

test {
    _ = @import("encode.zig");
    _ = canonical;
    _ = signing;
}
