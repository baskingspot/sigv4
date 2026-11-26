//! The signing key, the string to sign, and the Authorization field value.
//!
//! The key is the HMAC chain the specification names: `AWS4` + secret over the
//! date, then the region, then the service, then `aws4_request`. Nothing here
//! reads a clock or a file: the timestamp is a caller-supplied string in the
//! form `20150830T123600Z`.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Writer = std.Io.Writer;
const testing = std.testing;
const ascii = std.ascii;

const canonical = @import("canonical.zig");

/// The algorithm named in the string to sign and the Authorization field.
/// SigV4a uses another one.
pub const algorithm = "AWS4-HMAC-SHA256";

/// The header a session token is signed under.
pub const session_token_header = "x-amz-security-token";

const scope_terminator = "aws4_request";

const whitespace = " \t\n\r\x0b\x0c";

/// Everything a signature needs that is not the request.
pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8,
    service: []const u8,
    /// The request time, `YYYYMMDDTHHMMSSZ`. The date half is the scope date.
    timestamp: []const u8,
    /// A token from STS, signed as `x-amz-security-token`. The caller still
    /// sends the header; this only puts it in the signature.
    session_token: ?[]const u8 = null,
};

/// What a signing call can refuse: a buffer that was too small, a request
/// without `host`, a payload hash that is not a hash, a timestamp that is not
/// `YYYYMMDDTHHMMSSZ` or not the one in the request, a session token that the
/// header list already carries, or an S3 service that does not use the S3 path
/// mode or does not sign its content hash.
pub const SignError = error{
    CreqTooSmall,
    OutTooSmall,
    MissingHost,
    InvalidPayloadHash,
    InvalidTimestamp,
    DuplicateSessionToken,
    TimestampMismatch,
    PathModeMismatch,
    ContentSha256Mismatch,
};

/// The credential scope, `date/region/service/aws4_request`, with the date
/// taken from the timestamp so the two cannot disagree.
pub const Scope = struct {
    date: [8]u8,
    region: []const u8,
    service: []const u8,

    /// Copies the date out of the timestamp, so the scope and the signature
    /// cannot disagree about the day. The other two parts are borrowed.
    pub fn init(timestamp: []const u8, region: []const u8, service: []const u8) SignError!Scope {
        if (!validTimestamp(timestamp)) return error.InvalidTimestamp;
        return .{
            .date = timestamp[0..8].*,
            .region = region,
            .service = service,
        };
    }
};

/// Writes the credential scope: the date, the region, the service, and the
/// terminator, slash separated.
pub fn writeScope(out: []u8, scope: Scope) canonical.WriteError![]const u8 {
    var w: Writer = .fixed(out);
    writeScopeTo(&w, scope) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the string to sign over a finished canonical request hash.
pub fn writeStringToSign(
    out: []u8,
    timestamp: []const u8,
    scope: Scope,
    canonical_request_hash: [32]u8,
) canonical.WriteError![]const u8 {
    var w: Writer = .fixed(out);
    writeStringToSignTo(
        &w,
        timestamp,
        scope,
        canonical_request_hash,
    ) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// The HMAC chain: `kDate` over `AWS4` + secret, then `kRegion`, then
/// `kService`, then `kSigning` over the scope terminator. The result signs the
/// string to sign.
pub fn signingKey(secret_key: []const u8, scope: Scope) [32]u8 {
    var hmac = secretKeyHmac(secret_key);
    defer zero(mem.asBytes(&hmac));

    var date_key: [32]u8 = undefined;
    hmac.update(&scope.date);
    hmac.final(&date_key);
    defer zero(&date_key);

    hmac = HmacSha256.init(&date_key);
    var region_key: [32]u8 = undefined;
    hmac.update(scope.region);
    hmac.final(&region_key);
    defer zero(&region_key);

    hmac = HmacSha256.init(&region_key);
    var service_key: [32]u8 = undefined;
    hmac.update(scope.service);
    hmac.final(&service_key);
    defer zero(&service_key);

    hmac = HmacSha256.init(&service_key);
    var signing_key: [32]u8 = undefined;
    hmac.update(scope_terminator);
    hmac.final(&signing_key);
    return signing_key;
}

/// HMAC-SHA256 of the string to sign under a key from `signingKey`.
pub fn signature(key: [32]u8, string_to_sign: []const u8) [32]u8 {
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, string_to_sign, &key);
    return mac;
}

/// Writes the value of the `Authorization` field, signing the request the way
/// `canonical.writeRequest` does. `creq` is scratch for the canonical request
/// and holds no result the caller asked for; size it like the canonical
/// request, a few KiB for a normal request.
///
/// The request must carry `host` and either an `x-amz-date` equal to
/// `credentials.timestamp` or a `Date` header. A signature AWS will reject is
/// not the caller's to make. An S3 service must use `PathMode.s3` and must
/// sign `x-amz-content-sha256` with the payload hash.
pub fn writeAuthorization(
    out: []u8,
    creq: []u8,
    request: canonical.Request,
    credentials: Credentials,
) SignError![]const u8 {
    const scope: Scope = try .init(credentials.timestamp, credentials.region, credentials.service);
    const extra: ?canonical.Header = if (credentials.session_token) |token|
        .{ .name = session_token_header, .value = token }
    else
        null;
    if (extra != null and canonical.contains(request.headers, session_token_header)) {
        return error.DuplicateSessionToken;
    }
    try checkTimestamp(request.headers, credentials.timestamp);
    try checkS3(request, credentials);

    const canonical_request = canonical.writeRequestWith(
        creq,
        request,
        extra,
    ) catch |err| return switch (err) {
        error.NoSpaceLeft => error.CreqTooSmall,
        else => |other| other,
    };
    var digest: [32]u8 = undefined;
    Sha256.hash(canonical_request, &digest, .{});

    var key = signingKey(credentials.secret_key, scope);
    defer zero(&key);
    var sink: Writer.Hashing(HmacSha256) = .initHasher(HmacSha256.init(&key), &.{});
    defer zero(mem.asBytes(&sink));
    writeStringToSignTo(
        &sink.writer,
        credentials.timestamp,
        scope,
        digest,
    ) catch unreachable; // The hashing writer has no sink to fill, so it cannot fail.
    var mac: [32]u8 = undefined;
    sink.hasher.final(&mac);

    var w: Writer = .fixed(out);
    writeField(&w, request.headers, extra, credentials, scope, mac) catch return error.OutTooSmall;
    return w.buffered();
}

fn writeScopeTo(w: *Writer, scope: Scope) Writer.Error!void {
    try w.writeAll(&scope.date);
    try w.writeByte('/');
    try w.writeAll(scope.region);
    try w.writeByte('/');
    try w.writeAll(scope.service);
    try w.writeByte('/');
    try w.writeAll(scope_terminator);
}

fn writeStringToSignTo(
    w: *Writer,
    timestamp: []const u8,
    scope: Scope,
    canonical_request_hash: [32]u8,
) Writer.Error!void {
    const hex: [64]u8 = std.fmt.bytesToHex(canonical_request_hash, .lower);
    try w.writeAll(algorithm);
    try w.writeByte('\n');
    try w.writeAll(timestamp);
    try w.writeByte('\n');
    try writeScopeTo(w, scope);
    try w.writeByte('\n');
    try w.writeAll(&hex);
}

/// `headers` is already sorted by the canonical request written just before
/// this, and the token merge is the same one.
fn writeField(
    w: *Writer,
    headers: []const canonical.Header,
    extra: ?canonical.Header,
    credentials: Credentials,
    scope: Scope,
    mac: [32]u8,
) Writer.Error!void {
    try w.writeAll(algorithm);
    try w.writeAll(" Credential=");
    try w.writeAll(credentials.access_key);
    try w.writeByte('/');
    try writeScopeTo(w, scope);
    try w.writeAll(", SignedHeaders=");
    try canonical.writeNamesInto(w, headers, extra);
    try w.writeAll(", Signature=");
    const hex: [64]u8 = std.fmt.bytesToHex(mac, .lower);
    try w.writeAll(&hex);
}

/// HMAC keyed with `AWS4` + secret. A secret that does not fit one hash block
/// is hashed first, which is what HMAC does with a long key, so no secret has
/// to be copied into a buffer with a size limit. The key material is zeroed
/// before the function returns, the way `signingKey` zeroes the intermediates.
fn secretKeyHmac(secret_key: []const u8) HmacSha256 {
    if (secret_key.len + 4 <= Sha256.block_length) {
        var key: [Sha256.block_length]u8 = undefined;
        defer zero(&key);
        @memcpy(key[0..4], "AWS4");
        @memcpy(key[4..][0..secret_key.len], secret_key);
        return HmacSha256.init(key[0 .. 4 + secret_key.len]);
    }
    var hasher = Sha256.init(.{});
    hasher.update("AWS4");
    hasher.update(secret_key);
    var digest: [32]u8 = undefined;
    defer zero(&digest);
    hasher.final(&digest);
    return HmacSha256.init(&digest);
}

inline fn zero(bytes: []u8) void {
    crypto.secureZero(u8, bytes);
}

/// S3 rejects a signature over a service path that was escaped twice, and one
/// that leaves out the content hash. Both are contradictions the library can
/// see, so it refuses them here instead of letting AWS answer
/// SignatureDoesNotMatch.
fn checkS3(request: canonical.Request, credentials: Credentials) SignError!void {
    if (!mem.startsWith(u8, credentials.service, "s3")) return;
    if (request.path_mode != .s3) return error.PathModeMismatch;
    const value = canonical.find(request.headers, "x-amz-content-sha256") orelse
        return error.ContentSha256Mismatch;
    const trimmed = mem.trim(u8, value, whitespace);
    if (!mem.eql(u8, trimmed, request.payload_hash)) return error.ContentSha256Mismatch;
}

fn checkTimestamp(headers: []const canonical.Header, timestamp: []const u8) SignError!void {
    if (canonical.find(headers, "x-amz-date")) |value| {
        const trimmed = mem.trim(u8, value, whitespace);
        if (!mem.eql(u8, trimmed, timestamp)) return error.TimestampMismatch;
        return;
    }
    if (canonical.contains(headers, "date")) return;
    return error.TimestampMismatch;
}

fn validTimestamp(timestamp: []const u8) bool {
    if (timestamp.len != 16) return false;
    for (timestamp[0..8]) |byte| {
        if (!ascii.isDigit(byte)) return false;
    }
    for (timestamp[9..15]) |byte| {
        if (!ascii.isDigit(byte)) return false;
    }
    return timestamp[8] == 'T' and timestamp[15] == 'Z';
}

test "the scope date comes from the timestamp" {
    const scope: Scope = try .init("20150830T123600Z", "us-east-1", "service");
    try testing.expectEqualStrings("20150830", &scope.date);

    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "20150830/us-east-1/service/aws4_request",
        try writeScope(&buffer, scope),
    );
}

test "a timestamp that is not the basic ISO form is refused" {
    try testing.expectError(error.InvalidTimestamp, Scope.init("2015-08-30T12:36:00Z", "r", "s"));
    try testing.expectError(error.InvalidTimestamp, Scope.init("20150830T1236Z", "r", "s"));
    try testing.expectError(error.InvalidTimestamp, Scope.init("20150830X123600Z", "r", "s"));
    try testing.expectError(error.InvalidTimestamp, Scope.init("20150830T123600Y", "r", "s"));
}

test "the signing key is the documented chain" {
    // The worked example in the AWS documentation: the IAM ListUsers request
    // of 20150830T123600Z.
    const scope: Scope = try .init("20150830T123600Z", "us-east-1", "iam");
    const key = signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", scope);
    try testing.expectEqualStrings(
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
        &std.fmt.bytesToHex(key, .lower),
    );
}

test "a secret longer than one hash block still signs" {
    // Two example secrets, 80 bytes, which is longer than SHA-256's 64-byte
    // block. HMAC hashes such a key first, and so does the helper here. The
    // value is what botocore 1.43.79 derives for the same inputs.
    const long: []const u8 =
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" ++
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const scope: Scope = try .init("20150830T123600Z", "us-east-1", "iam");
    try testing.expectEqualStrings(
        "ebb29ad5a9a9c048c0c40f2b16feabaa95d61580e1211918763b6710d9245b01",
        &std.fmt.bytesToHex(signingKey(long, scope), .lower),
    );
}

test "the convenience equals the hand-composed field" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    const credentials: Credentials = .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20260826T000000Z",
    };
    const request: canonical.Request = .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    };

    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    const value = try writeAuthorization(&field, &creq, request, credentials);

    const scope: Scope = try .init(credentials.timestamp, credentials.region, credentials.service);
    var hand_creq: [1024]u8 = undefined;
    const hand_canonical = try canonical.writeRequest(&hand_creq, request);
    var digest: [32]u8 = undefined;
    Sha256.hash(hand_canonical, &digest, .{});

    var sts: [512]u8 = undefined;
    const hand_sts = try writeStringToSign(&sts, credentials.timestamp, scope, digest);
    const mac = signature(signingKey(credentials.secret_key, scope), hand_sts);

    var names: [128]u8 = undefined;
    const signed = try canonical.writeNames(&names, &headers, null);
    var scope_text: [128]u8 = undefined;

    var expected: [512]u8 = undefined;
    var w: Writer = .fixed(&expected);
    try w.print("{s} Credential={s}/{s}, SignedHeaders={s}, Signature={s}", .{
        algorithm,
        credentials.access_key,
        try writeScope(&scope_text, scope),
        signed,
        &std.fmt.bytesToHex(mac, .lower),
    });

    // The whole convenience is the four primitives in a row, with no path of
    // its own through the format.
    try testing.expectEqualStrings(hand_canonical, creq[0..hand_canonical.len]);
    try testing.expectEqualStrings(w.buffered(), value);
}

test "a session token signs the same whether it is listed or injected" {
    const token = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4F";
    var injected_headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var listed_headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
        .{ .name = session_token_header, .value = token },
    };
    const base: Credentials = .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20260826T000000Z",
    };

    var injected_field: [1024]u8 = undefined;
    var injected_creq: [1024]u8 = undefined;
    const injected = try writeAuthorization(&injected_field, &injected_creq, .{
        .method = "GET",
        .path = "/",
        .headers = &injected_headers,
        .payload_hash = canonical.empty_payload_hash,
    }, .{
        .access_key = base.access_key,
        .secret_key = base.secret_key,
        .region = base.region,
        .service = base.service,
        .timestamp = base.timestamp,
        .session_token = token,
    });

    var listed_field: [1024]u8 = undefined;
    var listed_creq: [1024]u8 = undefined;
    const listed = try writeAuthorization(&listed_field, &listed_creq, .{
        .method = "GET",
        .path = "/",
        .headers = &listed_headers,
        .payload_hash = canonical.empty_payload_hash,
    }, base);

    try testing.expectEqualStrings(listed, injected);
}

test "a token in both the headers and the credentials is refused" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = session_token_header, .value = "a" },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    try testing.expectError(error.DuplicateSessionToken, writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20260826T000000Z",
        .session_token = "b",
    }));
}

test "a buffer that is too small is refused" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var small: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, canonical.writeRequest(&small, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    }));
}

test "a Date header stands in for x-amz-date" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "date", .value = "Sun, 30 Aug 2015 12:36:00 GMT" },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    const value = try writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20150830T123600Z",
    });
    try testing.expect(mem.find(u8, value, "SignedHeaders=date;host") != null);
}

test "a request with no date at all is refused" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    try testing.expectError(error.TimestampMismatch, writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20150830T123600Z",
    }));
}

test "a short buffer names which one is short" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20150830T123600Z" },
    };
    const request: canonical.Request = .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    };
    const credentials: Credentials = .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20150830T123600Z",
    };
    var field: [512]u8 = undefined;
    var small: [8]u8 = undefined;
    try testing.expectError(
        error.CreqTooSmall,
        writeAuthorization(&field, &small, request, credentials),
    );

    var tiny: [8]u8 = undefined;
    var creq: [1024]u8 = undefined;
    try testing.expectError(
        error.OutTooSmall,
        writeAuthorization(&tiny, &creq, request, credentials),
    );
}

test "an S3 service must use the S3 path mode" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
        .{ .name = "x-amz-content-sha256", .value = canonical.empty_payload_hash },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    try testing.expectError(error.PathModeMismatch, writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
    }));
}

test "an S3 request must sign the content hash it carries" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    const credentials: Credentials = .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
    };
    const request: canonical.Request = .{
        .method = "GET",
        .path = "/",
        .path_mode = .s3,
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    };
    try testing.expectError(
        error.ContentSha256Mismatch,
        writeAuthorization(&field, &creq, request, credentials),
    );

    var wrong = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
        .{ .name = "x-amz-content-sha256", .value = "UNSIGNED-PAYLOAD" },
    };
    var other = request;
    other.headers = &wrong;
    try testing.expectError(
        error.ContentSha256Mismatch,
        writeAuthorization(&field, &creq, other, credentials),
    );
}

test "an s3express service takes the same guard" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    try testing.expectError(error.PathModeMismatch, writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = canonical.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3express",
        .timestamp = "20260826T000000Z",
    }));
}
