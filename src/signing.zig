//! The signing key, the string to sign, the Authorization field value, and the
//! query string of a presigned URL.
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
const encode = @import("encode.zig");

/// The algorithm named in the string to sign and the Authorization field.
/// SigV4a uses another one.
pub const algorithm = "AWS4-HMAC-SHA256";

/// The longest a presigned URL may work: one week, the cap AWS puts on
/// `X-Amz-Expires`.
pub const max_expires_seconds: u32 = 7 * 24 * 60 * 60;

/// The header a session token is signed under.
pub const session_token_header = "x-amz-security-token";

/// The query parameter a presigned URL carries a session token in.
pub const session_token_query = "X-Amz-Security-Token";

const scope_terminator = "aws4_request";

const whitespace = " \t\n\r\x0b\x0c";

/// The prefix the presigned form owns. AWS reserves it for the parameters in
/// the query that carry the signature.
const reserved_prefix = "x-amz-";

/// Everything a signature needs that is not the request.
pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8,
    service: []const u8,
    /// The request time, `YYYYMMDDTHHMMSSZ`. The date half is the scope date.
    timestamp: []const u8,
    /// A token from STS. Header auth signs it as `x-amz-security-token`, and
    /// the caller still sends that header. `presign` writes it as
    /// `X-Amz-Security-Token` in the query instead.
    session_token: ?[]const u8 = null,
};

/// What a signing call can refuse: a buffer that was too small, a request
/// without `host`, a payload hash that is not a hash, a timestamp that is not
/// `YYYYMMDDTHHMMSSZ` or not the one in the request, a session token that the
/// header list already carries, a presigned URL that would live longer than a
/// week, a caller parameter that a reserved query name owns, or an S3 service
/// that does not use the S3 path mode or does not sign its content hash.
pub const SignError = error{
    CreqTooSmall,
    OutTooSmall,
    MissingHost,
    InvalidPayloadHash,
    InvalidTimestamp,
    InvalidExpires,
    DuplicateSessionToken,
    ReservedQueryParameter,
    TimestampMismatch,
    PathModeMismatch,
    ContentSha256Mismatch,
};

/// What a presigned URL takes besides the request and the credentials.
pub const Options = struct {
    /// How long the URL works, in seconds, from 1 to `max_expires_seconds`.
    expires_seconds: u32,
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

/// Writes the query string of a presigned URL: the caller's parameters in the
/// order it holds them, then `X-Amz-Algorithm`, `X-Amz-Credential`,
/// `X-Amz-Date`, `X-Amz-SignedHeaders`, `X-Amz-Expires`,
/// `X-Amz-Security-Token` when a token is present, and `X-Amz-Signature`
/// last.
///
/// `request.headers` is the set of headers the signature covers, as it is for
/// the header form: pass `host` alone for the ordinary presigned URL, and add
/// a header only when the recipient must send it, because a signed header the
/// recipient leaves out fails the signature. `host` is required.
///
/// `out` also holds the escaped canonical URI while the signature is computed.
/// A `..` segment removes the bytes the segment before it wrote, and a writer
/// cannot take bytes back, so the URI cannot be streamed. Size `out` for the
/// escaped path and the query.
///
/// `request.query` and `request.headers` are sorted in place, because the
/// canonical request sorts and the caller owns the buffers.
///
/// The signature covers `request.payload_hash` as given. S3 presigning requires
/// `UNSIGNED-PAYLOAD`: S3 canonicalizes that line for every presigned request,
/// and any other hash returns `error.ContentSha256Mismatch`. The query form has
/// no `x-amz-content-sha256` header, and this writes none.
pub fn presign(
    out: []u8,
    request: canonical.Request,
    credentials: Credentials,
    options: Options,
) SignError![]const u8 {
    if (options.expires_seconds == 0 or options.expires_seconds > max_expires_seconds) {
        return error.InvalidExpires;
    }
    if (!canonical.validPayloadHash(request.payload_hash)) return error.InvalidPayloadHash;
    const scope = try Scope.init(credentials.timestamp, credentials.region, credentials.service);
    if (!canonical.contains(request.headers, "host")) return error.MissingHost;
    try checkPresignedS3(request, credentials);
    for (request.query) |param| {
        if (isReserved(param.name)) return error.ReservedQueryParameter;
    }

    const fields: Fields = .{
        .access_key = credentials.access_key,
        .scope = scope,
        .timestamp = credentials.timestamp,
        .expires_seconds = options.expires_seconds,
        .session_token = credentials.session_token,
        .headers = request.headers,
    };

    // The caller's parameters keep the order the caller holds them, so they
    // are written before the sort. The signed-header names are only ever read
    // sorted, so they are sorted before either query is written.
    canonical.sortHeaders(request.headers);

    var w: Writer = .fixed(out);
    writeCallerQuery(&w, request.query) catch return error.OutTooSmall;
    const uri_offset = w.end;
    const uri = canonical.writeUri(out[uri_offset..], request.path, request.path_mode) catch
        return error.OutTooSmall;

    canonical.sortQuery(request.query);

    var hasher: Writer.Hashing(Sha256) = .initHasher(Sha256.init(.{}), &.{});
    writeCanonicalRequest(&hasher.writer, request, uri, fields) catch |err| switch (err) {
        // The hashing writer has no sink to fill, so it cannot fail.
        error.WriteFailed => unreachable,
    };
    var digest: [32]u8 = undefined;
    hasher.hasher.final(&digest);

    var key = signingKey(credentials.secret_key, scope);
    defer zero(&key);
    var sink: Writer.Hashing(HmacSha256) = .initHasher(HmacSha256.init(&key), &.{});
    defer zero(mem.asBytes(&sink));
    writeStringToSignTo(
        &sink.writer,
        credentials.timestamp,
        scope,
        digest,
    ) catch |err| switch (err) {
        // The hashing writer has no sink to fill, so it cannot fail.
        error.WriteFailed => unreachable,
    };
    var mac: [32]u8 = undefined;
    sink.hasher.final(&mac);

    // The fields replace the URI in the buffer, which has been hashed.
    const separator: []const u8 = if (request.query.len == 0) "" else "&";
    writePresignedFields(&w, fields, separator) catch return error.OutTooSmall;
    const hex = std.fmt.bytesToHex(mac, .lower);
    w.writeAll("&X-Amz-Signature=") catch return error.OutTooSmall;
    w.writeAll(&hex) catch return error.OutTooSmall;
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

/// A query field the presigned form adds. The declaration order is the
/// canonical name order, which is the order `canonical_fields` lists.
const Field = enum { algorithm, credential, date, expires, security_token, signed_headers };

/// The fields in canonical name order, which is the order the canonical query
/// merges them in.
const canonical_fields = [_]Field{
    .algorithm, .credential, .date, .expires, .security_token, .signed_headers,
};

/// The order the official suite emits, which is the order a presigned URL
/// reads in: the algorithm, the credential, the date, the signed headers, the
/// expiry, the token, and then the signature. The canonical query sorts
/// instead.
const emitted_fields = [_]Field{
    .algorithm, .credential, .date, .signed_headers, .expires, .security_token,
};

/// The values a presigned query adds, and the scope its credential names.
const Fields = struct {
    access_key: []const u8,
    scope: Scope,
    timestamp: []const u8,
    expires_seconds: u32,
    session_token: ?[]const u8,
    /// The headers the signature covers, already sorted.
    headers: []const canonical.Header,

    /// False for the token when the credentials carry none.
    fn present(self: Fields, field: Field) bool {
        return field != .security_token or self.session_token != null;
    }
};

fn fieldName(field: Field) []const u8 {
    return switch (field) {
        .algorithm => "X-Amz-Algorithm",
        .credential => "X-Amz-Credential",
        .date => "X-Amz-Date",
        .expires => "X-Amz-Expires",
        .security_token => session_token_query,
        .signed_headers => "X-Amz-SignedHeaders",
    };
}

/// The caller's own parameters, in the order it holds them, as the wire text
/// they are.
fn writeCallerQuery(w: *Writer, params: []const canonical.Param) Writer.Error!void {
    for (params, 0..) |param, index| {
        if (index != 0) try w.writeByte('&');
        try w.writeAll(param.name);
        try w.writeByte('=');
        try w.writeAll(param.value);
    }
}

/// The fields the signature adds. `separator` joins the first one to the
/// caller's parameters; `&` joins the rest.
fn writePresignedFields(w: *Writer, fields: Fields, separator: []const u8) Writer.Error!void {
    var first = true;
    for (emitted_fields) |field| {
        if (!fields.present(field)) continue;
        try w.writeAll(if (first) separator else "&");
        first = false;
        try writeQueryField(w, field, fields);
    }
}

/// The same parameters in canonical order, without the signature.
fn writeCanonicalQuery(
    w: *Writer,
    params: []const canonical.Param,
    fields: Fields,
) Writer.Error!void {
    var it: Merge = .init(params, fields);
    var first = true;
    while (it.next()) |item| {
        if (!first) try w.writeByte('&');
        first = false;
        switch (item) {
            .param => |param| try canonical.writeQueryPair(w, param),
            .field => |field| try writeQueryField(w, field, fields),
        }
    }
}

const Item = union(enum) {
    param: canonical.Param,
    field: Field,
};

/// Walks the caller's parameters, already in canonical order, and the fields
/// in canonical name order, taking whichever name sorts first. A field name
/// never equals a parameter name: `presign` refuses the reserved prefix.
const Merge = struct {
    params: []const canonical.Param,
    fields: Fields,
    param_index: usize = 0,
    field_index: usize = 0,

    fn init(params: []const canonical.Param, fields: Fields) Merge {
        return .{ .params = params, .fields = fields };
    }

    fn next(self: *Merge) ?Item {
        while (self.field_index < canonical_fields.len and
            !self.fields.present(canonical_fields[self.field_index]))
        {
            self.field_index += 1;
        }
        if (self.param_index >= self.params.len) {
            if (self.field_index >= canonical_fields.len) return null;
            defer self.field_index += 1;
            return .{ .field = canonical_fields[self.field_index] };
        }
        if (self.field_index >= canonical_fields.len) {
            defer self.param_index += 1;
            return .{ .param = self.params[self.param_index] };
        }
        const field = canonical_fields[self.field_index];
        const order = encode.order(fieldName(field), self.params[self.param_index].name);
        std.debug.assert(order != .eq);
        if (order == .lt) {
            defer self.field_index += 1;
            return .{ .field = field };
        }
        defer self.param_index += 1;
        return .{ .param = self.params[self.param_index] };
    }
};

fn writeQueryField(w: *Writer, field: Field, fields: Fields) Writer.Error!void {
    try w.writeAll(fieldName(field));
    try w.writeByte('=');
    switch (field) {
        .algorithm => try w.writeAll(algorithm),
        .credential => try writeCredential(w, fields),
        .date => try w.writeAll(fields.timestamp),
        .expires => try w.print("{d}", .{fields.expires_seconds}),
        .security_token => try encode.writeQueryComponent(w, fields.session_token.?),
        .signed_headers => try canonical.writeQueryNamesInto(w, fields.headers, null),
    }
}

/// Writes the credential, `access_key/date/region/service/aws4_request`, with
/// each `/` escaped as `%2F`. It is written in pieces, so no buffer has to
/// hold a key whose length the library does not know.
fn writeCredential(w: *Writer, fields: Fields) Writer.Error!void {
    try encode.writeQueryComponent(w, fields.access_key);
    try w.writeAll("%2F");
    try encode.writeQueryComponent(w, &fields.scope.date);
    try w.writeAll("%2F");
    try encode.writeQueryComponent(w, fields.scope.region);
    try w.writeAll("%2F");
    try encode.writeQueryComponent(w, fields.scope.service);
    try w.writeAll("%2F");
    try w.writeAll(scope_terminator);
}

/// The canonical request, streamed into the hasher that signs it. `uri` is the
/// escaped canonical URI, which the caller built in a buffer it can take back.
fn writeCanonicalRequest(
    w: *Writer,
    request: canonical.Request,
    uri: []const u8,
    fields: Fields,
) Writer.Error!void {
    try canonical.writeMethodInto(w, request.method);
    try w.writeByte('\n');
    try w.writeAll(uri);
    try w.writeByte('\n');
    try writeCanonicalQuery(w, request.query, fields);
    try w.writeByte('\n');
    try canonical.writeHeadersInto(w, request.headers, null);
    try w.writeByte('\n');
    try canonical.writeNamesInto(w, request.headers, null);
    try w.writeByte('\n');
    try w.writeAll(request.payload_hash);
}

/// True when the name, once decoded, starts with the reserved prefix. An
/// escaped `%58-Amz-Signature` is still reserved. The presigned form owns
/// those names, and a second copy of one would leave the canonical query
/// unsortable.
fn isReserved(name: []const u8) bool {
    var canonical_name: encode.Canonical = .init(name);
    for (reserved_prefix) |byte| {
        const decoded = canonical_name.next() orelse return false;
        if (ascii.toLower(decoded) != byte) return false;
    }
    return true;
}

/// S3 answers a presigned URL only when the canonical URI is the wire path and
/// the payload line is `UNSIGNED-PAYLOAD`. S3 canonicalizes `UNSIGNED-PAYLOAD`
/// for every presigned request, so any other hash signs a URL it answers with
/// `SignatureDoesNotMatch`. The query form carries no `x-amz-content-sha256`
/// header, and none is written.
fn checkPresignedS3(request: canonical.Request, credentials: Credentials) SignError!void {
    if (!mem.startsWith(u8, credentials.service, "s3")) return;
    if (request.path_mode != .s3) return error.PathModeMismatch;
    if (!mem.eql(u8, request.payload_hash, "UNSIGNED-PAYLOAD")) {
        return error.ContentSha256Mismatch;
    }
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

test "presign is the primitives in one row" {
    const token = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4F";
    const credentials: Credentials = .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "service",
        .timestamp = "20260826T000000Z",
        .session_token = token,
    };
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var params = [_]canonical.Param{
        .{ .name = "b", .value = "2" },
        .{ .name = "a", .value = "1" },
    };

    var out: [1024]u8 = undefined;
    const query = try presign(&out, .{
        .method = "GET",
        .path = "/",
        .query = &params,
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    }, credentials, .{ .expires_seconds = 3600 });

    // The same query, from the canonical request, the key chain, and the
    // signature, with nothing of `presign`'s own in it.
    var all = [_]canonical.Param{
        .{ .name = "b", .value = "2" },
        .{ .name = "a", .value = "1" },
        .{ .name = "X-Amz-Algorithm", .value = algorithm },
        .{
            .name = "X-Amz-Credential",
            .value = "AKIDEXAMPLE/20260826/us-east-1/service/aws4_request",
        },
        .{ .name = "X-Amz-Date", .value = credentials.timestamp },
        .{ .name = "X-Amz-Expires", .value = "3600" },
        .{ .name = "X-Amz-Security-Token", .value = token },
        .{ .name = "X-Amz-SignedHeaders", .value = "host" },
    };
    var creq_buffer: [2048]u8 = undefined;
    const creq = try canonical.writeRequest(&creq_buffer, .{
        .method = "GET",
        .path = "/",
        .query = &all,
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    });
    var digest: [32]u8 = undefined;
    Sha256.hash(creq, &digest, .{});
    const scope = try Scope.init(credentials.timestamp, credentials.region, credentials.service);
    var string_buffer: [512]u8 = undefined;
    const string_to_sign = try writeStringToSign(
        &string_buffer,
        credentials.timestamp,
        scope,
        digest,
    );
    const key = signingKey(credentials.secret_key, scope);
    const hex = std.fmt.bytesToHex(signature(key, string_to_sign), .lower);

    var expected: [1024]u8 = undefined;
    var w: Writer = .fixed(&expected);
    const emitted = [_]canonical.Param{
        .{ .name = "b", .value = "2" },
        .{ .name = "a", .value = "1" },
        .{ .name = "X-Amz-Algorithm", .value = algorithm },
        .{
            .name = "X-Amz-Credential",
            .value = "AKIDEXAMPLE/20260826/us-east-1/service/aws4_request",
        },
        .{ .name = "X-Amz-Date", .value = credentials.timestamp },
        .{ .name = "X-Amz-SignedHeaders", .value = "host" },
        .{ .name = "X-Amz-Expires", .value = "3600" },
        .{ .name = "X-Amz-Security-Token", .value = token },
        .{ .name = "X-Amz-Signature", .value = &hex },
    };
    for (emitted, 0..) |param, index| {
        if (index != 0) try w.writeByte('&');
        try canonical.writeQueryPair(&w, param);
    }

    // The caller's parameters keep their order, the canonical query sorts
    // them, and the token is a query parameter and not a signed header.
    try testing.expectEqualStrings(w.buffered(), query);
}

/// The credentials the presign tests share.
const test_credentials: Credentials = .{
    .access_key = "AKIDEXAMPLE",
    .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    .region = "us-east-1",
    .service = "service",
    .timestamp = "20260826T000000Z",
};

test "a presigned URL lives between one second and one week" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    const request: canonical.Request = .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    };
    var out: [1024]u8 = undefined;

    try testing.expectError(error.InvalidExpires, presign(&out, request, test_credentials, .{
        .expires_seconds = 0,
    }));
    try testing.expectError(error.InvalidExpires, presign(&out, request, test_credentials, .{
        .expires_seconds = max_expires_seconds + 1,
    }));
    const shortest = try presign(&out, request, test_credentials, .{ .expires_seconds = 1 });
    try testing.expect(mem.find(u8, shortest, "X-Amz-Expires=1&") != null);
    _ = try presign(&out, request, test_credentials, .{ .expires_seconds = max_expires_seconds });
}

test "a presigned query needs a host and room for the path" {
    var headers = [_]canonical.Header{
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var out: [256]u8 = undefined;
    const unsigned: canonical.Request = .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    };
    try testing.expectError(error.MissingHost, presign(&out, unsigned, test_credentials, .{
        .expires_seconds = 3600,
    }));

    // The escaped path is written into `out` while the signature is computed.
    var host = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutTooSmall, presign(&tiny, .{
        .method = "GET",
        .path = "/a/longer/path/than/the/buffer",
        .headers = &host,
        .payload_hash = "UNSIGNED-PAYLOAD",
    }, test_credentials, .{ .expires_seconds = 3600 }));
}

test "a caller parameter cannot take a reserved name" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var out: [1024]u8 = undefined;

    var reserved = [_]canonical.Param{
        .{ .name = "X-Amz-Signature", .value = "0" },
    };
    try testing.expectError(error.ReservedQueryParameter, presign(&out, .{
        .method = "GET",
        .path = "/",
        .query = &reserved,
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    }, test_credentials, .{ .expires_seconds = 3600 }));

    // An escaped `X` is the same name, and the prefix is not case-sensitive.
    var escaped = [_]canonical.Param{
        .{ .name = "%58-amz-date", .value = "x" },
    };
    try testing.expectError(error.ReservedQueryParameter, presign(&out, .{
        .method = "GET",
        .path = "/",
        .query = &escaped,
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    }, test_credentials, .{ .expires_seconds = 3600 }));
}

test "a presigned S3 URL uses the S3 path mode and the caller's payload hash" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var out: [1024]u8 = undefined;
    var request: canonical.Request = .{
        .method = "GET",
        .path = "/a%20b",
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    };
    const s3: Credentials = .{
        .access_key = test_credentials.access_key,
        .secret_key = test_credentials.secret_key,
        .region = test_credentials.region,
        .service = "s3",
        .timestamp = test_credentials.timestamp,
    };

    try testing.expectError(error.PathModeMismatch, presign(&out, request, s3, .{
        .expires_seconds = 3600,
    }));

    // S3 presigning fixes the payload line: any hash but `UNSIGNED-PAYLOAD`
    // signs a URL S3 answers with SignatureDoesNotMatch.
    request.path_mode = .s3;
    const query = try presign(&out, request, s3, .{ .expires_seconds = 3600 });
    try testing.expect(mem.find(u8, query, "x-amz-content-sha256") == null);
    request.payload_hash = canonical.empty_payload_hash;
    try testing.expectError(error.ContentSha256Mismatch, presign(&out, request, s3, .{
        .expires_seconds = 3600,
    }));
    request.payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    try testing.expectError(error.ContentSha256Mismatch, presign(&out, request, s3, .{
        .expires_seconds = 3600,
    }));
}

test "a header in the slice is signed in the query form" {
    var headers = [_]canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    var out: [1024]u8 = undefined;
    const query = try presign(&out, .{
        .method = "PUT",
        .path = "/",
        .headers = &headers,
        .payload_hash = "UNSIGNED-PAYLOAD",
    }, test_credentials, .{ .expires_seconds = 3600 });

    // The recipient has to send the header back, so it is both signed and
    // named, and a token the credentials do not carry is not written.
    try testing.expect(mem.find(u8, query, "X-Amz-SignedHeaders=content-type%3Bhost&") != null);
    try testing.expect(mem.find(u8, query, "X-Amz-Security-Token") == null);
}
