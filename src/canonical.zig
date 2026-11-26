//! The canonical request: the method, the canonical URI, the canonical query
//! string, the canonical headers, the signed-header names, and the payload
//! hash, laid out in that order and newline separated.
//!
//! Every function writes into a caller-owned buffer and returns the bytes it
//! wrote. The header and query slices are sorted in place, because the sort is
//! the only state a builder needs and a buffer for it would be the caller's
//! anyway.

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const ascii = std.ascii;
const testing = std.testing;
const Writer = std.Io.Writer;

const encode = @import("encode.zig");

const whitespace = " \t\n\r\x0b\x0c";

/// A canonical buffer that was too small. Nothing partial is returned.
pub const WriteError = error{NoSpaceLeft};

/// What a canonical request refuses besides a short buffer: a header set with
/// no `host`, or a payload hash that is not a hash.
pub const RequestError = error{
    NoSpaceLeft,
    MissingHost,
    InvalidPayloadHash,
};

/// The lowercase hex SHA-256 of an empty body. Every request with no body
/// signs this string as its payload hash.
pub const empty_payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// How the canonical URI treats the wire path.
pub const PathMode = enum {
    /// Every service except S3. Normalizes dot segments, then encodes the wire
    /// path again, so a wire `%25` becomes `%2525`.
    service,
    /// A service path with no normalization. Encodes the wire path again and
    /// leaves dot segments alone. The AWS signing test suite signs both forms.
    unnormalized,
    /// S3. The wire path is the canonical URI, with no normalization and no
    /// second encoding. The caller sends an encoded path.
    s3,
};

/// One header field line. `name` is matched and written in ASCII case-folded
/// form; `value` has every run of ASCII whitespace collapsed to one space and
/// its ends trimmed. The caller de-folds continuation lines before it gets
/// here.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// One query parameter as it goes on the wire. A valid %XX triplet is decoded
/// and re-encoded, so `%7e` becomes `~` and `%2f` becomes `%2F`. Every other
/// byte outside the unreserved set is escaped, and a literal `%` must arrive
/// as `%25`.
pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

/// A request in the terms the signature is defined over. The headers a caller
/// sends but does not sign stay out of `headers`. `host` must be in it.
pub const Request = struct {
    method: []const u8,
    /// The path from the request target, as it goes on the wire. An empty
    /// path signs as `/`.
    path: []const u8,
    /// Sorted in place.
    query: []Param = &.{},
    /// Sorted in place.
    headers: []Header,
    /// Lowercase hex SHA-256 of the body, `UNSIGNED-PAYLOAD`, or a
    /// `STREAMING-` form.
    payload_hash: []const u8,
    path_mode: PathMode = .service,
};

/// Writes the whole canonical request, sorting `request.headers` and
/// `request.query` in place. `host` must be among the headers, and
/// `payload_hash` must be a hash, `UNSIGNED-PAYLOAD`, or a `STREAMING-` form.
pub fn writeRequest(out: []u8, request: Request) RequestError![]const u8 {
    return writeRequestWith(out, request, null);
}

/// Writes the canonical request with one header that is not in
/// `request.headers`. A session token joins the signature this way, because a
/// caller's header array has no room for a slot it did not declare.
///
/// `extra` must not share a name with a header in the list; two fields of the
/// same name would be written as one line with the values comma-joined.
pub fn writeRequestWith(out: []u8, request: Request, extra: ?Header) RequestError![]const u8 {
    try validate(request, extra);
    var w: Writer = .fixed(out);
    writeRequestTo(&w, request, extra) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the canonical URI for a wire path.
///
/// In `.service` mode the path is normalized and encoded again, so an escape
/// that the wire already has becomes a second escape. In `.s3` mode the bytes
/// are the canonical URI, so the caller sends an encoded path.
///
/// The URI goes into a fixed buffer because a `..` segment removes the bytes
/// the segment before it wrote, and a writer that has already sent them
/// cannot take them back.
pub fn writeUri(out: []u8, path: []const u8, mode: PathMode) WriteError![]const u8 {
    var w: Writer = .fixed(out);
    writePathTo(&w, path, mode) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the method, upper case, as the first line of the canonical request.
pub fn writeMethodInto(w: *Writer, method: []const u8) Writer.Error!void {
    for (method) |byte| try w.writeByte(ascii.toUpper(byte));
}

/// Writes the canonical query string, sorting `params` in place by canonical
/// name and then canonical value.
pub fn writeQuery(out: []u8, params: []Param) WriteError![]const u8 {
    sortQuery(params);
    var w: Writer = .fixed(out);
    writeQueryTo(&w, params) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Sorts `params` in place in canonical order: by name, then by value, both
/// compared in their encoded form. This is the order the canonical query
/// string is written in, and the only state a builder needs.
pub fn sortQuery(params: []Param) void {
    mem.sort(Param, params, {}, paramLessThan);
}

/// Writes one query pair, `name=value`, in canonical form, with no `&` before
/// it. The caller writes the separators, which is how a presigned query places
/// its own fields between the parameters it was handed.
pub fn writeQueryPair(w: *Writer, param: Param) Writer.Error!void {
    try encode.writeQueryComponent(w, param.name);
    try w.writeByte('=');
    try encode.writeQueryComponent(w, param.value);
}

/// Writes the canonical headers block: one `name:value` line per header, names
/// case-folded and sorted, values trimmed, duplicate names comma-joined in the
/// order they arrived. `extra` joins the block the same way it joins a request.
pub fn writeHeaders(out: []u8, headers: []Header, extra: ?Header) WriteError![]const u8 {
    sortHeaders(headers);
    var w: Writer = .fixed(out);
    writeHeadersInto(&w, headers, extra) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Sorts `headers` in place by ASCII case-folded name, which is the order the
/// canonical header block and the signed-header list are written in.
pub fn sortHeaders(headers: []Header) void {
    mem.sort(Header, headers, {}, headerLessThan);
}

/// The streaming form of `writeHeaders`, for a caller that already owns a
/// writer. `headers` and `extra` must be sorted.
pub fn writeHeadersInto(w: *Writer, headers: []const Header, extra: ?Header) Writer.Error!void {
    var it: Sorted = .init(headers, extra);
    var current = it.next();
    while (current) |first| {
        const name = first.name;
        try writeLower(w, name);
        try w.writeByte(':');
        try writeValue(w, first.value);
        current = it.next();
        while (current) |next| {
            if (nameOrder(next.name, name) != .eq) break;
            try w.writeByte(',');
            try writeValue(w, next.value);
            current = it.next();
        }
        try w.writeByte('\n');
    }
}

/// Writes the named headers, semicolon separated, with a repeated name listed
/// once. This is the `SignedHeaders` value of the Authorization field.
pub fn writeNames(out: []u8, headers: []Header, extra: ?Header) WriteError![]const u8 {
    sortHeaders(headers);
    var w: Writer = .fixed(out);
    writeNamesInto(&w, headers, extra) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// True when `name` is in `headers`, ASCII case-folded. One scan, no order
/// required.
pub fn contains(headers: []const Header, name: []const u8) bool {
    return find(headers, name) != null;
}

/// The value of the first header named `name`, ASCII case-folded, or null.
pub fn find(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (nameOrder(header.name, name) == .eq) return header.value;
    }
    return null;
}

/// The streaming form of `writeNames`, for a caller that already owns a writer.
/// `headers` and `extra` must be sorted; the assertion is here because a
/// wrong order writes a SignedHeaders value that does not verify.
pub fn writeNamesInto(w: *Writer, headers: []const Header, extra: ?Header) Writer.Error!void {
    try writeNamesWith(w, headers, extra, ";", writeLower);
}

/// The signed-header list as one percent-encoded query value: names
/// lower-cased, a repeated name listed once, and `;` between them escaped as
/// `%3B`. This is the `X-Amz-SignedHeaders` value of a presigned URL.
pub fn writeQueryNamesInto(w: *Writer, headers: []const Header, extra: ?Header) Writer.Error!void {
    try writeNamesWith(w, headers, extra, "%3B", writeLowerQuery);
}

/// One list of distinct names. The header form separates with `;` and writes
/// the name; the query form separates with `%3B` and escapes the name too.
fn writeNamesWith(
    w: *Writer,
    headers: []const Header,
    extra: ?Header,
    comptime separator: []const u8,
    comptime writeName: fn (*Writer, []const u8) Writer.Error!void,
) Writer.Error!void {
    assert(isSorted(headers, extra));
    var it: Sorted = .init(headers, extra);
    var previous: ?[]const u8 = null;
    var first = true;
    while (it.next()) |header| {
        if (previous) |name| {
            if (nameOrder(name, header.name) == .eq) continue;
        }
        if (!first) try w.writeAll(separator);
        first = false;
        try writeName(w, header.name);
        previous = header.name;
    }
}

fn validate(request: Request, extra: ?Header) RequestError!void {
    if (!hasHost(request.headers, extra)) return error.MissingHost;
    if (!validPayloadHash(request.payload_hash)) return error.InvalidPayloadHash;
}

fn hasHost(headers: []const Header, extra: ?Header) bool {
    if (contains(headers, "host")) return true;
    const header = extra orelse return false;
    return nameOrder(header.name, "host") == .eq;
}

/// True for the payload forms the canonical request accepts: 64 lowercase hex
/// characters, `UNSIGNED-PAYLOAD`, or a `STREAMING-` form. Uppercase hex and a
/// raw digest are not a payload hash, so they do not sign in silence.
pub fn validPayloadHash(hash: []const u8) bool {
    if (mem.eql(u8, hash, "UNSIGNED-PAYLOAD")) return true;
    if (mem.startsWith(u8, hash, "STREAMING-")) return true;
    if (hash.len != 64) return false;
    for (hash) |byte| {
        if (ascii.isDigit(byte)) continue;
        if (byte >= 'a' and byte <= 'f') continue;
        return false;
    }
    return true;
}

fn writeRequestTo(w: *Writer, request: Request, extra: ?Header) Writer.Error!void {
    sortHeaders(request.headers);
    sortQuery(request.query);
    try writeMethodInto(w, request.method);
    try w.writeByte('\n');
    try writePathTo(w, request.path, request.path_mode);
    try w.writeByte('\n');
    try writeQueryTo(w, request.query);
    try w.writeByte('\n');
    try writeHeadersInto(w, request.headers, extra);
    try w.writeByte('\n');
    try writeNamesInto(w, request.headers, extra);
    try w.writeByte('\n');
    try w.writeAll(request.payload_hash);
}

fn writePathTo(w: *Writer, path: []const u8, mode: PathMode) Writer.Error!void {
    if (path.len == 0) {
        try w.writeByte('/');
        return;
    }
    switch (mode) {
        .service => try writeNormalizedPath(w, path),
        .unnormalized => try encode.writePath(w, path),
        .s3 => try w.writeAll(path),
    }
}

fn writeNormalizedPath(w: *Writer, path: []const u8) Writer.Error!void {
    const start = w.end;
    var segments = mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0) continue;
        if (segment.len == 1 and segment[0] == '.') continue;
        if (segment.len == 2 and segment[0] == '.' and segment[1] == '.') {
            rewindSegment(w, start);
            continue;
        }
        try w.writeByte('/');
        try encode.writePathSegment(w, segment);
    }
    // A path always starts with one slash, and a trailing slash survives only
    // when the raw path had one.
    if (w.end == start) {
        try w.writeByte('/');
    } else if (path[path.len - 1] == '/') {
        try w.writeByte('/');
    }
}

/// Drops the last segment the normalized path wrote. This is the one place the
/// builder walks backwards, and it stays inside the caller's buffer.
fn rewindSegment(w: *Writer, start: usize) void {
    const written = w.buffer[start..w.end];
    if (mem.findScalarLast(u8, written, '/')) |offset| {
        w.end = start + offset;
    } else {
        w.end = start;
    }
}

fn writeQueryTo(w: *Writer, params: []const Param) Writer.Error!void {
    for (params, 0..) |param, index| {
        if (index != 0) try w.writeByte('&');
        try writeQueryPair(w, param);
    }
}

/// Collapses every run of ASCII whitespace to one space and trims both ends,
/// which is the whitespace set aws-c-auth collapses, and also keeps a value
/// with a CR or LF from writing a second canonical line.
fn writeValue(w: *Writer, value: []const u8) Writer.Error!void {
    const trimmed = mem.trim(u8, value, whitespace);
    var pending_space = false;
    for (trimmed) |byte| {
        if (ascii.isWhitespace(byte)) {
            pending_space = true;
            continue;
        }
        if (pending_space) try w.writeByte(' ');
        pending_space = false;
        try w.writeByte(byte);
    }
}

fn writeLower(w: *Writer, bytes: []const u8) Writer.Error!void {
    for (bytes) |byte| try w.writeByte(ascii.toLower(byte));
}

fn writeLowerQuery(w: *Writer, bytes: []const u8) Writer.Error!void {
    for (bytes) |byte| try encode.writeQueryByte(w, ascii.toLower(byte));
}

fn headerLessThan(_: void, a: Header, b: Header) bool {
    return nameOrder(a.name, b.name) == .lt;
}

fn paramLessThan(_: void, a: Param, b: Param) bool {
    return switch (encode.order(a.name, b.name)) {
        .lt => true,
        .gt => false,
        .eq => encode.order(a.value, b.value) == .lt,
    };
}

/// ASCII case-folded byte order, which is how both header names and the
/// signed-header list sort.
fn nameOrder(a: []const u8, b: []const u8) std.math.Order {
    const len = @min(a.len, b.len);
    var index: usize = 0;
    while (index < len) : (index += 1) {
        const left = ascii.toLower(a[index]);
        const right = ascii.toLower(b[index]);
        if (left < right) return .lt;
        if (left > right) return .gt;
    }
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return .eq;
}

fn isSorted(headers: []const Header, extra: ?Header) bool {
    var it: Sorted = .init(headers, extra);
    var previous: ?[]const u8 = null;
    while (it.next()) |header| {
        if (previous) |name| {
            if (nameOrder(name, header.name) == .gt) return false;
        }
        previous = header.name;
    }
    return true;
}

/// The header list as the signature sees it: the caller's headers in sorted
/// order with `extra` merged in at its place. It borrows both.
const Sorted = struct {
    headers: []const Header,
    extra: ?Header,
    index: usize = 0,
    extra_done: bool = false,

    fn init(headers: []const Header, extra: ?Header) Sorted {
        return .{ .headers = headers, .extra = extra };
    }

    fn next(self: *Sorted) ?Header {
        if (self.index < self.headers.len) {
            if (!self.extra_done) {
                if (self.extra) |extra| {
                    if (nameOrder(extra.name, self.headers[self.index].name) == .lt) {
                        self.extra_done = true;
                        return extra;
                    }
                }
            }
            defer self.index += 1;
            return self.headers[self.index];
        }
        if (self.extra_done) return null;
        self.extra_done = true;
        return self.extra;
    }
};

test "an empty path signs as one slash" {
    var buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("/", try writeUri(&buffer, "", .service));
    try testing.expectEqualStrings("/", try writeUri(&buffer, "", .s3));
}

test "a service path is normalized and encoded again" {
    const cases = [_]struct { path: []const u8, canonical: []const u8 }{
        .{ .path = "/", .canonical = "/" },
        .{ .path = "//", .canonical = "/" },
        .{ .path = "//example//", .canonical = "/example/" },
        .{ .path = "/./example", .canonical = "/example" },
        .{ .path = "/example/..", .canonical = "/" },
        .{ .path = "/example1/example2/../..", .canonical = "/" },
        .{ .path = "/example space/", .canonical = "/example%20space/" },
        .{ .path = "/a/b/", .canonical = "/a/b/" },
        .{ .path = "/a%25b", .canonical = "/a%2525b" },
    };
    for (cases) |case| {
        var buffer: [64]u8 = undefined;
        try testing.expectEqualStrings(case.canonical, try writeUri(&buffer, case.path, .service));
    }
}

test "an unnormalized service path keeps its dot segments" {
    const cases = [_]struct { path: []const u8, canonical: []const u8 }{
        .{ .path = "//example//", .canonical = "//example//" },
        .{ .path = "/example/..", .canonical = "/example/.." },
        .{ .path = "/a b", .canonical = "/a%20b" },
        .{ .path = "/a%25b", .canonical = "/a%2525b" },
    };
    for (cases) |case| {
        var buffer: [64]u8 = undefined;
        try testing.expectEqualStrings(
            case.canonical,
            try writeUri(&buffer, case.path, .unnormalized),
        );
    }
}

test "an S3 path is the wire path" {
    const cases = [_][]const u8{ "/", "/a/b/", "/a%20b", "/a%2Bb", "/a%25b", "/a%3Db", "/a b" };
    for (cases) |path| {
        var buffer: [64]u8 = undefined;
        try testing.expectEqualStrings(path, try writeUri(&buffer, path, .s3));
    }
}

test "the method is upper case" {
    var headers = [_]Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var buffer: [256]u8 = undefined;
    const canonical = try writeRequest(&buffer, .{
        .method = "get",
        .path = "/",
        .headers = &headers,
        .payload_hash = empty_payload_hash,
    });
    try testing.expect(mem.startsWith(u8, canonical, "GET\n"));
}

test "a request without host is refused" {
    var headers = [_]Header{
        .{ .name = "x-amz-date", .value = "20150830T123600Z" },
    };
    var buffer: [256]u8 = undefined;
    try testing.expectError(error.MissingHost, writeRequest(&buffer, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = empty_payload_hash,
    }));
}

test "a payload hash that is not a hash is refused" {
    var headers = [_]Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
    };
    var buffer: [256]u8 = undefined;
    const request: Request = .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = empty_payload_hash,
    };
    var upper: [64]u8 = undefined;
    @memcpy(&upper, empty_payload_hash);
    for (&upper) |*byte| byte.* = ascii.toUpper(byte.*);

    try testing.expectError(error.InvalidPayloadHash, writeRequest(&buffer, .{
        .method = request.method,
        .path = request.path,
        .headers = request.headers,
        .payload_hash = &upper,
    }));
    try testing.expectError(error.InvalidPayloadHash, writeRequest(&buffer, .{
        .method = request.method,
        .path = request.path,
        .headers = request.headers,
        .payload_hash = "deadbeef",
    }));
    var unsigned = request;
    unsigned.payload_hash = "UNSIGNED-PAYLOAD";
    _ = try writeRequest(&buffer, unsigned);
    var streaming = request;
    streaming.payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    _ = try writeRequest(&buffer, streaming);
}

test "headers sort case-folded and duplicates join in arrival order" {
    var headers = [_]Header{
        .{ .name = "X-Dupe", .value = "b" },
        .{ .name = "Host", .value = " example.amazonaws.com " },
        .{ .name = "x-dupe", .value = "a" },
        .{ .name = "X-Gap", .value = "a\t \nb" },
    };
    var buffer: [256]u8 = undefined;
    var names: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "host:example.amazonaws.com\nx-dupe:b,a\nx-gap:a b\n",
        try writeHeaders(&buffer, &headers, null),
    );
    try testing.expectEqualStrings("host;x-dupe;x-gap", try writeNames(&names, &headers, null));
}

test "an extra header joins at its sorted place" {
    var headers = [_]Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20150830T123600Z" },
    };
    var buffer: [256]u8 = undefined;
    var names: [64]u8 = undefined;
    const extra: Header = .{ .name = "x-custom", .value = "v" };
    try testing.expectEqualStrings(
        "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\nx-custom:v\n",
        try writeHeaders(&buffer, &headers, extra),
    );
    try testing.expectEqualStrings(
        "host;x-amz-date;x-custom",
        try writeNames(&names, &headers, extra),
    );
}

test "query parameters sort by canonical name and then canonical value" {
    var params = [_]Param{
        .{ .name = "a", .value = "2" },
        .{ .name = " ", .value = "first" },
        .{ .name = "a", .value = "1" },
        .{ .name = "", .value = "" },
    };
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "=&%20=first&a=1&a=2",
        try writeQuery(&buffer, &params),
    );
}

test "a bare query key gets an empty value" {
    var params = [_]Param{
        .{ .name = "flag", .value = "" },
        .{ .name = "a", .value = "1" },
    };
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("a=1&flag=", try writeQuery(&buffer, &params));
}
