//! The canonical request: the method, the canonical URI, the canonical query
//! string, the canonical headers, the signed-header names, and the payload
//! hash, laid out in that order and newline separated.
//!
//! Every function writes into a caller-owned buffer and returns the bytes it
//! wrote. The header and query slices are sorted in place, because the sort is
//! the only state a builder needs and a buffer for it would be the caller's
//! anyway.

const std = @import("std");
const encode = @import("encode.zig");

const Writer = std.Io.Writer;

/// A canonical buffer that was too small. Nothing partial is returned.
pub const WriteError = error{NoSpaceLeft};

/// The lowercase hex SHA-256 of an empty body. Every request with no body
/// signs this string as its payload hash.
pub const empty_payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// One header field line. `name` is matched and written in ASCII case-folded
/// form; `value` is trimmed and its runs of spaces and tabs collapse to one
/// space. The caller de-folds continuation lines before it gets here.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// One query parameter as it appears on the wire. A valid %XX triplet is
/// decoded and re-encoded, so a name may be percent-encoded or not.
pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

/// A request in the terms the signature is defined over. The headers a caller
/// sends but does not sign stay out of `headers`; `host` and `x-amz-date` must
/// be in it.
pub const Request = struct {
    method: []const u8,
    /// The path from the request target, decoded. The canonical URI is encoded
    /// from these bytes. An empty path signs as `/`.
    path: []const u8,
    /// Sorted in place.
    query: []Param = &.{},
    /// Sorted in place.
    headers: []Header,
    /// Lowercase hex SHA-256 of the body, or `UNSIGNED-PAYLOAD`.
    payload_hash: []const u8,
    /// Removes `.`, `..`, and empty path segments, the way RFC 3986 section
    /// 5.2.4 does. Every service except S3 signs the normalized path.
    normalize_path: bool = false,
};

/// Writes the whole canonical request, sorting `request.headers` and
/// `request.query` in place.
pub fn writeRequest(out: []u8, request: Request) WriteError![]const u8 {
    return writeRequestWith(out, request, null);
}

/// Writes the canonical request with one header that is not in
/// `request.headers`. A session token joins the signature this way, because a
/// caller's header array has no room for a slot it did not declare.
///
/// `extra` must not share a name with a header in the list; two fields of the
/// same name would be written as one line with the values comma-joined.
pub fn writeRequestWith(out: []u8, request: Request, extra: ?Header) WriteError![]const u8 {
    var w: Writer = .fixed(out);
    writeRequestTo(&w, request, extra) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the canonical URI for a decoded path.
///
/// The bytes are escaped as given, so an already-escaped target is escaped
/// again: `%25` becomes `%2525`. Pass the decoded path, which is what S3
/// object keys and every other service's path have in common.
pub fn writeUri(out: []u8, path: []const u8, normalize: bool) WriteError![]const u8 {
    var w: Writer = .fixed(out);
    writePathTo(&w, path, normalize) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the canonical query string, sorting `params` in place by encoded
/// name and then by encoded value.
pub fn writeQuery(out: []u8, params: []Param) WriteError![]const u8 {
    std.mem.sort(Param, params, {}, paramLessThan);
    var w: Writer = .fixed(out);
    writeQueryTo(&w, params) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the canonical headers block: one `name:value` line per header, names
/// case-folded and sorted, values trimmed, duplicate names comma-joined in the
/// order they arrived. `extra` joins the block the same way it joins a request.
pub fn writeHeaders(out: []u8, headers: []Header, extra: ?Header) WriteError![]const u8 {
    std.mem.sort(Header, headers, {}, headerLessThan);
    var w: Writer = .fixed(out);
    writeHeadersTo(&w, headers, extra) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// Writes the named headers, semicolon separated, with a repeated name listed
/// once. This is the `SignedHeaders` value of the Authorization field.
pub fn writeNames(out: []u8, headers: []Header, extra: ?Header) WriteError![]const u8 {
    std.mem.sort(Header, headers, {}, headerLessThan);
    var w: Writer = .fixed(out);
    writeNamesInto(&w, headers, extra) catch return error.NoSpaceLeft;
    return w.buffered();
}

/// True when `name` is in `headers`, ASCII case-folded. One scan, no order
/// required.
pub fn contains(headers: []const Header, name: []const u8) bool {
    for (headers) |header| {
        if (nameOrder(header.name, name) == .eq) return true;
    }
    return false;
}

/// The streaming form of `writeNames`, for a caller that already owns a writer.
/// `headers` must be sorted.
pub fn writeNamesInto(w: *Writer, headers: []const Header, extra: ?Header) Writer.Error!void {
    var it: Sorted = .init(headers, extra);
    var previous: ?[]const u8 = null;
    var first = true;
    while (it.next()) |header| {
        if (previous) |name| {
            if (nameOrder(name, header.name) == .eq) continue;
        }
        if (!first) try w.writeByte(';');
        first = false;
        try writeLower(w, header.name);
        previous = header.name;
    }
}

fn writeRequestTo(w: *Writer, request: Request, extra: ?Header) Writer.Error!void {
    std.mem.sort(Header, request.headers, {}, headerLessThan);
    std.mem.sort(Param, request.query, {}, paramLessThan);
    try w.writeAll(request.method);
    try w.writeByte('\n');
    try writePathTo(w, request.path, request.normalize_path);
    try w.writeByte('\n');
    try writeQueryTo(w, request.query);
    try w.writeByte('\n');
    try writeHeadersTo(w, request.headers, extra);
    try w.writeByte('\n');
    try writeNamesInto(w, request.headers, extra);
    try w.writeByte('\n');
    try w.writeAll(request.payload_hash);
}

fn writePathTo(w: *Writer, path: []const u8, normalize: bool) Writer.Error!void {
    if (path.len == 0) {
        try w.writeByte('/');
        return;
    }
    if (!normalize) {
        try encode.writePath(w, path);
        return;
    }
    try writeNormalizedPath(w, path);
}

fn writeNormalizedPath(w: *Writer, path: []const u8) Writer.Error!void {
    const start = w.end;
    var segments = std.mem.splitScalar(u8, path, '/');
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
    if (std.mem.findScalarLast(u8, written, '/')) |offset| {
        w.end = start + offset;
    } else {
        w.end = start;
    }
}

fn writeQueryTo(w: *Writer, params: []const Param) Writer.Error!void {
    for (params, 0..) |param, index| {
        if (index != 0) try w.writeByte('&');
        try encode.writeQueryComponent(w, param.name);
        try w.writeByte('=');
        try encode.writeQueryComponent(w, param.value);
    }
}

fn writeHeadersTo(w: *Writer, headers: []const Header, extra: ?Header) Writer.Error!void {
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

fn writeValue(w: *Writer, value: []const u8) Writer.Error!void {
    const trimmed = std.mem.trim(u8, value, " \t");
    var pending_space = false;
    for (trimmed) |byte| {
        if (byte == ' ' or byte == '\t') {
            pending_space = true;
            continue;
        }
        if (pending_space) try w.writeByte(' ');
        pending_space = false;
        try w.writeByte(byte);
    }
}

fn writeLower(w: *Writer, bytes: []const u8) Writer.Error!void {
    for (bytes) |byte| try w.writeByte(std.ascii.toLower(byte));
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
        const left = std.ascii.toLower(a[index]);
        const right = std.ascii.toLower(b[index]);
        if (left < right) return .lt;
        if (left > right) return .gt;
    }
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return .eq;
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
    try std.testing.expectEqualStrings("/", try writeUri(&buffer, "", false));
}

test "normalization drops dot and empty segments" {
    const cases = [_]struct { path: []const u8, normalized: []const u8 }{
        .{ .path = "/", .normalized = "/" },
        .{ .path = "//", .normalized = "/" },
        .{ .path = "//example//", .normalized = "/example/" },
        .{ .path = "/./example", .normalized = "/example" },
        .{ .path = "/example/..", .normalized = "/" },
        .{ .path = "/example1/example2/../..", .normalized = "/" },
        .{ .path = "/example space/", .normalized = "/example%20space/" },
    };
    for (cases) |case| {
        var buffer: [64]u8 = undefined;
        try std.testing.expectEqualStrings(case.normalized, try writeUri(&buffer, case.path, true));
    }
}

test "a path is encoded from the bytes it has" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/a%2525b", try writeUri(&buffer, "/a%25b", false));
    try std.testing.expectEqualStrings("/a%2525b", try writeUri(&buffer, "/a%25b", true));
}

test "headers sort case-folded and duplicates join in arrival order" {
    var headers = [_]Header{
        .{ .name = "X-Dupe", .value = "b" },
        .{ .name = "Host", .value = " example.amazonaws.com " },
        .{ .name = "x-dupe", .value = "a" },
        .{ .name = "X-Tab", .value = "a\t \tb" },
    };
    var buffer: [256]u8 = undefined;
    var names: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "host:example.amazonaws.com\nx-dupe:b,a\nx-tab:a b\n",
        try writeHeaders(&buffer, &headers, null),
    );
    try std.testing.expectEqualStrings("host;x-dupe;x-tab", try writeNames(&names, &headers, null));
}

test "an extra header joins at its sorted place" {
    var headers = [_]Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20150830T123600Z" },
    };
    var buffer: [256]u8 = undefined;
    var names: [64]u8 = undefined;
    const extra: Header = .{ .name = "x-custom", .value = "v" };
    try std.testing.expectEqualStrings(
        "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\nx-custom:v\n",
        try writeHeaders(&buffer, &headers, extra),
    );
    try std.testing.expectEqualStrings(
        "host;x-amz-date;x-custom",
        try writeNames(&names, &headers, extra),
    );
}

test "query parameters sort by encoded name and then encoded value" {
    var params = [_]Param{
        .{ .name = "a", .value = "2" },
        .{ .name = " ", .value = "first" },
        .{ .name = "a", .value = "1" },
        .{ .name = "", .value = "" },
    };
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "=&%20=first&a=1&a=2",
        try writeQuery(&buffer, &params),
    );
}
