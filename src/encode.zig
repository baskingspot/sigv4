//! The percent-encoding rules the canonical request stands on. A byte outside
//! the unreserved set becomes %XX with uppercase hex digits. The canonical
//! query keeps a %XX that the wire already has, because it takes wire text.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const Writer = Io.Writer;

const upper_hex = "0123456789ABCDEF";

/// True for `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`, `_`, and `~`.
pub fn unreserved(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// Writes one query name or value in canonical form. The input is wire text:
/// a valid %XX triplet is decoded and re-encoded, so `%7e` becomes `~` and
/// `%2f` becomes `%2F`. Every other byte outside the unreserved set becomes
/// uppercase %XX, and a literal `%` must arrive as `%25`.
pub fn writeQueryComponent(w: *Writer, bytes: []const u8) Writer.Error!void {
    var canonical: Canonical = .init(bytes);
    while (canonical.next()) |byte| try w.writeByte(byte);
}

/// Writes one byte of a query name or value in canonical form: an unreserved
/// byte stays literal and every other byte becomes uppercase %XX. The byte is
/// taken as the byte it is, not as wire text, so `%` becomes `%25`.
pub fn writeQueryByte(w: *Writer, byte: u8) Writer.Error!void {
    if (unreserved(byte)) {
        try w.writeByte(byte);
    } else {
        try writeEscape(w, byte);
    }
}

/// Writes a path with its `/` separators left literal and every other byte
/// outside the unreserved set escaped, with no dot-segment removal.
pub fn writePath(w: *Writer, path: []const u8) Writer.Error!void {
    for (path) |byte| {
        if (byte == '/' or unreserved(byte)) {
            try w.writeByte(byte);
        } else {
            try writeEscape(w, byte);
        }
    }
}

/// Writes one path segment with every byte outside the unreserved set escaped.
/// This is the second escape a service path takes, so a wire `%25` becomes
/// `%2525` here.
pub fn writePathSegment(w: *Writer, segment: []const u8) Writer.Error!void {
    for (segment) |byte| {
        if (unreserved(byte)) {
            try w.writeByte(byte);
        } else {
            try writeEscape(w, byte);
        }
    }
}

fn writeEscape(w: *Writer, byte: u8) Writer.Error!void {
    const escape = [3]u8{ '%', upper_hex[byte >> 4], upper_hex[byte & 0xf] };
    try w.writeAll(&escape);
}

/// The canonical form of a wire query component, one byte at a time. A valid
/// %XX is decoded first, then the byte is re-encoded, so `%7e` and `~` reach
/// the same byte and `%2f` and `%2F` do too. The stream is what the canonical
/// query writes and what its sort compares, so the two cannot disagree.
pub const Canonical = struct {
    raw: []const u8,
    index: usize,
    pending: [3]u8,
    pending_end: u8,
    pending_at: u8,

    pub fn init(raw: []const u8) Canonical {
        return .{
            .raw = raw,
            .index = 0,
            .pending = undefined,
            .pending_end = 0,
            .pending_at = 0,
        };
    }

    /// The next byte of the canonical form, or null at the end.
    pub fn next(self: *Canonical) ?u8 {
        if (self.pending_at < self.pending_end) {
            const byte = self.pending[self.pending_at];
            self.pending_at += 1;
            return byte;
        }
        if (self.index >= self.raw.len) return null;
        const byte = self.take();
        if (unreserved(byte)) return byte;
        self.pending = .{ '%', upper_hex[byte >> 4], upper_hex[byte & 0xf] };
        self.pending_end = 3;
        self.pending_at = 1;
        return '%';
    }

    /// The next raw byte, with a valid %XX decoded to the byte it names.
    fn take(self: *Canonical) u8 {
        if (self.index + 3 <= self.raw.len) {
            if (self.raw[self.index] == '%') {
                if (hexDigit(self.raw[self.index + 1])) |high| {
                    if (hexDigit(self.raw[self.index + 2])) |low| {
                        self.index += 3;
                        return (high << 4) | low;
                    }
                }
            }
        }
        const byte = self.raw[self.index];
        self.index += 1;
        return byte;
    }
};

fn hexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'A'...'F' => byte - 'A' + 10,
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

/// Compares the canonical forms of `a` and `b`, which is the order the
/// canonical query string sorts in.
pub fn order(a: []const u8, b: []const u8) std.math.Order {
    var left: Canonical = .init(a);
    var right: Canonical = .init(b);
    while (true) {
        const l = left.next();
        const r = right.next();
        if (l == null) {
            return if (r == null) .eq else .lt;
        }
        if (r == null) return .gt;
        if (l.? < r.?) return .lt;
        if (l.? > r.?) return .gt;
    }
}

test "every unreserved byte stays literal" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "abcXYZ019-._~");
    try testing.expectEqualStrings("abcXYZ019-._~", w.buffered());
}

test "a reserved byte uses uppercase hex" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "a b&c=d");
    try testing.expectEqualStrings("a%20b%26c%3Dd", w.buffered());
}

test "a written escape is decoded and re-encoded" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "a%20b%e1%88%B4");
    try testing.expectEqualStrings("a%20b%E1%88%B4", w.buffered());

    var other: [64]u8 = undefined;
    var w2: Writer = .fixed(&other);
    try writeQueryComponent(&w2, "%7e%2f%41%25");
    try testing.expectEqualStrings("~%2FA%25", w2.buffered());
}

test "a literal percent must arrive as an escape" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "100%");
    try testing.expectEqualStrings("100%25", w.buffered());

    var other: [64]u8 = undefined;
    var w2: Writer = .fixed(&other);
    try writeQueryComponent(&w2, "a%zz");
    try testing.expectEqualStrings("a%25zz", w2.buffered());
}

test "a path segment escapes everything else, the escape included" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writePathSegment(&w, "a%20b c");
    try testing.expectEqualStrings("a%2520b%20c", w.buffered());
}

test "a decoded byte and its escape compare equal" {
    try testing.expectEqual(std.math.Order.eq, order("a b", "a%20b"));
    try testing.expectEqual(std.math.Order.lt, order("%20", "a"));
    try testing.expectEqual(std.math.Order.gt, order("a", "%20"));
}

test "order reads canonical bytes, not raw ones" {
    // A raw '.' (0x2e) sorts before a raw '/' (0x2f), but '/' encodes to
    // '%2F', and '%' (0x25) sorts before '.'.
    try testing.expectEqual(std.math.Order.lt, order("/", "."));
    try testing.expectEqual(std.math.Order.gt, order(".", "/"));
}

test "an escape and the byte it names compare equal" {
    try testing.expectEqual(std.math.Order.eq, order("%2f", "%2F"));
    try testing.expectEqual(std.math.Order.eq, order("%7e", "~"));
    try testing.expectEqual(std.math.Order.eq, order("%41", "A"));
    try testing.expectEqual(std.math.Order.eq, order("%25", "%"));
}
