//! The percent-encoding rules the canonical request stands on. A byte outside
//! the unreserved set becomes %XX with uppercase hex digits, which is the one
//! thing every AWS SDK agrees on.

const std = @import("std");

const Writer = std.Io.Writer;

const upper_hex = "0123456789ABCDEF";

/// True for `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`, `_`, and `~`.
pub fn unreserved(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// Writes one query name or value in canonical form: a valid %XX triplet is
/// decoded first and then re-encoded, so the wire form and the decoded form
/// land on the same bytes.
pub fn writeQueryComponent(w: *Writer, bytes: []const u8) Writer.Error!void {
    var encoded: Encoded = .init(bytes);
    while (encoded.next()) |byte| try w.writeByte(byte);
}

/// Writes a raw path with its `/` separators left literal. Every other byte
/// outside the unreserved set is escaped, `%` included: a path that arrives
/// percent-encoded comes out encoded twice, which is what the signature wants.
pub fn writePath(w: *Writer, path: []const u8) Writer.Error!void {
    for (path) |byte| {
        if (byte == '/' or unreserved(byte)) {
            try w.writeByte(byte);
        } else {
            try writeEscape(w, byte);
        }
    }
}

/// Writes one raw path segment, a path with no `/` in it.
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

/// The canonical encoded form of `raw`, one byte at a time. A valid %XX
/// triplet is decoded before it is re-encoded, so `a%20b`, `a b`, and
/// `a%20%62` all yield the same stream. An invalid triplet is literal bytes.
pub const Encoded = struct {
    raw: []const u8,
    index: usize = 0,
    pending: [3]u8 = undefined,
    pending_end: u8 = 0,
    pending_at: u8 = 0,

    pub fn init(raw: []const u8) Encoded {
        return .{ .raw = raw };
    }

    /// The next byte of the encoded form, or null at the end.
    pub fn next(self: *Encoded) ?u8 {
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

    fn take(self: *Encoded) u8 {
        if (self.index + 3 <= self.raw.len) {
            if (self.raw[self.index] == '%') {
                if (digit(self.raw[self.index + 1])) |high| {
                    if (digit(self.raw[self.index + 2])) |low| {
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

/// Compares the canonical encoded forms of `a` and `b`, which is the order the
/// canonical query string sorts in.
pub fn order(a: []const u8, b: []const u8) std.math.Order {
    var left: Encoded = .init(a);
    var right: Encoded = .init(b);
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

fn digit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'A'...'F' => byte - 'A' + 10,
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

test "every unreserved byte stays literal" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "abcXYZ019-._~");
    try std.testing.expectEqualStrings("abcXYZ019-._~", w.buffered());
}

test "reserved bytes use uppercase hex" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "a b/c&d=e%f");
    try std.testing.expectEqualStrings("a%20b%2Fc%26d%3De%25f", w.buffered());
}

test "a path keeps its separators" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writePath(&w, "/example space/");
    try std.testing.expectEqualStrings("/example%20space/", w.buffered());
}

test "a triplet is decoded before it is encoded" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try writeQueryComponent(&w, "%e1%88%B4");
    try std.testing.expectEqualStrings("%E1%88%B4", w.buffered());
}

test "an encoded and a decoded byte compare equal" {
    try std.testing.expectEqual(std.math.Order.eq, order("a b", "a%20b"));
    try std.testing.expectEqual(std.math.Order.lt, order("%20", "a"));
    try std.testing.expectEqual(std.math.Order.gt, order("a", "%20"));
}

test "order reads encoded bytes, not raw ones" {
    // A raw '.' (0x2e) sorts before a raw '/' (0x2f), but '/' encodes to
    // '%2F', and '%' (0x25) sorts before '.'.
    try std.testing.expectEqual(std.math.Order.lt, order("/", "."));
    try std.testing.expectEqual(std.math.Order.gt, order(".", "/"));
}

test "an invalid triplet is literal" {
    try std.testing.expectEqual(std.math.Order.eq, order("%zz", "%25zz"));
    try std.testing.expectEqual(std.math.Order.eq, order("%2", "%252"));
}
