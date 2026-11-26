//! Runs the AWS signing test suite and the reference vectors through the
//! public module.
//!
//! Both roots use the suite's file layout: `request.txt` is the request as
//! sent, `context.json` the credentials and the time, and one `header-` or
//! `query-` triple holds the expected canonical request, string to sign, and
//! signature. The runner builds the signer's input from those files: the
//! headers named in `SignedHeaders`, the query from the target, and the
//! payload hash the context asks for. A session token in the context reaches
//! the signer as a credential, never as a header line, so the injection path
//! is what the suite checks.
//!
//! The files are read at run time with the working directory at the build
//! root, so a fixture added to a root runs without touching this file.

const std = @import("std");
const testing = std.testing;
const sigv4 = @import("sigv4");

const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const suite_root = "test/fixtures/aws-signing-suite/v4";
const vector_root = "test/fixtures/vectors/v4";

const max_file = 1 << 20;

test "the AWS suite and the reference vectors" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var suite_variants: u32 = 0;
    const suite_cases = try runRoot(testing.io, arena, suite_root, &suite_variants);
    var vector_variants: u32 = 0;
    const vector_cases = try runRoot(testing.io, arena, vector_root, &vector_variants);

    // Every suite case signs a header request and a presigned one; every
    // reference vector has the header form only. A case with neither is a
    // case the runner skipped, which is how a renamed file would hide.
    try testing.expectEqual(suite_cases * 2, suite_variants);
    try testing.expectEqual(vector_cases, vector_variants);
}

fn runRoot(io: Io, arena: Allocator, root_path: []const u8, variants: *u32) !u32 {
    var root = try Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);

    var cases: u32 = 0;
    var entries = root.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var dir = try root.openDir(io, entry.name, .{});
        defer dir.close(io);
        try runCase(io, arena, dir, entry.name, variants);
        cases += 1;
    }
    try testing.expect(cases > 0);
    return cases;
}

fn runCase(io: Io, arena: Allocator, dir: Io.Dir, name: []const u8, variants: *u32) !void {
    errdefer std.debug.print("fixture {s} failed\n", .{name});

    const wire = try parseRequest(arena, try readIn(io, dir, arena, "request.txt"));
    const context = try parseContext(arena, try readIn(io, dir, arena, "context.json"));
    const payload_hash = try payloadHash(arena, wire.body, context.sign_body);

    if (try runVariant(io, arena, dir, .header, wire, context, payload_hash)) variants.* += 1;
    if (try runVariant(io, arena, dir, .query, wire, context, payload_hash)) variants.* += 1;
}

const Kind = enum { header, query };

fn runVariant(
    io: Io,
    arena: Allocator,
    dir: Io.Dir,
    kind: Kind,
    wire: Wire,
    context: Context,
    payload_hash: []const u8,
) !bool {
    const prefix = if (kind == .header) "header-" else "query-";
    const expected_canonical = try readOptional(io, dir, arena, try joined(arena, prefix, "canonical-request.txt")) orelse
        return false;
    const expected_string = try readIn(io, dir, arena, try joined(arena, prefix, "string-to-sign.txt"));
    const expected_signature = try readIn(io, dir, arena, try joined(arena, prefix, "signature.txt"));

    const signed_name = if (kind == .header) "header-signed-request.txt" else "query-signed-request.txt";
    const signed = try parseRequest(arena, try readIn(io, dir, arena, signed_name));

    // The signed request is the signer's input: its target carries the query
    // the caller asked to sign, and its headers are the ones sent.
    const path = if (kind == .header) wire.path else signed.path;
    const params = if (kind == .header)
        try parseQuery(arena, wire.query)
    else
        try presignedParams(arena, signed.query, context.session_token != null);

    const names = if (kind == .header)
        try signedNames(
            arena,
            headerValue(signed.headers, "authorization") orelse return error.NoAuthorization,
        )
    else
        try presignedNames(arena, params);

    const headers = try selectHeaders(arena, wire.headers, signed.headers, names);
    const request: sigv4.canonical.Request = .{
        .method = wire.method,
        .path = path,
        .query = params,
        .headers = headers,
        .payload_hash = payload_hash,
        .path_mode = context.path_mode,
    };

    // A token from the context is not a header line in the wire request; the
    // signer takes it out of band, the same way `writeAuthorization` does.
    // A presigned target carries the token as a query parameter instead.
    const extra: ?sigv4.canonical.Header = if (kind == .header)
        if (context.session_token) |credential_token|
            .{ .name = sigv4.signing.session_token_header, .value = credential_token }
        else
            null
    else
        null;

    var creq_buffer: [16 * 1024]u8 = undefined;
    const canonical = try sigv4.canonical.writeRequestWith(&creq_buffer, request, extra);
    try testing.expectEqualStrings(expected_canonical, canonical);

    var digest: [32]u8 = undefined;
    Sha256.hash(canonical, &digest, .{});
    const scope = try sigv4.signing.Scope.init(context.timestamp, context.region, context.service);

    var string_buffer: [1024]u8 = undefined;
    const string_to_sign = try sigv4.signing.writeStringToSign(&string_buffer, context.timestamp, scope, digest);
    try testing.expectEqualStrings(expected_string, string_to_sign);

    const key = sigv4.signing.signingKey(context.secret_key, scope);
    const mac = sigv4.signing.signature(key, string_to_sign);
    try testing.expectEqualStrings(expected_signature, &std.fmt.bytesToHex(mac, .lower));

    if (kind == .header) {
        const credentials: sigv4.signing.Credentials = .{
            .access_key = context.access_key,
            .secret_key = context.secret_key,
            .region = context.region,
            .service = context.service,
            .timestamp = context.timestamp,
            .session_token = context.session_token,
        };
        var field_buffer: [2048]u8 = undefined;
        const field = try sigv4.signing.writeAuthorization(&field_buffer, &creq_buffer, request, credentials);
        const expected_field = headerValue(signed.headers, "authorization") orelse return error.NoAuthorization;
        try testing.expectEqualStrings(expected_field, field);
    }
    return true;
}

/// The session token never arrives as a header line in these fixtures; it is a
/// credential. Every other signed header is selected in the order it arrived,
/// duplicates included.
fn selectHeaders(
    arena: Allocator,
    wire: []const Header,
    signed: []const Header,
    names: []const []const u8,
) ![]sigv4.canonical.Header {
    var source: std.ArrayList(Header) = .empty;
    try source.appendSlice(arena, wire);
    for (signed) |header| {
        if (!hasHeader(source.items, header.name)) try source.append(arena, header);
    }

    var selected: std.ArrayList(sigv4.canonical.Header) = .empty;
    for (names) |name| {
        if (std.ascii.eqlIgnoreCase(name, sigv4.signing.session_token_header)) continue;
        var found = false;
        for (source.items) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
            try selected.append(arena, .{ .name = name, .value = header.value });
            found = true;
        }
        if (!found) return error.MissingSignedHeader;
    }
    return selected.toOwnedSlice(arena);
}

const Wire = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    headers: []Header,
    body: []const u8,
};

const Header = struct {
    name: []const u8,
    value: []const u8,
};

fn parseRequest(arena: Allocator, text: []const u8) !Wire {
    const head_end = std.mem.indexOf(u8, text, "\n\n") orelse text.len;
    const body = if (head_end < text.len) text[head_end + 2 ..] else text[text.len..];
    var lines = std.mem.splitScalar(u8, text[0..head_end], '\n');

    const request_line = std.mem.trimEnd(u8, lines.next() orelse return error.MalformedRequest, "\r");
    // The suite has targets with a raw space in the path, so the target runs
    // from the first space to the last one, not to the next word.
    const first = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.MalformedRequest;
    const version_at = std.mem.findScalarLast(u8, request_line, ' ') orelse return error.MalformedRequest;
    if (version_at <= first) return error.MalformedRequest;
    const method = request_line[0..first];
    const target = request_line[first + 1 .. version_at];

    var headers: std.ArrayList(Header) = .empty;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            if (headers.items.len == 0) return error.MalformedRequest;
            const last = &headers.items[headers.items.len - 1];
            const continuation = std.mem.trim(u8, line, " \t");
            last.value = try std.mem.concat(arena, u8, &.{ last.value, " ", continuation });
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedRequest;
        try headers.append(arena, .{ .name = line[0..colon], .value = line[colon + 1 ..] });
    }

    const question = std.mem.indexOfScalar(u8, target, '?');
    return .{
        .method = method,
        .path = if (question) |index| target[0..index] else target,
        .query = if (question) |index| target[index + 1 ..] else "",
        .headers = try headers.toOwnedSlice(arena),
        .body = body,
    };
}

fn parseQuery(arena: Allocator, query: []const u8) ![]sigv4.canonical.Param {
    var params: std.ArrayList(sigv4.canonical.Param) = .empty;
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        if (pair.len == 0) continue;
        const equals = std.mem.indexOfScalar(u8, pair, '=');
        if (equals) |index| {
            try params.append(arena, .{ .name = pair[0..index], .value = pair[index + 1 ..] });
        } else {
            try params.append(arena, .{ .name = pair, .value = "" });
        }
    }
    return params.toOwnedSlice(arena);
}

/// The presigned target carries the signature that is being computed, so the
/// canonical query string is over the parameters that are not it. A token the
/// context omits is not signed and is dropped the same way; the fixture URL
/// may still carry it.
fn presignedParams(arena: Allocator, query: []const u8, with_token: bool) ![]sigv4.canonical.Param {
    var kept: std.ArrayList(sigv4.canonical.Param) = .empty;
    for (try parseQuery(arena, query)) |param| {
        if (std.mem.eql(u8, param.name, "X-Amz-Signature")) continue;
        if (!with_token and std.mem.eql(u8, param.name, "X-Amz-Security-Token")) continue;
        try kept.append(arena, param);
    }
    return kept.toOwnedSlice(arena);
}

const Context = struct {
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8,
    service: []const u8,
    timestamp: []const u8,
    session_token: ?[]const u8,
    path_mode: sigv4.canonical.PathMode,
    sign_body: bool,
};

fn parseContext(arena: Allocator, text: []const u8) !Context {
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    const root = parsed.object;

    const credentials = (root.get("credentials") orelse return error.MalformedContext).object;
    const timestamp = (root.get("timestamp") orelse return error.MalformedContext).string;

    // `omit_session_token` keeps a token in the credentials but out of the
    // signature, which is the case where a caller rotates a credential early.
    const omit = root.get("omit_session_token") orelse std.json.Value{ .bool = false };
    const session_token = if (omit.bool)
        null
    else if (credentials.get("token")) |value| value.string else null;

    const normalize = (root.get("normalize") orelse return error.MalformedContext).bool;
    const path_mode = if (root.get("path_mode")) |value|
        try parsePathMode(value.string)
    else if (normalize)
        sigv4.canonical.PathMode.service
    else
        sigv4.canonical.PathMode.unnormalized;

    return .{
        .access_key = (credentials.get("access_key_id") orelse return error.MalformedContext).string,
        .secret_key = (credentials.get("secret_access_key") orelse return error.MalformedContext).string,
        .region = (root.get("region") orelse return error.MalformedContext).string,
        .service = (root.get("service") orelse return error.MalformedContext).string,
        .timestamp = try basicTimestamp(arena, timestamp),
        .session_token = session_token,
        .path_mode = path_mode,
        .sign_body = (root.get("sign_body") orelse return error.MalformedContext).bool,
    };
}

fn parsePathMode(name: []const u8) !sigv4.canonical.PathMode {
    if (std.mem.eql(u8, name, "service")) return .service;
    if (std.mem.eql(u8, name, "unnormalized")) return .unnormalized;
    if (std.mem.eql(u8, name, "s3")) return .s3;
    return error.MalformedContext;
}

fn basicTimestamp(arena: Allocator, iso: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (iso) |byte| {
        if (byte == '-' or byte == ':') continue;
        try out.append(arena, byte);
    }
    return out.toOwnedSlice(arena);
}

fn payloadHash(arena: Allocator, body: []const u8, sign_body: bool) ![]const u8 {
    if (!sign_body) return sigv4.empty_payload_hash;
    var digest: [32]u8 = undefined;
    Sha256.hash(body, &digest, .{});
    return arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn signedNames(arena: Allocator, authorization: []const u8) ![]const []const u8 {
    const marker = "SignedHeaders=";
    const start = std.mem.indexOf(u8, authorization, marker) orelse return error.NoSignedHeaders;
    const rest = authorization[start + marker.len ..];
    const end = std.mem.indexOf(u8, rest, ", ") orelse rest.len;
    return splitNames(arena, rest[0..end]);
}

fn splitNames(arena: Allocator, names: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var parts = std.mem.splitScalar(u8, names, ';');
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        try list.append(arena, part);
    }
    return list.toOwnedSlice(arena);
}

fn presignedNames(arena: Allocator, params: []const sigv4.canonical.Param) ![]const []const u8 {
    for (params) |param| {
        if (!std.mem.eql(u8, param.name, "X-Amz-SignedHeaders")) continue;
        return splitNames(arena, try percentDecode(arena, param.value));
    }
    return error.NoSignedHeaders;
}

fn percentDecode(arena: Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < text.len) {
        if (text[index] == '%' and index + 3 <= text.len) {
            const high = hexDigit(text[index + 1]);
            const low = hexDigit(text[index + 2]);
            if (high != null and low != null) {
                try out.append(arena, (high.? << 4) | low.?);
                index += 3;
                continue;
            }
        }
        try out.append(arena, text[index]);
        index += 1;
    }
    return out.toOwnedSlice(arena);
}

fn hexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'A'...'F' => byte - 'A' + 10,
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

fn headerValue(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn hasHeader(headers: []const Header, name: []const u8) bool {
    return headerValue(headers, name) != null;
}

fn readIn(io: Io, dir: Io.Dir, arena: Allocator, name: []const u8) ![]u8 {
    return dir.readFileAlloc(io, name, arena, .limited(max_file));
}

fn readOptional(io: Io, dir: Io.Dir, arena: Allocator, name: []const u8) !?[]u8 {
    return readIn(io, dir, arena, name) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn joined(arena: Allocator, prefix: []const u8, suffix: []const u8) ![]const u8 {
    return std.mem.concat(arena, u8, &.{ prefix, suffix });
}
