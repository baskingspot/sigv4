//! The signing path's benchmarks: the canonical request at a few header
//! counts, the key chain, the Authorization field end to end, and a presigned
//! query. They are regression detectors, not claims: the work is dominated by
//! SHA-256 and HMAC, which `std.crypto` owns, and no second SigV4 signer runs
//! here to compare against.
//!
//! Run with `just bench`, or pass arguments to the runner:
//! `just bench -- --benchtime=250ms --filter=Sigv4`.

const std = @import("std");

const testingx = @import("testingx");

const sigv4 = @import("sigv4");

/// The suite root the generated bench main calls: every row in this file,
/// registered by name so the report reads `BenchmarkCanonicalRequest` and not
/// a module path.
pub fn benchmarkMain(b: *testingx.B) !void {
    try b.add("CanonicalRequest", benchmarkCanonicalRequest);
    try b.add("SigningKey", benchmarkSigningKey);
    try b.add("Authorization", benchmarkAuthorization);
    try b.add("Presign", benchmarkPresign);
}

const header_count = 8;

/// A request shape a client sends: host, the signing date, the payload hash,
/// and the headers a real request carries. `writeRequest` sorts the slice in
/// place, so each iteration starts from the template.
const header_template = [header_count]sigv4.canonical.Header{
    .{ .name = "host", .value = "s3.us-east-1.amazonaws.com" },
    .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    .{ .name = "x-amz-content-sha256", .value = sigv4.empty_payload_hash },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-length", .value = "512" },
    .{ .name = "user-agent", .value = "sigv4-bench/0.1" },
    .{ .name = "accept", .value = "application/json" },
    .{ .name = "x-amz-target", .value = "AmazonS3.GetObject" },
};

const credentials: sigv4.signing.Credentials = .{
    .access_key = "AKIDEXAMPLE",
    .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    .region = "us-east-1",
    .service = "service",
    .timestamp = "20260826T000000Z",
};

pub fn benchmarkCanonicalRequest(b: *testingx.B) !void {
    var sink: usize = 0;
    defer b.keepAlive(sink);
    var buffer: [4096]u8 = undefined;
    while (try b.loop()) {
        var headers = b.blackBox(header_template);
        const canonical = try sigv4.canonical.writeRequest(&buffer, .{
            .method = "GET",
            .path = "/",
            .headers = &headers,
            .payload_hash = sigv4.empty_payload_hash,
        });
        sink +%= canonical.len;
    }
}

pub fn benchmarkSigningKey(b: *testingx.B) !void {
    const scope = try sigv4.signing.Scope.init(
        credentials.timestamp,
        credentials.region,
        credentials.service,
    );
    var sink: u64 = 0;
    defer b.keepAlive(sink);
    while (try b.loop()) {
        const key = sigv4.signing.signingKey(b.blackBox(credentials.secret_key), scope);
        sink ^= memToInt(key);
    }
}

pub fn benchmarkAuthorization(b: *testingx.B) !void {
    var sink: usize = 0;
    defer b.keepAlive(sink);
    var field: [1024]u8 = undefined;
    var creq: [4096]u8 = undefined;
    while (try b.loop()) {
        var headers = b.blackBox(header_template);
        const value = try sigv4.signing.writeAuthorization(&field, &creq, .{
            .method = "GET",
            .path = "/",
            .headers = &headers,
            .payload_hash = sigv4.empty_payload_hash,
        }, credentials);
        sink +%= value.len;
    }
}

pub fn benchmarkPresign(b: *testingx.B) !void {
    var sink: usize = 0;
    defer b.keepAlive(sink);
    var query: [4096]u8 = undefined;
    while (try b.loop()) {
        // Host alone: a presigned URL signs the headers the recipient sends.
        var headers = [_]sigv4.canonical.Header{
            .{ .name = "host", .value = "s3.us-east-1.amazonaws.com" },
        };
        const value = try sigv4.signing.presign(&query, .{
            .method = "GET",
            .path = "/bucket/key",
            .headers = &headers,
            .payload_hash = "UNSIGNED-PAYLOAD",
        }, credentials, .{ .expires_seconds = 3600 });
        sink +%= value.len;
    }
}

fn memToInt(bytes: [32]u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .little);
}
