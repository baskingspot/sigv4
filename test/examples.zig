//! The README's example and the public surface, compiled against the module
//! with the rest of the tests. The README cannot show code that does not
//! build.

const std = @import("std");
const testing = std.testing;

const sigv4 = @import("sigv4");

/// Writes the Authorization field value for a signed GET. This is the README's
/// example.
fn authorize(
    field: []u8,
    creq: []u8,
    headers: []sigv4.canonical.Header,
) sigv4.signing.SignError![]const u8 {
    return sigv4.signing.writeAuthorization(field, creq, .{
        .method = "GET",
        .path = "/",
        .headers = headers,
        .payload_hash = sigv4.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
    });
}

test "the README example" {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var field: [512]u8 = undefined;
    var creq: [2048]u8 = undefined;

    const value = try authorize(&field, &creq, &headers);
    try testing.expectEqualStrings(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260826/us-east-1/s3/aws4_request," ++
            " SignedHeaders=host;x-amz-date," ++
            " Signature=89d28d8013f53cb672ecb1a68b8eddd43ef86619e53a64a94dbd72012b17c17f",
        value,
    );
}

test "build the four stages by hand" {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var creq: [2048]u8 = undefined;

    const canonical = try sigv4.canonical.writeRequest(&creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = sigv4.empty_payload_hash,
    });

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical, &digest, .{});

    const scope = try sigv4.signing.Scope.init("20260826T000000Z", "us-east-1", "s3");
    var sts_buffer: [512]u8 = undefined;
    const string_to_sign = try sigv4.signing.writeStringToSign(&sts_buffer, "20260826T000000Z", scope, digest);

    const secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const key = sigv4.signing.signingKey(secret_access_key, scope);
    const mac = sigv4.signing.signature(key, string_to_sign);
    try testing.expectEqual(@as(usize, 64), std.fmt.bytesToHex(mac, .lower).len);
}

test "a session token joins the signature" {
    const access_key = "AKIDEXAMPLE";
    const secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const token = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4F";

    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var field: [1024]u8 = undefined;
    var creq: [2048]u8 = undefined;

    const value = try sigv4.signing.writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = sigv4.empty_payload_hash,
    }, .{
        .access_key = access_key,
        .secret_key = secret_access_key,
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
        .session_token = token,
    });

    try testing.expect(std.mem.indexOf(u8, value, "x-amz-security-token") != null);
}

test "a header you do not list is not signed" {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };

    // The HTTP client also sends `user-agent`. It is not in this slice, so the
    // canonical request does not carry it and the signature does not cover it.
    // A header that is sent and not signed is the caller's choice, and this is
    // how the caller makes it.
    var buffer: [1024]u8 = undefined;
    const canonical = try sigv4.canonical.writeRequest(&buffer, .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = sigv4.empty_payload_hash,
    });

    try testing.expect(std.mem.indexOf(u8, canonical, "user-agent") == null);
    try testing.expect(std.mem.startsWith(u8, canonical, "GET\n/\n\nhost:example.amazonaws.com"));
}

test "the query is sorted after it is encoded" {
    var params = [_]sigv4.canonical.Param{
        .{ .name = "b", .value = "2" },
        .{ .name = "a b", .value = "" },
        .{ .name = "a", .value = "1" },
    };
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "a=1&a%20b=&b=2",
        try sigv4.canonical.writeQuery(&buffer, &params),
    );
}
