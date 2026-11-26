//! The guide's examples, compiled and run with the module's own test suite.
//! A guide page cannot show code that does not build.

const std = @import("std");
const testing = std.testing;

const sigv4 = @import("sigv4");

test "the request the signature covers" {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20150830T123600Z" },
    };

    const request: sigv4.canonical.Request = .{
        .method = "GET",
        .path = "/",
        .headers = &headers,
        .payload_hash = sigv4.empty_payload_hash,
    };

    var buffer: [1024]u8 = undefined;
    const canonical = try sigv4.canonical.writeRequest(&buffer, request);
    try testing.expectEqualStrings(
        "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n" ++
            "host;x-amz-date\n" ++ sigv4.empty_payload_hash,
        canonical,
    );
}

test "the path mode decides the canonical URI" {
    var service: [256]u8 = undefined;
    var unnormalized: [256]u8 = undefined;
    var s3: [256]u8 = undefined;

    // A wire path arrives already escaped. A service escapes it again.
    try testing.expectEqualStrings(
        "/a%2525b",
        try sigv4.canonical.writeUri(&service, "/a%25b", .service),
    );
    // S3 signs the wire path as it is.
    try testing.expectEqualStrings(
        "/a%25b",
        try sigv4.canonical.writeUri(&s3, "/a%25b", .s3),
    );
    // Only the service mode removes dot segments.
    try testing.expectEqualStrings(
        "/b",
        try sigv4.canonical.writeUri(&service, "/a/../b", .service),
    );
    try testing.expectEqualStrings(
        "/a/../b",
        try sigv4.canonical.writeUri(&unnormalized, "/a/../b", .unnormalized),
    );
}

test "the scope takes its date from the timestamp" {
    const scope = try sigv4.signing.Scope.init("20150830T123600Z", "us-east-1", "iam");
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "20150830/us-east-1/iam/aws4_request",
        try sigv4.signing.writeScope(&buffer, scope),
    );
    try testing.expectError(
        error.InvalidTimestamp,
        sigv4.signing.Scope.init("2015-08-30T12:36:00Z", "us-east-1", "iam"),
    );
}

test "the signing key is the documented vector" {
    const scope = try sigv4.signing.Scope.init("20150830T123600Z", "us-east-1", "iam");
    const key = sigv4.signing.signingKey(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        scope,
    );
    try testing.expectEqualStrings(
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
        &std.fmt.bytesToHex(key, .lower),
    );

    const mac = sigv4.signing.signature(key, "the string to sign");
    try testing.expectEqual(@as(usize, 32), mac.len);
}

test "write the Authorization field" {
    var headers = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-content-sha256", .value = sigv4.empty_payload_hash },
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var field: [1024]u8 = undefined;
    var creq: [2048]u8 = undefined;

    const value = try sigv4.signing.writeAuthorization(&field, &creq, .{
        .method = "GET",
        .path = "/",
        .path_mode = .s3,
        .headers = &headers,
        .payload_hash = sigv4.empty_payload_hash,
    }, .{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .timestamp = "20260826T000000Z",
    });

    try testing.expectEqualStrings(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260826/us-east-1/s3/aws4_request," ++
            " SignedHeaders=host;x-amz-content-sha256;x-amz-date," ++
            " Signature=42e3431ea83ebfba8aa2488a2fa9a07afae23a0fc658721ef9b2f105a0e9ab34",
        value,
    );
}

test "a request the signature cannot cover is refused" {
    var without_host = [_]sigv4.canonical.Header{
        .{ .name = "x-amz-date", .value = "20260826T000000Z" },
    };
    var buffer: [512]u8 = undefined;
    try testing.expectError(error.MissingHost, sigv4.canonical.writeRequest(&buffer, .{
        .method = "GET",
        .path = "/",
        .headers = &without_host,
        .payload_hash = sigv4.empty_payload_hash,
    }));

    var stale = [_]sigv4.canonical.Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20260826T000001Z" },
    };
    var field: [512]u8 = undefined;
    var creq: [1024]u8 = undefined;
    try testing.expectError(
        error.TimestampMismatch,
        sigv4.signing.writeAuthorization(&field, &creq, .{
            .method = "GET",
            .path = "/",
            .headers = &stale,
            .payload_hash = sigv4.empty_payload_hash,
        }, .{
            .access_key = "AKIDEXAMPLE",
            .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            .region = "us-east-1",
            .service = "service",
            .timestamp = "20260826T000000Z",
        }),
    );
}
