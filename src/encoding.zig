const std = @import("std");
const mem = std.mem;

pub fn percentEncode(allocator: mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (input) |byte| {
        if ((byte >= 'A' and byte <= 'Z') or
            (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '-' or byte == '_' or byte == '.' or byte == '~')
        {
            try result.append(byte);
        } else {
            try result.writer().print("%{X:0>2}", .{byte});
        }
    }

    return result.toOwnedSlice();
}

pub fn jsonEscape(allocator: mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (input) |byte| {
        switch (byte) {
            '"' => try result.appendSlice("\\\""),
            '\\' => try result.appendSlice("\\\\"),
            '\n' => try result.appendSlice("\\n"),
            '\r' => try result.appendSlice("\\r"),
            '\t' => try result.appendSlice("\\t"),
            0x08 => try result.appendSlice("\\b"), // backspace
            0x0C => try result.appendSlice("\\f"), // form feed
            0x00...0x07, 0x0B, 0x0E...0x1F => {
                // Other control characters
                try result.writer().print("\\u{X:0>4}", .{byte});
            },
            else => try result.append(byte),
        }
    }

    return result.toOwnedSlice();
}

pub fn generateNonce(allocator: mem.Allocator) ![]u8 {
    var seed: u64 = @intCast(std.time.timestamp());
    seed ^= @intCast(std.time.nanoTimestamp() & 0xFFFFFFFF);
    var rng = std.Random.DefaultPrng.init(seed);
    const random = rng.random();
    
    var nonce: [16]u8 = undefined;
    random.bytes(&nonce);
    
    const encoded = std.base64.standard.Encoder;
    const size = encoded.calcSize(nonce.len);
    const temp_result = try allocator.alloc(u8, size);
    defer allocator.free(temp_result);
    _ = encoded.encode(temp_result, &nonce);
    
    // Count non-alphanumeric characters
    var count: usize = 0;
    for (temp_result) |c| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9')) {
            count += 1;
        }
    }
    
    // Allocate exact size and copy
    const result = try allocator.alloc(u8, count);
    var i: usize = 0;
    for (temp_result) |c| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9')) {
            result[i] = c;
            i += 1;
        }
    }
    
    return result;
}

test "percentEncode basic" {
    const allocator = std.testing.allocator;
    
    const result = try percentEncode(allocator, "Hello World!");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello%20World%21", result);
}

test "percentEncode safe characters" {
    const allocator = std.testing.allocator;
    
    const result = try percentEncode(allocator, "ABCabc123-_.~");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("ABCabc123-_.~", result);
}

test "percentEncode special characters" {
    const allocator = std.testing.allocator;
    
    const result = try percentEncode(allocator, "!@#$%^&*()+=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("%21%40%23%24%25%5E%26%2A%28%29%2B%3D", result);
}

test "jsonEscape quotes and backslashes" {
    const allocator = std.testing.allocator;
    
    const result = try jsonEscape(allocator, "Hello \"World\" \\ Test");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello \\\"World\\\" \\\\ Test", result);
}

test "jsonEscape newlines and tabs" {
    const allocator = std.testing.allocator;
    
    const result = try jsonEscape(allocator, "Line1\nLine2\tTabbed");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Line1\\nLine2\\tTabbed", result);
}

test "jsonEscape control characters" {
    const allocator = std.testing.allocator;
    
    const input = [_]u8{ 'T', 'e', 's', 't', 0x00, 0x1F };
    const result = try jsonEscape(allocator, &input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Test\\u0000\\u001F", result);
}

test "generateNonce creates alphanumeric string" {
    const allocator = std.testing.allocator;
    
    const nonce1 = try generateNonce(allocator);
    defer allocator.free(nonce1);
    const nonce2 = try generateNonce(allocator);
    defer allocator.free(nonce2);
    
    // Check that nonces are different
    try std.testing.expect(!mem.eql(u8, nonce1, nonce2));
    
    // Check that nonces contain only alphanumeric characters
    for (nonce1) |c| {
        try std.testing.expect((c >= 'A' and c <= 'Z') or 
                               (c >= 'a' and c <= 'z') or 
                               (c >= '0' and c <= '9'));
    }
}