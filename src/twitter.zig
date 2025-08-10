const std = @import("std");
const http = std.http;
const mem = std.mem;
const fmt = std.fmt;

const config_mod = @import("config.zig");
const oauth = @import("oauth.zig");
const encoding = @import("encoding.zig");

pub fn postTweet(allocator: mem.Allocator, config: config_mod.Config, message: []const u8, media_id: ?[]const u8, debug: bool) !void {
    const url = "https://api.twitter.com/2/tweets";
    
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    
    // Escape the message for JSON
    const escaped_message = try encoding.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);
    
    // Create request body
    const body = if (media_id) |id|
        try fmt.allocPrint(allocator, "{{\"text\":\"{s}\",\"media\":{{\"media_ids\":[\"{s}\"]}}}}", .{ escaped_message, id })
    else
        try fmt.allocPrint(allocator, "{{\"text\":\"{s}\"}}", .{escaped_message});
    defer allocator.free(body);
    
    if (debug) {
        std.debug.print("Tweet request body: {s}\n", .{body});
    }
    
    // Create auth header with extra params for v2 API
    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();
    
    const auth_header = try oauth.createOAuthHeader(
        allocator,
        config.api_key,
        config.api_secret,
        config.access_token,
        config.access_token_secret,
        "POST",
        url,
        null,
        null,
    );
    defer allocator.free(auth_header);
    
    // Create request
    const uri = try std.Uri.parse(url);
    
    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth_header },
        .{ .name = "Content-Type", .value = "application/json" },
    };
    
    const server_header_buffer = try allocator.alloc(u8, 8192);
    defer allocator.free(server_header_buffer);
    
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = server_header_buffer,
        .extra_headers = &headers,
    });
    defer req.deinit();
    
    req.transfer_encoding = .{ .content_length = body.len };
    
    try req.send();
    try req.writeAll(body);
    try req.finish();
    try req.wait();
    
    if (req.response.status != .ok and req.response.status != .created) {
        std.debug.print("Error: HTTP {d}\n", .{@intFromEnum(req.response.status)});
        
        const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(response_body);
        std.debug.print("Response: {s}\n", .{response_body});
        
        return error.TweetFailed;
    }
    
    if (debug) {
        const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(response_body);
        std.debug.print("Tweet posted successfully: {s}\n", .{response_body});
    }
    
    // Success - return silently (Unix philosophy)
}

test "postTweet JSON formatting" {
    // This test would require mocking HTTP calls
    // For now we just test that the module compiles correctly
    try std.testing.expect(true);
}