const std = @import("std");
const crypto = std.crypto;
const http = std.http;
const mem = std.mem;
const fmt = std.fmt;

const config_mod = @import("config.zig");
const encoding = @import("encoding.zig");

pub const OAuthTokens = struct {
    token: []const u8,
    token_secret: []const u8,
    verifier: ?[]const u8 = null,
};

pub fn createSignature(
    allocator: mem.Allocator,
    config: config_mod.Config,
    method: []const u8,
    url: []const u8,
    params: std.StringHashMap([]const u8),
) ![]u8 {
    // Create parameter string
    var param_list = std.ArrayList([]const u8).init(allocator);
    defer param_list.deinit();
    
    var param_iter = params.iterator();
    while (param_iter.next()) |entry| {
        const encoded_key = try encoding.percentEncode(allocator, entry.key_ptr.*);
        defer allocator.free(encoded_key);
        const encoded_value = try encoding.percentEncode(allocator, entry.value_ptr.*);
        defer allocator.free(encoded_value);
        
        const param = try fmt.allocPrint(allocator, "{s}={s}", .{ encoded_key, encoded_value });
        try param_list.append(param);
    }
    
    // Sort parameters
    const items = try param_list.toOwnedSlice();
    defer {
        for (items) |item| {
            allocator.free(item);
        }
        allocator.free(items);
    }
    std.mem.sort([]const u8, items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    
    // Join parameters
    const param_string = try mem.join(allocator, "&", items);
    defer allocator.free(param_string);
    
    // Create signature base string
    const encoded_url = try encoding.percentEncode(allocator, url);
    defer allocator.free(encoded_url);
    const encoded_params = try encoding.percentEncode(allocator, param_string);
    defer allocator.free(encoded_params);
    
    const base_string = try fmt.allocPrint(allocator, "{s}&{s}&{s}", .{ method, encoded_url, encoded_params });
    defer allocator.free(base_string);
    
    // Create signing key
    const encoded_secret = try encoding.percentEncode(allocator, config.api_secret);
    defer allocator.free(encoded_secret);
    const encoded_token_secret = try encoding.percentEncode(allocator, config.access_token_secret);
    defer allocator.free(encoded_token_secret);
    
    const signing_key = try fmt.allocPrint(allocator, "{s}&{s}", .{ encoded_secret, encoded_token_secret });
    defer allocator.free(signing_key);
    
    // Generate HMAC-SHA1 signature
    const HmacSha1 = crypto.auth.hmac.Hmac(crypto.hash.Sha1);
    var hmac = HmacSha1.init(signing_key);
    hmac.update(base_string);
    var signature: [HmacSha1.mac_length]u8 = undefined;
    hmac.final(&signature);
    
    // Base64 encode the signature
    const encoded = std.base64.standard.Encoder;
    const size = encoded.calcSize(signature.len);
    const result = try allocator.alloc(u8, size);
    _ = encoded.encode(result, &signature);
    
    return result;
}

pub fn createOAuthHeaderWithCallback(
    allocator: mem.Allocator,
    api_key: []const u8,
    api_secret: []const u8,
    method: []const u8,
    url: []const u8,
    callback: []const u8,
) ![]u8 {
    const timestamp = std.time.timestamp();
    const nonce = try encoding.generateNonce(allocator);
    defer allocator.free(nonce);
    
    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();
    
    const timestamp_str = try fmt.allocPrint(allocator, "{d}", .{timestamp});
    defer allocator.free(timestamp_str);
    
    try params.put("oauth_callback", callback);
    try params.put("oauth_consumer_key", api_key);
    try params.put("oauth_nonce", nonce);
    try params.put("oauth_signature_method", "HMAC-SHA1");
    try params.put("oauth_timestamp", timestamp_str);
    try params.put("oauth_version", "1.0");
    
    // Create config for signature
    const temp_config = config_mod.Config{
        .api_key = api_key,
        .api_secret = api_secret,
        .access_token = "",
        .access_token_secret = "",
    };
    
    const signature = try createSignature(allocator, temp_config, method, url, params);
    defer allocator.free(signature);
    
    const encoded_signature = try encoding.percentEncode(allocator, signature);
    defer allocator.free(encoded_signature);
    
    // Build OAuth header
    var header = std.ArrayList(u8).init(allocator);
    defer header.deinit();
    
    try header.appendSlice("OAuth ");
    try header.writer().print("oauth_callback=\"{s}\", ", .{callback});
    try header.writer().print("oauth_consumer_key=\"{s}\", ", .{api_key});
    try header.writer().print("oauth_nonce=\"{s}\", ", .{nonce});
    try header.appendSlice("oauth_signature_method=\"HMAC-SHA1\", ");
    try header.writer().print("oauth_signature=\"{s}\", ", .{encoded_signature});
    try header.writer().print("oauth_timestamp=\"{d}\", ", .{timestamp});
    try header.appendSlice("oauth_version=\"1.0\"");
    
    return header.toOwnedSlice();
}

pub fn createOAuthHeader(
    allocator: mem.Allocator,
    api_key: []const u8,
    api_secret: []const u8,
    token: ?[]const u8,
    token_secret: ?[]const u8,
    method: []const u8,
    url: []const u8,
    extra_params: ?std.StringHashMap([]const u8),
    verifier: ?[]const u8,
) ![]u8 {
    const timestamp = std.time.timestamp();
    const nonce = try encoding.generateNonce(allocator);
    defer allocator.free(nonce);
    
    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();
    
    const timestamp_str = try fmt.allocPrint(allocator, "{d}", .{timestamp});
    defer allocator.free(timestamp_str);
    
    try params.put("oauth_consumer_key", api_key);
    try params.put("oauth_nonce", nonce);
    try params.put("oauth_signature_method", "HMAC-SHA1");
    try params.put("oauth_timestamp", timestamp_str);
    if (token) |t| {
        try params.put("oauth_token", t);
    }
    if (verifier) |v| {
        try params.put("oauth_verifier", v);
    }
    try params.put("oauth_version", "1.0");
    
    // Add any extra params for signature
    if (extra_params) |extra| {
        var iter = extra.iterator();
        while (iter.next()) |entry| {
            try params.put(entry.key_ptr.*, entry.value_ptr.*);
        }
    }
    
    // Create config for signature
    const temp_config = config_mod.Config{
        .api_key = api_key,
        .api_secret = api_secret,
        .access_token = token orelse "",
        .access_token_secret = token_secret orelse "",
    };
    
    const signature = try createSignature(allocator, temp_config, method, url, params);
    defer allocator.free(signature);
    
    const encoded_signature = try encoding.percentEncode(allocator, signature);
    defer allocator.free(encoded_signature);
    
    // Build OAuth header
    var header = std.ArrayList(u8).init(allocator);
    defer header.deinit();
    
    try header.appendSlice("OAuth ");
    try header.writer().print("oauth_consumer_key=\"{s}\", ", .{api_key});
    try header.writer().print("oauth_nonce=\"{s}\", ", .{nonce});
    try header.appendSlice("oauth_signature_method=\"HMAC-SHA1\", ");
    try header.writer().print("oauth_signature=\"{s}\", ", .{encoded_signature});
    try header.writer().print("oauth_timestamp=\"{d}\", ", .{timestamp});
    if (token) |t| {
        try header.writer().print("oauth_token=\"{s}\", ", .{t});
    }
    if (verifier) |v| {
        try header.writer().print("oauth_verifier=\"{s}\", ", .{v});
    }
    try header.appendSlice("oauth_version=\"1.0\"");
    
    return header.toOwnedSlice();
}

pub fn parseOAuthResponse(allocator: mem.Allocator, response: []const u8) !OAuthTokens {
    var result = OAuthTokens{
        .token = "",
        .token_secret = "",
        .verifier = null,
    };
    
    var pairs = mem.tokenizeScalar(u8, response, '&');
    while (pairs.next()) |pair| {
        var parts = mem.tokenizeScalar(u8, pair, '=');
        const key = parts.next() orelse continue;
        const value = parts.next() orelse continue;
        
        if (mem.eql(u8, key, "oauth_token")) {
            result.token = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, key, "oauth_token_secret")) {
            result.token_secret = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, key, "oauth_verifier")) {
            result.verifier = try allocator.dupe(u8, value);
        }
    }
    
    return result;
}

pub fn getRequestToken(allocator: mem.Allocator, api_key: []const u8, api_secret: []const u8) !OAuthTokens {
    const url = "https://api.twitter.com/oauth/request_token";
    
    // Don't pass oauth_callback as extra param, it goes in the OAuth header
    const auth_header = try createOAuthHeaderWithCallback(
        allocator,
        api_key,
        api_secret,
        "POST",
        url,
        "oob",
    );
    defer allocator.free(auth_header);
    
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    
    const uri = try std.Uri.parse(url);
    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth_header },
    };
    
    const server_header_buffer = try allocator.alloc(u8, 8192);
    defer allocator.free(server_header_buffer);
    
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = server_header_buffer,
        .extra_headers = &headers,
    });
    defer req.deinit();
    
    req.transfer_encoding = .{ .content_length = 0 };
    
    try req.send();
    try req.finish();
    try req.wait();
    
    if (req.response.status != .ok) {
        const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(response_body);
        
        std.debug.print("\n❌ Failed to get request token (HTTP {d})\n", .{@intFromEnum(req.response.status)});
        std.debug.print("Response: {s}\n\n", .{response_body});
        
        if (req.response.status == .unauthorized) {
            std.debug.print("Possible causes:\n", .{});
            std.debug.print("1. Incorrect API Key or API Secret\n", .{});
            std.debug.print("2. App doesn't have Read and Write permissions\n", .{});
            std.debug.print("3. OAuth 1.0a not enabled for your app\n", .{});
            std.debug.print("4. System clock is out of sync (OAuth requires accurate time)\n\n", .{});
            std.debug.print("Please check your app settings at https://developer.twitter.com\n", .{});
        }
        
        return error.RequestTokenFailed;
    }
    
    const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
    defer allocator.free(response_body);
    
    return try parseOAuthResponse(allocator, response_body);
}

pub fn getAccessToken(
    allocator: mem.Allocator,
    api_key: []const u8,
    api_secret: []const u8,
    request_token: []const u8,
    request_token_secret: []const u8,
    verifier: []const u8,
) !OAuthTokens {
    const url = "https://api.twitter.com/oauth/access_token";
    
    const auth_header = try createOAuthHeader(
        allocator,
        api_key,
        api_secret,
        request_token,
        request_token_secret,
        "POST",
        url,
        null,
        verifier,
    );
    defer allocator.free(auth_header);
    
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    
    const uri = try std.Uri.parse(url);
    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth_header },
    };
    
    const server_header_buffer = try allocator.alloc(u8, 8192);
    defer allocator.free(server_header_buffer);
    
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = server_header_buffer,
        .extra_headers = &headers,
    });
    defer req.deinit();
    
    req.transfer_encoding = .{ .content_length = 0 };
    
    try req.send();
    try req.finish();
    try req.wait();
    
    if (req.response.status != .ok) {
        const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(response_body);
        std.debug.print("Failed to get access token: {s}\n", .{response_body});
        return error.AccessTokenFailed;
    }
    
    const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
    defer allocator.free(response_body);
    
    return try parseOAuthResponse(allocator, response_body);
}

pub fn performOAuthFlowWithKeys(allocator: mem.Allocator, api_key: []const u8, api_secret: []const u8) !config_mod.Config {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    
    try stdout.print("\nGetting authorization URL...\n", .{});
    
    // Get request token
    const request_tokens = try getRequestToken(allocator, api_key, api_secret);
    defer allocator.free(request_tokens.token);
    defer allocator.free(request_tokens.token_secret);
    
    // Generate auth URL
    const auth_url = try fmt.allocPrint(allocator, 
        "https://api.twitter.com/oauth/authorize?oauth_token={s}", 
        .{request_tokens.token}
    );
    defer allocator.free(auth_url);
    
    try stdout.print("\n📱 Please visit this URL to authorize the app:\n", .{});
    try stdout.print("{s}\n\n", .{auth_url});
    try stdout.print("After authorizing, enter the PIN code shown: ", .{});
    
    const pin_buf = try allocator.alloc(u8, 32);
    const pin_len = try stdin.read(pin_buf);
    const pin = mem.trim(u8, pin_buf[0..pin_len], " \t\n\r");
    
    // Exchange for access tokens
    try stdout.print("\nExchanging for access tokens...\n", .{});
    const access_tokens = try getAccessToken(
        allocator,
        api_key,
        api_secret,
        request_tokens.token,
        request_tokens.token_secret,
        pin,
    );
    defer allocator.free(access_tokens.token);
    defer allocator.free(access_tokens.token_secret);
    
    const config = config_mod.Config{
        .api_key = try allocator.dupe(u8, api_key),
        .api_secret = try allocator.dupe(u8, api_secret),
        .access_token = try allocator.dupe(u8, access_tokens.token),
        .access_token_secret = try allocator.dupe(u8, access_tokens.token_secret),
    };
    
    // Save config
    try config_mod.saveConfig(allocator, config);
    try stdout.print("✅ Configuration saved to ~/.config/tweet/config\n\n", .{});
    
    return config;
}

test "parseOAuthResponse" {
    const allocator = std.testing.allocator;
    
    const response = "oauth_token=test_token&oauth_token_secret=test_secret&oauth_verifier=test_verifier";
    const tokens = try parseOAuthResponse(allocator, response);
    defer {
        allocator.free(tokens.token);
        allocator.free(tokens.token_secret);
        if (tokens.verifier) |v| allocator.free(v);
    }
    
    try std.testing.expectEqualStrings("test_token", tokens.token);
    try std.testing.expectEqualStrings("test_secret", tokens.token_secret);
    try std.testing.expectEqualStrings("test_verifier", tokens.verifier.?);
}

test "parseOAuthResponse partial" {
    const allocator = std.testing.allocator;
    
    const response = "oauth_token=token1&oauth_token_secret=secret1";
    const tokens = try parseOAuthResponse(allocator, response);
    defer {
        allocator.free(tokens.token);
        allocator.free(tokens.token_secret);
        if (tokens.verifier) |v| allocator.free(v);
    }
    
    try std.testing.expectEqualStrings("token1", tokens.token);
    try std.testing.expectEqualStrings("secret1", tokens.token_secret);
    try std.testing.expect(tokens.verifier == null);
}