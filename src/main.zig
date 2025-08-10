const std = @import("std");
const crypto = std.crypto;
const http = std.http;
const mem = std.mem;
const fmt = std.fmt;

const Config = struct {
    api_key: []const u8,
    api_secret: []const u8,
    access_token: []const u8,
    access_token_secret: []const u8,
};

const MediaUploadResponse = struct {
    media_id_string: []const u8,
};

const OAuthTokens = struct {
    token: []const u8,
    token_secret: []const u8,
    verifier: ?[]const u8 = null,
};

fn percentEncode(allocator: mem.Allocator, input: []const u8) ![]u8 {
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

fn jsonEscape(allocator: mem.Allocator, input: []const u8) ![]u8 {
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

fn generateNonce(allocator: mem.Allocator) ![]u8 {
    var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
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

fn createSignature(
    allocator: mem.Allocator,
    config: Config,
    method: []const u8,
    url: []const u8,
    params: std.StringHashMap([]const u8),
) ![]u8 {
    // Create parameter string
    var param_list = std.ArrayList([]const u8).init(allocator);
    defer param_list.deinit();
    
    var param_iter = params.iterator();
    while (param_iter.next()) |entry| {
        const encoded_key = try percentEncode(allocator, entry.key_ptr.*);
        defer allocator.free(encoded_key);
        const encoded_value = try percentEncode(allocator, entry.value_ptr.*);
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
    const encoded_url = try percentEncode(allocator, url);
    defer allocator.free(encoded_url);
    const encoded_params = try percentEncode(allocator, param_string);
    defer allocator.free(encoded_params);
    
    const base_string = try fmt.allocPrint(allocator, "{s}&{s}&{s}", .{ method, encoded_url, encoded_params });
    defer allocator.free(base_string);
    
    // Create signing key
    const encoded_secret = try percentEncode(allocator, config.api_secret);
    defer allocator.free(encoded_secret);
    const encoded_token_secret = try percentEncode(allocator, config.access_token_secret);
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

fn createOAuthHeaderWithCallback(
    allocator: mem.Allocator,
    api_key: []const u8,
    api_secret: []const u8,
    method: []const u8,
    url: []const u8,
    callback: []const u8,
) ![]u8 {
    const timestamp = std.time.timestamp();
    const nonce = try generateNonce(allocator);
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
    const temp_config = Config{
        .api_key = api_key,
        .api_secret = api_secret,
        .access_token = "",
        .access_token_secret = "",
    };
    
    const signature = try createSignature(allocator, temp_config, method, url, params);
    defer allocator.free(signature);
    
    const encoded_signature = try percentEncode(allocator, signature);
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

fn createOAuthHeader(
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
    const nonce = try generateNonce(allocator);
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
    const temp_config = Config{
        .api_key = api_key,
        .api_secret = api_secret,
        .access_token = token orelse "",
        .access_token_secret = token_secret orelse "",
    };
    
    const signature = try createSignature(allocator, temp_config, method, url, params);
    defer allocator.free(signature);
    
    const encoded_signature = try percentEncode(allocator, signature);
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

fn parseOAuthResponse(allocator: mem.Allocator, response: []const u8) !OAuthTokens {
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

fn getRequestToken(allocator: mem.Allocator, api_key: []const u8, api_secret: []const u8) !OAuthTokens {
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

fn getAccessToken(
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

fn getMimeType(file_path: []const u8) []const u8 {
    const ext = std.fs.path.extension(file_path);
    
    if (mem.eql(u8, ext, ".jpg") or mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
    if (mem.eql(u8, ext, ".png")) return "image/png";
    if (mem.eql(u8, ext, ".gif")) return "image/gif";
    if (mem.eql(u8, ext, ".webp")) return "image/webp";
    if (mem.eql(u8, ext, ".mp4")) return "video/mp4";
    if (mem.eql(u8, ext, ".mov")) return "video/quicktime";
    if (mem.eql(u8, ext, ".avi")) return "video/x-msvideo";
    if (mem.eql(u8, ext, ".webm")) return "video/webm";
    
    // Default to octet-stream
    return "application/octet-stream";
}

fn uploadMedia(allocator: mem.Allocator, config: Config, file_path: []const u8, debug: bool) ![]const u8 {
    const url = "https://upload.twitter.com/1.1/media/upload.json";
    
    // Read file
    const file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();
    
    const file_size = try file.getEndPos();
    if (file_size > 5 * 1024 * 1024 and mem.indexOf(u8, getMimeType(file_path), "image") != null) {
        std.debug.print("Error: Image file too large (max 5MB)\n", .{});
        return error.FileTooLarge;
    }
    if (file_size > 512 * 1024 * 1024 and mem.indexOf(u8, getMimeType(file_path), "video") != null) {
        std.debug.print("Error: Video file too large (max 512MB)\n", .{});
        return error.FileTooLarge;
    }
    
    const file_data = try allocator.alloc(u8, file_size);
    defer allocator.free(file_data);
    _ = try file.read(file_data);
    
    // Base64 encode the file data
    const encoded = std.base64.standard.Encoder;
    const encoded_size = encoded.calcSize(file_data.len);
    const encoded_data = try allocator.alloc(u8, encoded_size);
    defer allocator.free(encoded_data);
    _ = encoded.encode(encoded_data, file_data);
    
    // Create multipart boundary
    const boundary = "------------------------boundary1234567890";
    
    // Build multipart body
    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();
    
    // Add media_data field
    try body.writer().print("--{s}\r\n", .{boundary});
    try body.appendSlice("Content-Disposition: form-data; name=\"media_data\"\r\n\r\n");
    try body.appendSlice(encoded_data);
    try body.appendSlice("\r\n");
    
    // End boundary
    try body.writer().print("--{s}--\r\n", .{boundary});
    
    const body_data = try body.toOwnedSlice();
    defer allocator.free(body_data);
    
    // Create OAuth header
    const auth_header = try createOAuthHeader(
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
    
    // Make request
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    
    const uri = try std.Uri.parse(url);
    
    const content_type = try fmt.allocPrint(allocator, "multipart/form-data; boundary={s}", .{boundary});
    defer allocator.free(content_type);
    
    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth_header },
        .{ .name = "Content-Type", .value = content_type },
    };
    
    const server_header_buffer = try allocator.alloc(u8, 8192);
    defer allocator.free(server_header_buffer);
    
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = server_header_buffer,
        .extra_headers = &headers,
    });
    defer req.deinit();
    
    req.transfer_encoding = .{ .content_length = body_data.len };
    
    try req.send();
    try req.writeAll(body_data);
    try req.finish();
    try req.wait();
    
    if (req.response.status != .ok and req.response.status != .created) {
        std.debug.print("Error uploading media: HTTP {d}\n", .{@intFromEnum(req.response.status)});
        
        const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(response_body);
        std.debug.print("Response: {s}\n", .{response_body});
        
        return error.MediaUploadFailed;
    }
    
    if (debug) {
        std.debug.print("Media upload successful: HTTP {d}\n", .{@intFromEnum(req.response.status)});
    }
    
    const response_body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
    defer allocator.free(response_body);
    
    if (debug) {
        std.debug.print("Media upload response: {s}\n", .{response_body});
    }
    
    // Parse JSON response to get media_id_string
    // Simple JSON parsing for media_id_string
    const media_id_prefix = "\"media_id_string\":\"";
    const media_id_start = mem.indexOf(u8, response_body, media_id_prefix) orelse return error.InvalidResponse;
    const id_start = media_id_start + media_id_prefix.len;
    const id_end = mem.indexOfScalarPos(u8, response_body, id_start, '"') orelse return error.InvalidResponse;
    
    const media_id = response_body[id_start..id_end];
    if (debug) {
        std.debug.print("Extracted media_id: {s}\n", .{media_id});
    }
    
    return try allocator.dupe(u8, media_id);
}

fn postTweet(allocator: mem.Allocator, config: Config, message: []const u8, media_id: ?[]const u8, debug: bool) !void {
    const url = "https://api.twitter.com/2/tweets";
    
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    
    // Escape the message for JSON
    const escaped_message = try jsonEscape(allocator, message);
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
    
    const auth_header = try createOAuthHeader(
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

fn saveConfig(allocator: mem.Allocator, config: Config) !void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHome;
    defer allocator.free(home);
    
    const config_dir = try fmt.allocPrint(allocator, "{s}/.config/tweet", .{home});
    defer allocator.free(config_dir);
    
    // Ensure config directory exists
    std.fs.makeDirAbsolute(config_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    
    const config_path = try fmt.allocPrint(allocator, "{s}/config", .{config_dir});
    defer allocator.free(config_path);
    
    const file = try std.fs.createFileAbsolute(config_path, .{});
    defer file.close();
    
    const content = try fmt.allocPrint(allocator,
        \\API_KEY={s}
        \\API_SECRET={s}
        \\ACCESS_TOKEN={s}
        \\ACCESS_TOKEN_SECRET={s}
        \\
    , .{ config.api_key, config.api_secret, config.access_token, config.access_token_secret });
    defer allocator.free(content);
    
    try file.writeAll(content);
}

fn loadOrCreateConfig(allocator: mem.Allocator) !Config {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHome;
    defer allocator.free(home);
    
    const config_path = try fmt.allocPrint(allocator, "{s}/.config/tweet/config", .{home});
    defer allocator.free(config_path);
    
    // Try to load existing config
    const file = std.fs.openFileAbsolute(config_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            // Config doesn't exist, start OAuth flow
            return performOAuthFlow(allocator);
        }
        return err;
    };
    defer file.close();
    
    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);
    
    var config = Config{
        .api_key = "",
        .api_secret = "",
        .access_token = "",
        .access_token_secret = "",
    };
    
    var lines = mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var parts = mem.tokenizeScalar(u8, line, '=');
        const key = parts.next() orelse continue;
        const value = parts.next() orelse continue;
        
        if (mem.eql(u8, key, "API_KEY")) {
            config.api_key = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, key, "API_SECRET")) {
            config.api_secret = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, key, "ACCESS_TOKEN")) {
            config.access_token = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, key, "ACCESS_TOKEN_SECRET")) {
            config.access_token_secret = try allocator.dupe(u8, value);
        }
    }
    
    // Check if config is complete
    if (config.api_key.len == 0 or config.api_secret.len == 0 or
        config.access_token.len == 0 or config.access_token_secret.len == 0) {
        // Missing credentials, ask for all of them
        return performOAuthFlow(allocator);
    }
    
    return config;
}

fn performOAuthFlow(allocator: mem.Allocator) !Config {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    
    try stdout.print("\n🐦 Welcome to Tweet CLI! Let's set up your Twitter/X access.\n\n", .{});
    try stdout.print("From your Twitter app's 'Keys and tokens' page, you'll need:\n", .{});
    try stdout.print("1. API Key and Secret (under Consumer Keys)\n", .{});
    try stdout.print("2. Access Token and Secret (under Authentication Tokens)\n\n", .{});
    
    try stdout.print("Enter your API Key: ", .{});
    var buf = try allocator.alloc(u8, 256);
    defer allocator.free(buf);
    
    const api_key_len = try stdin.read(buf);
    const api_key = try allocator.dupe(u8, mem.trim(u8, buf[0..api_key_len], " \t\n\r"));
    
    try stdout.print("Enter your API Secret: ", .{});
    const api_secret_len = try stdin.read(buf);
    const api_secret = try allocator.dupe(u8, mem.trim(u8, buf[0..api_secret_len], " \t\n\r"));
    
    try stdout.print("Enter your Access Token: ", .{});
    const access_token_len = try stdin.read(buf);
    const access_token = try allocator.dupe(u8, mem.trim(u8, buf[0..access_token_len], " \t\n\r"));
    
    try stdout.print("Enter your Access Token Secret: ", .{});
    const access_token_secret_len = try stdin.read(buf);
    const access_token_secret = try allocator.dupe(u8, mem.trim(u8, buf[0..access_token_secret_len], " \t\n\r"));
    
    const config = Config{
        .api_key = api_key,
        .api_secret = api_secret,
        .access_token = access_token,
        .access_token_secret = access_token_secret,
    };
    
    // Save config
    try saveConfig(allocator, config);
    try stdout.print("\n✅ Configuration saved to ~/.config/tweet/config\n\n", .{});
    
    return config;
}

fn performOAuthFlowWithKeys(allocator: mem.Allocator, api_key: []const u8, api_secret: []const u8) !Config {
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
    
    const config = Config{
        .api_key = try allocator.dupe(u8, api_key),
        .api_secret = try allocator.dupe(u8, api_secret),
        .access_token = try allocator.dupe(u8, access_tokens.token),
        .access_token_secret = try allocator.dupe(u8, access_tokens.token_secret),
    };
    
    // Save config
    try saveConfig(allocator, config);
    try stdout.print("✅ Configuration saved to ~/.config/tweet/config\n\n", .{});
    
    return config;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    // Check for --reset flag to force re-authentication
    for (args[1..]) |arg| {
        if (mem.eql(u8, arg, "--reset")) {
            const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHome;
            defer allocator.free(home);
            const config_path = try fmt.allocPrint(allocator, "{s}/.config/tweet/config", .{home});
            defer allocator.free(config_path);
            std.fs.deleteFileAbsolute(config_path) catch {};
            // Silent success
            return;
        }
    }
    
    // Check if config exists
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHome;
    defer allocator.free(home);
    const config_path = try fmt.allocPrint(allocator, "{s}/.config/tweet/config", .{home});
    defer allocator.free(config_path);
    
    const config_exists = if (std.fs.accessAbsolute(config_path, .{})) true else |_| false;
    
    const config = try loadOrCreateConfig(allocator);
    defer {
        allocator.free(config.api_key);
        allocator.free(config.api_secret);
        allocator.free(config.access_token);
        allocator.free(config.access_token_secret);
    }
    
    // If we just created config, exit so user can run command again
    if (!config_exists) {
        return;
    }
    
    var message: ?[]const u8 = null;
    var media_path: ?[]const u8 = null;
    var should_free_media_path = false;
    var debug_mode = false;
    
    // Parse arguments - first pass for flags
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (mem.eql(u8, args[i], "--debug")) {
            debug_mode = true;
        } else if (mem.eql(u8, args[i], "--attach")) {
            if (i + 1 < args.len) {
                i += 1;
                if (mem.eql(u8, args[i], "-")) {
                    // Read file path from stdin for pipe support
                    const stdin = std.io.getStdIn().reader();
                    const path = try stdin.readUntilDelimiterAlloc(allocator, '\n', 1024);
                    media_path = mem.trim(u8, path, " \t\n\r");
                    should_free_media_path = true;
                } else {
                    media_path = args[i];
                }
            } else {
                std.debug.print("Error: --attach requires a file path\n", .{});
                return;
            }
        } else if (!mem.startsWith(u8, args[i], "--")) {
            // This is the message (first non-flag argument)
            if (message == null) {
                message = args[i];
            }
        }
    }
    
    // If no message was provided as argument, read from stdin
    var stdin_input: ?[]u8 = null;
    if (message == null) {
        const stdin = std.io.getStdIn().reader();
        stdin_input = try stdin.readAllAlloc(allocator, 1024 * 1024);
        message = mem.trim(u8, stdin_input.?, " \t\n\r");
    }
    defer if (stdin_input) |input| allocator.free(input);
    
    const msg = message.?;
    defer if (should_free_media_path) {
        if (media_path) |path| allocator.free(path);
    };
    
    if (msg.len == 0) {
        std.debug.print("Error: No message to tweet\n", .{});
        std.debug.print("Usage: tweet \"your message\" [--attach file.jpg] [--debug]\n", .{});
        std.debug.print("       echo \"your message\" | tweet [--attach file.jpg] [--debug]\n", .{});
        std.debug.print("       echo \"path/to/file.jpg\" | tweet \"message\" --attach - [--debug]\n", .{});
        std.debug.print("\nOptions:\n", .{});
        std.debug.print("  --attach FILE   Attach an image or video to the tweet\n", .{});
        std.debug.print("  --debug         Show debug output for troubleshooting\n", .{});
        std.debug.print("  --reset         Clear saved credentials\n", .{});
        return;
    }
    
    if (msg.len > 280) {
        std.debug.print("Error: Message too long ({d} chars, max 280)\n", .{msg.len});
        return;
    }
    
    // Upload media if provided
    var media_id: ?[]const u8 = null;
    if (media_path) |path| {
        // Expand tilde if present
        const expanded_path = if (mem.startsWith(u8, path, "~/")) blk: {
            const home_path = try fmt.allocPrint(allocator, "{s}{s}", .{ home, path[1..] });
            break :blk home_path;
        } else path;
        defer if (mem.startsWith(u8, path, "~/")) allocator.free(expanded_path);
        
        // Check if file exists
        std.fs.accessAbsolute(expanded_path, .{}) catch |err| {
            std.debug.print("Error: Cannot access file '{s}': {}\n", .{ expanded_path, err });
            return;
        };
        
        if (debug_mode) {
            std.debug.print("Uploading media: {s}...\n", .{std.fs.path.basename(expanded_path)});
        }
        media_id = try uploadMedia(allocator, config, expanded_path, debug_mode);
    }
    defer if (media_id) |id| allocator.free(id);
    
    try postTweet(allocator, config, msg, media_id, debug_mode);
}