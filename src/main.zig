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

fn generateNonce(allocator: mem.Allocator) ![]u8 {
    var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
    const random = rng.random();
    
    var nonce: [16]u8 = undefined;
    random.bytes(&nonce);
    
    const encoded = std.base64.standard.Encoder;
    const size = encoded.calcSize(nonce.len);
    const result = try allocator.alloc(u8, size);
    _ = encoded.encode(result, &nonce);
    
    // Remove non-alphanumeric characters
    var i: usize = 0;
    for (result) |c| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9')) {
            result[i] = c;
            i += 1;
        }
    }
    
    return result[0..i];
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
    defer allocator.free(items);
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
    var hmac = crypto.auth.hmac.sha1.Hmac.init(signing_key);
    hmac.update(base_string);
    var signature: [crypto.auth.hmac.sha1.Hmac.mac_length]u8 = undefined;
    hmac.final(&signature);
    
    // Base64 encode the signature
    const encoded = std.base64.standard.Encoder;
    const size = encoded.calcSize(signature.len);
    const result = try allocator.alloc(u8, size);
    _ = encoded.encode(result, &signature);
    
    return result;
}

fn createAuthHeader(
    allocator: mem.Allocator,
    config: Config,
    method: []const u8,
    url: []const u8,
    status: []const u8,
) ![]u8 {
    const timestamp = @divFloor(std.time.timestamp(), 1);
    const nonce = try generateNonce(allocator);
    defer allocator.free(nonce);
    
    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();
    
    try params.put("oauth_consumer_key", config.api_key);
    try params.put("oauth_nonce", nonce);
    try params.put("oauth_signature_method", "HMAC-SHA1");
    try params.put("oauth_timestamp", try fmt.allocPrint(allocator, "{d}", .{timestamp}));
    try params.put("oauth_token", config.access_token);
    try params.put("oauth_version", "1.0");
    try params.put("status", status);
    
    const signature = try createSignature(allocator, config, method, url, params);
    defer allocator.free(signature);
    
    const encoded_signature = try percentEncode(allocator, signature);
    defer allocator.free(encoded_signature);
    
    // Build OAuth header
    var header = std.ArrayList(u8).init(allocator);
    defer header.deinit();
    
    try header.appendSlice("OAuth ");
    try header.writer().print("oauth_consumer_key=\"{s}\", ", .{config.api_key});
    try header.writer().print("oauth_nonce=\"{s}\", ", .{nonce});
    try header.appendSlice("oauth_signature_method=\"HMAC-SHA1\", ");
    try header.writer().print("oauth_signature=\"{s}\", ", .{encoded_signature});
    try header.writer().print("oauth_timestamp=\"{d}\", ", .{timestamp});
    try header.writer().print("oauth_token=\"{s}\", ", .{config.access_token});
    try header.appendSlice("oauth_version=\"1.0\"");
    
    return header.toOwnedSlice();
}

fn postTweet(allocator: mem.Allocator, config: Config, message: []const u8) !void {
    const url = "https://api.twitter.com/2/tweets";
    
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    
    // Create request body
    const body = try fmt.allocPrint(allocator, "{{\"text\":\"{s}\"}}", .{message});
    defer allocator.free(body);
    
    // Create auth header
    const auth_header = try createAuthHeader(allocator, config, "POST", url, message);
    defer allocator.free(auth_header);
    
    // Create request
    const uri = try std.Uri.parse(url);
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = try allocator.alloc(u8, 8192),
    });
    defer req.deinit();
    
    req.transfer_encoding = .{ .content_length = body.len };
    
    try req.headers.append("Authorization", auth_header);
    try req.headers.append("Content-Type", "application/json");
    
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
    
    std.debug.print("Tweet posted successfully!\n", .{});
}

fn loadConfig(allocator: mem.Allocator) !Config {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHome;
    defer allocator.free(home);
    
    const config_path = try fmt.allocPrint(allocator, "{s}/.tweet", .{home});
    defer allocator.free(config_path);
    
    const file = std.fs.openFileAbsolute(config_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            std.debug.print("Config file not found at {s}\n", .{config_path});
            std.debug.print("Please create it with the following format:\n", .{});
            std.debug.print("API_KEY=your_api_key\n", .{});
            std.debug.print("API_SECRET=your_api_secret\n", .{});
            std.debug.print("ACCESS_TOKEN=your_access_token\n", .{});
            std.debug.print("ACCESS_TOKEN_SECRET=your_access_token_secret\n", .{});
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
    
    var lines = mem.tokenize(u8, content, "\n");
    while (lines.next()) |line| {
        var parts = mem.tokenize(u8, line, "=");
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
    
    if (config.api_key.len == 0 or config.api_secret.len == 0 or
        config.access_token.len == 0 or config.access_token_secret.len == 0) {
        return error.IncompleteConfig;
    }
    
    return config;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    const config = try loadConfig(allocator);
    defer {
        allocator.free(config.api_key);
        allocator.free(config.api_secret);
        allocator.free(config.access_token);
        allocator.free(config.access_token_secret);
    }
    
    var message: []const u8 = undefined;
    
    if (args.len > 1) {
        // Tweet from command line argument
        message = args[1];
    } else {
        // Read from stdin
        const stdin = std.io.getStdIn().reader();
        message = try stdin.readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(message);
        
        // Trim whitespace
        message = mem.trim(u8, message, " \t\n\r");
    }
    
    if (message.len == 0) {
        std.debug.print("Error: No message to tweet\n", .{});
        std.debug.print("Usage: tweet \"your message\" or echo \"your message\" | tweet\n", .{});
        return;
    }
    
    if (message.len > 280) {
        std.debug.print("Error: Message too long ({d} chars, max 280)\n", .{message.len});
        return;
    }
    
    try postTweet(allocator, config, message);
}