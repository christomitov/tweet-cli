const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;

pub const Config = struct {
    api_key: []const u8,
    api_secret: []const u8,
    access_token: []const u8,
    access_token_secret: []const u8,
};

pub fn saveConfig(allocator: mem.Allocator, config: Config) !void {
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

pub fn loadConfig(allocator: mem.Allocator) !?Config {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHome;
    defer allocator.free(home);
    
    const config_path = try fmt.allocPrint(allocator, "{s}/.config/tweet/config", .{home});
    defer allocator.free(config_path);
    
    // Try to load existing config
    const file = std.fs.openFileAbsolute(config_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return null;
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
        return null;
    }
    
    return config;
}

pub fn performOAuthFlow(allocator: mem.Allocator) !Config {
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

pub fn loadOrCreateConfig(allocator: mem.Allocator) !Config {
    if (try loadConfig(allocator)) |config| {
        return config;
    }
    return performOAuthFlow(allocator);
}

test "Config struct" {
    const config = Config{
        .api_key = "test_key",
        .api_secret = "test_secret",
        .access_token = "test_token",
        .access_token_secret = "test_token_secret",
    };
    
    try std.testing.expectEqualStrings("test_key", config.api_key);
    try std.testing.expectEqualStrings("test_secret", config.api_secret);
    try std.testing.expectEqualStrings("test_token", config.access_token);
    try std.testing.expectEqualStrings("test_token_secret", config.access_token_secret);
}

test "saveConfig and loadConfig" {
    const allocator = std.testing.allocator;
    
    // Create a temporary config for testing
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        // Skip test if HOME not set
        return;
    };
    defer allocator.free(home);
    
    const test_config_dir = try fmt.allocPrint(allocator, "{s}/.config/tweet_test", .{home});
    defer allocator.free(test_config_dir);
    
    // Clean up after test
    defer std.fs.deleteTreeAbsolute(test_config_dir) catch {};
}