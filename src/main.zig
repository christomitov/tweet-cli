const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;

const config_mod = @import("config.zig");
const media = @import("media.zig");
const twitter = @import("twitter.zig");

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
    
    const config = try config_mod.loadOrCreateConfig(allocator);
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
        media_id = try media.uploadMedia(allocator, config, expanded_path, debug_mode);
    }
    defer if (media_id) |id| allocator.free(id);
    
    try twitter.postTweet(allocator, config, msg, media_id, debug_mode);
}