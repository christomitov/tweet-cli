const std = @import("std");
const http = std.http;
const mem = std.mem;
const fmt = std.fmt;

const config_mod = @import("config.zig");
const oauth = @import("oauth.zig");

pub const MediaUploadResponse = struct {
    media_id_string: []const u8,
};

pub fn getMimeType(file_path: []const u8) []const u8 {
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

pub fn uploadMedia(allocator: mem.Allocator, config: config_mod.Config, file_path: []const u8, debug: bool) ![]const u8 {
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

test "getMimeType image types" {
    try std.testing.expectEqualStrings("image/jpeg", getMimeType("photo.jpg"));
    try std.testing.expectEqualStrings("image/jpeg", getMimeType("photo.jpeg"));
    try std.testing.expectEqualStrings("image/png", getMimeType("image.png"));
    try std.testing.expectEqualStrings("image/gif", getMimeType("animation.gif"));
    try std.testing.expectEqualStrings("image/webp", getMimeType("photo.webp"));
}

test "getMimeType video types" {
    try std.testing.expectEqualStrings("video/mp4", getMimeType("video.mp4"));
    try std.testing.expectEqualStrings("video/quicktime", getMimeType("video.mov"));
    try std.testing.expectEqualStrings("video/x-msvideo", getMimeType("video.avi"));
    try std.testing.expectEqualStrings("video/webm", getMimeType("video.webm"));
}

test "getMimeType unknown type" {
    try std.testing.expectEqualStrings("application/octet-stream", getMimeType("file.xyz"));
    try std.testing.expectEqualStrings("application/octet-stream", getMimeType("file.unknown"));
}