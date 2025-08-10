# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A command-line Twitter/X client written in Zig that allows posting tweets with optional media attachments. Uses OAuth 1.0a for authentication and Twitter API v2 for posting.

## Build and Run Commands

```bash
# Build the project
zig build -Doptimize=ReleaseFast

# Run tests
zig build test

# Run the application directly
zig build run -- "Your tweet message"

# Install to system
cp zig-out/bin/tweet ~/.local/bin/
# or
sudo cp zig-out/bin/tweet /usr/local/bin/
```

## Architecture

The codebase is organized into modular components:

- **main.zig**: Entry point, argument parsing, and orchestration
- **config.zig**: Configuration management, handles API credentials stored in `~/.config/tweet/config`
- **oauth.zig**: OAuth 1.0a implementation for Twitter API authentication
- **twitter.zig**: Twitter API v2 interaction for posting tweets
- **media.zig**: Media upload functionality supporting images and videos
- **encoding.zig**: URL and JSON encoding utilities

## Key Implementation Details

### Authentication Flow
The tool uses pre-generated Access Tokens (not OAuth flow):
1. User provides all 4 credentials on first run (API Key, API Secret, Access Token, Access Token Secret)
2. Credentials stored in `~/.config/tweet/config`
3. Each request signed with HMAC-SHA1 using OAuth 1.0a

### Media Upload
- Uses Twitter's v1.1 media upload endpoint
- Base64 encodes media data in multipart form
- Returns media_id for attachment to tweets
- Size limits: 5MB for images, 512MB for videos

### Command-Line Interface
- Supports direct message argument: `tweet "message"`
- Stdin input for piping: `echo "message" | tweet`
- Media attachment: `--attach path/to/file`
- Stdin path for media: `--attach -` (reads path from stdin)
- Debug mode: `--debug` for verbose output
- Reset credentials: `--reset`

## Testing Approach

Run unit tests with `zig build test`. The test infrastructure is defined in build.zig and tests can be added to any `.zig` file using Zig's built-in testing framework.

## Development Notes

- Returns the tweet URL on successful post (format: https://twitter.com/i/status/{id})
- Error messages are printed to stderr
- Supports multiline tweets and special characters through proper JSON escaping
- Uses Zig 0.14.1 standard library for HTTP client and crypto operations