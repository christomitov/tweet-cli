# Tweet CLI Tool

A simple command-line tool to post tweets written in Zig.

## Setup

On first run, the tool will ask for your Twitter API credentials. You'll need all 4 values from your app's "Keys and tokens" page:

1. **API Key** and **API Secret** (under "Consumer Keys")
2. **Access Token** and **Access Token Secret** (under "Authentication Tokens")

If you don't have Access Tokens yet:
1. Click "Generate" next to "Access Token and Secret"
2. Make sure they have "Read and Write" permissions
3. Copy all 4 values when prompted

The credentials will be saved to `~/.config/tweet/config`

## Build

Build the tool:
```bash
zig build -Doptimize=ReleaseFast
```

Install to your PATH:
```bash
cp zig-out/bin/tweet ~/.local/bin/
# or
sudo cp zig-out/bin/tweet /usr/local/bin/
```

## Usage

Tweet from command line (returns the tweet URL):
```bash
tweet "Hello, world!"
# Output: https://twitter.com/i/status/1234567890
```

Tweet with image or video:
```bash
tweet "Check this out!" --attach ~/Desktop/screenshot.png
tweet "New video!" --attach video.mp4
```

Pipe text to tweet:
```bash
echo "Hello from pipe!" | tweet
```

Pipe text with media:
```bash
echo "Great photo!" | tweet --attach photo.jpg
```

Pipe file path for media (use `-` for stdin):
```bash
echo "~/Desktop/latest.png" | tweet "Screenshot:" --attach -
find ~/Pictures -name "*.jpg" | head -1 | tweet "Photo of the day" --attach -
```

### Supported Media Formats
- **Images**: JPG, PNG, GIF, WebP (max 5MB)
- **Videos**: MP4, MOV, AVI, WebM (max 512MB)

### Debugging
If media attachments aren't working, use the `--debug` flag to see detailed output:
```bash
tweet "Test with image" --attach photo.jpg --debug
```

## How It Works

The tool uses OAuth 1.0a to authenticate with Twitter's API:
1. On first run, it asks for all 4 credentials from your Twitter app
2. Stores them securely in `~/.config/tweet/config`
3. Uses HMAC-SHA1 signatures to authenticate each request
4. Posts tweets using Twitter API v2

To reset credentials, run:
```bash
tweet --reset
```