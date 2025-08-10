# Tweet CLI Tool

A simple command-line tool to post tweets written in Zig.

## Setup

The tool will guide you through OAuth authentication on first use. You'll need:
- Twitter/X API Key and API Secret from https://developer.twitter.com

On first run, the tool will:
1. Ask for your API Key and API Secret
2. Generate an authorization URL
3. Ask you to visit the URL and authorize the app
4. Enter the PIN code shown after authorization
5. Save your credentials to `~/.config/tweet/config`

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

Tweet from command line:
```bash
tweet "Hello, world!"
```

Pipe text to tweet:
```bash
echo "Hello from pipe!" | tweet
```

## How It Works

This tool implements OAuth 1.0a PIN-based authentication (Out-of-Band flow):
1. On first run, it requests your API credentials
2. Fetches a request token from Twitter
3. Generates an authorization URL for you to visit
4. After you authorize and get a PIN, exchanges it for access tokens
5. Stores all credentials securely for future use

The stored config file contains:
- API Key & Secret (identifies your app)
- Access Token & Secret (allows posting on your behalf)