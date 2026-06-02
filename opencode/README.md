# opencode-credit-dashboard


[![npm version](https://img.shields.io/npm/v/opencode-credit-dashboard)](https://www.npmjs.com/package/opencode-credit-dashboard)
[![npm downloads](https://img.shields.io/npm/dm/opencode-credit-dashboard)](https://www.npmjs.com/package/opencode-credit-dashboard)
[![CI](https://github.com/intisy/opencode-credit-dashboard/actions/workflows/publish.yml/badge.svg)](https://github.com/intisy/opencode-credit-dashboard/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Credit usage dashboard plugin for [OpenCode](https://github.com/sst/opencode).

Shows per-account quota, token usage (input/output/thinking), daily cost breakdown, and enable/disable toggles for Antigravity accounts. Syncs data across devices via Firebase.

## Features

- **Per-account quota display** — see remaining quota for Gemini Pro, Flash, and Claude across all accounts
- **Token breakdown** — input, output, and thinking tokens per session and model
- **Daily cost tracking** — cost and token usage aggregated by day
- **Model usage cards** — sortable by tokens, cost, or messages
- **Multi-device sync** — Firebase Realtime Database keeps data in sync across machines
- **Account management** — enable/disable accounts, set nicknames for devices
- **Session browser** — view all sessions with cost and token details
- **Auto-refresh** — live updates every 15 seconds

## Installation

### Option A — Via plugin-updater (recommended)

If you have [opencode-plugin-updater](https://github.com/intisy/opencode-plugin-updater) installed, add this entry to `~/.config/opencode/config/plugins.json`:

```json
{
  "name": "opencode-credit-dashboard",
  "url": "https://github.com/intisy/opencode-credit-dashboard.git",
  "install": null,
  "build": null,
  "bundle": null,
  "output": "credit-dashboard.js",
  "pluginFile": "credit-dashboard.js",
  "autoUpdate": true
}
```

Restart OpenCode. The updater will clone the repo and deploy the plugin automatically.

### Option B — npm

Add the package to your `~/.config/opencode/opencode.json`:

```jsonc
{
  "plugins": ["opencode-credit-dashboard@latest"]
}
```

Restart OpenCode.

### Option C — Manual

```bash
mkdir -p ~/.config/opencode/repos/intisy/opencode-credit-dashboard
git clone https://github.com/intisy/opencode-credit-dashboard.git ~/.config/opencode/repos/intisy/opencode-credit-dashboard
cp ~/.config/opencode/repos/intisy/opencode-credit-dashboard/credit-dashboard.js ~/.config/opencode/plugins/credit-dashboard.js
```

Register the plugin in `~/.config/opencode/opencode.json`:

```jsonc
{
  "plugins": {
    "credit-dashboard": "./plugins/credit-dashboard.js"
  }
}
```

## Firebase Sync (optional)

To enable multi-device sync, place a Firebase service account JSON file at:

```
~/.config/opencode/config/firebase-service-account.json
```

Without this file, the dashboard works in local-only mode.

## Usage

The plugin exposes a `credit_dashboard` tool. Ask OpenCode:

```
Show me my credit dashboard
```

This opens a web dashboard at `http://localhost:3456` with full analytics.

## License

MIT
