# HackRU 2026 — AI Application Security Platform

Heimdall is a GitHub-native security control plane for AI agents and MCP servers. It scans public repositories, maps agents and tools, traces trust-boundary crossings, and turns high-confidence findings into actionable fixes.

The product deliberately separates four evidence states: observed source evidence, inferred control gaps, simulated walkthroughs, and verified reruns. A scan is a prioritization aid, not proof that an application is safe.

## What is included

- A polished browser-based security console in `web/`
- Real public-repository source inspection and rule-based findings
- Dependency parsing with OSV vulnerability lookup
- Secret redaction and entropy-based detection
- Evidence-backed attack paths, scan history, and change diffs
- JSON, Markdown, and SARIF report exports
- Coverage limits and evidence confidence are surfaced in the console so teams can distinguish facts from heuristics
- A Chrome extension in `extension/` for GitHub overlays, prompt protection, page scanning, and a side-panel security copilot

## Run the web demo

The web demo has no build step. Serve the repository root with any static server, then open `web/index.html`.

```bash
npx serve .
```

## Build the Chrome extension

```bash
cd extension
npm install
npm run build
```

Load `extension/dist` as an unpacked extension from `chrome://extensions` after enabling Developer mode.

## Safety

Only scan repositories and applications you own or have explicit authorization to test. Demonstrations are designed to explain risk without exposing retrieved secrets.

## Current scope

The browser demo analyzes public repositories only. It is intentionally limited by GitHub API availability, source-file selection, browser memory, and static heuristics. It does not provide runtime verification, private-repository support, or a server-side audit trail yet. For production use, treat findings as reviewable evidence and validate controls in your own CI and runtime environment.
