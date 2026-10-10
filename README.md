# HackRU 2026 — AI Application Security Platform

An interactive security product that scans public GitHub repositories, finds exploitable code and dependency risks, proves impact through attack-path evidence, and turns findings into actionable fixes.

## What is included

- A polished browser-based security console in `web/`
- Real public-repository source inspection and rule-based findings
- Dependency parsing with OSV vulnerability lookup
- Secret redaction and entropy-based detection
- Evidence-backed attack paths, scan history, and change diffs
- JSON, Markdown, and SARIF report exports
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
