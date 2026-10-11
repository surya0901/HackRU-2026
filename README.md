# HackRU 2026 — Heimdall

Heimdall helps developers evaluate an unfamiliar repository before adding it to their project. It compares the developer's public project with the candidate tool, groups evidence-backed security findings into plain-language gaps, and prepares a redacted report that Gemini can turn into a project-specific integration plan.

The product deliberately separates four evidence states: observed source evidence, inferred control gaps, simulated walkthroughs, and verified reruns. A scan is a prioritization aid, not proof that an application is safe.

## What is included

- A polished browser-based security console in `web/`
- A two-repository integration review: your project plus the tool you are considering
- Real public-repository source inspection and rule-based findings
- Dependency parsing with OSV vulnerability lookup
- Secret redaction and entropy-based detection
- Evidence-backed attack paths, scan history, and change diffs
- JSON, Markdown, and SARIF report exports
- Coverage limits and evidence confidence are surfaced in the console so teams can distinguish facts from heuristics
- A Chrome extension in `extension/` for GitHub overlays, prompt protection, page scanning, and a side-panel security copilot
- A protected Gemini endpoint template in `gemini-worker/`; Gemini receives redacted findings, not repository source or secret values

## Run the web demo

Serve the repository root with any static server, then open `web/index.html`.

```bash
npx serve .
```

The generated AeroShards browser bundle is committed for the static demo. To rebuild it after changing files in `web/src/`:

```bash
cd web
npm install
npm run build
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

The browser demo analyzes public repositories only. It is intentionally limited by GitHub API availability, source-file selection, browser memory, and static heuristics. Private-repository access is not implemented. Gemini is enabled only after the protected endpoint is deployed and configured; the public site never contains the API key. Treat findings as reviewable evidence and validate controls after integration in CI and the runtime environment.
