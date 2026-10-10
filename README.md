# Heimdall — Scan → See proof → Fix → Verify

Heimdall checks **public GitHub repositories** for potential security mistakes. Paste a repository URL and get filename/line evidence, redacted snippets, plain-language guidance, known OSV advisories when available, and a basic before/after comparison.

## Run

Serve the repository root using `npx serve .` and open `/web/`. The simple experience is `web/index.html`. The original multi-feature prototype is preserved at `web/console.html`. The Chrome extension remains in `extension/` but is not part of the main demo flow.

## What works without configuration

- Read-only public GitHub API repository scan (up to 35 selected files)
- Pattern-based detection of credential candidates, dynamic code execution, raw HTML sinks, and command execution surfaces
- OSV advisory lookup for pinned npm dependency versions, if the OSV endpoint is reachable
- Real file paths, line numbers, GitHub code links, and **redacted** evidence
- Local scan history and comparison of finding fingerprints across rescans
- Rules-based fixes shown immediately

## Optional Gemini integration

Deploy as a Vercel project with the repository root as project root and set the `GEMINI_API_KEY` environment variable on the server. `/api/explain` is a server-side endpoint that calls Gemini 2.5 Flash; the browser does **not** contain your Gemini API key. The Explain with Gemini button shows an honest unavailable message on static-only GitHub Pages deployments.

## Known limits

This is static analysis, not exploitation or security certification. The scanner reads a capped subset of public files, uses heuristics that may produce false positives, does not verify runtime exploitability, and does not currently resolve lockfiles to exact installed versions. Secret-like values are redacted before display or Gemini requests. Avoid storing actual exposed credentials in test repositories; use fictional fixtures. Re-scan comparisons detect warnings disappearing, **not proof** that a code change fully resolves a vulnerability.
