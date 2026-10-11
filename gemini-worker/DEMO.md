# Heimdall Gemini demo

## Connect once

1. Deploy this Worker.
2. In Gemini, open **Settings → Connected Apps → Add a custom app**.
3. Name it **Heimdall Security**.
4. Enter `https://YOUR-WORKER.workers.dev/mcp`.
5. If authentication is enabled, use the configured Bearer token.

## 90-second judge demo

Start with:

> @Heimdall scan https://github.com/OWASP/NodeGoat. Explain the highest-priority finding in normal words and cite the Heimdall finding ID.

Then show the project-specific comparison:

> @Heimdall compare https://github.com/surya0901/HackRU-2026 with https://github.com/OWASP/NodeGoat. I want to reuse its authentication approach in a public student application. Tell me whether I should integrate it, what evidence supports the decision, and what I must fix first.

Finish with:

> What did Heimdall actually verify, what could it not verify, and how would I confirm the fix?

## Judge explanation

> Gemini is the reasoning and conversation layer. It decides when to call Heimdall's read-only security tools. Heimdall performs the bounded scan, checks package versions against OSV, and returns redacted evidence. Gemini explains how that evidence affects the developer's intended use. It cannot change the score or invent a finding.

## Honest limitations

- Public GitHub repositories only.
- A maximum of 18 selected files and 900 KB per scan.
- Repository code is read but never executed.
- The readiness score prioritizes visible findings; it is not a security certification.
- Missing controls are labeled as inferred gaps rather than confirmed vulnerabilities.
