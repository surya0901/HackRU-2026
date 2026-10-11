# Heimdall Gemini endpoint

This small server keeps the Gemini API key out of the public GitHub Pages app. It accepts only Heimdall's redacted integration report, asks Gemini for a schema-controlled explanation, and returns JSON for the comparison screen.

## Connect it

1. Authenticate Wrangler with the Cloudflare account that will host the endpoint.
2. From this directory, save the key as a Worker secret: `npx wrangler secret put GEMINI_API_KEY`.
3. Deploy with `npx wrangler deploy`.
4. Set the returned Worker URL in `web/config.js` and redeploy the website.

Do not commit the Gemini key. The Worker restricts browser requests to the configured `ALLOWED_ORIGIN`. For another host or a local test, change that value before deployment.

## Gemini Connected App (MCP)

The same Worker exposes a read-only MCP endpoint at `/mcp`. It provides two tools:

- `scan_repository`: scans one public GitHub repository with bounded static rules and OSV lookups.
- `check_reference`: scans a project and a reference repository, then returns an evidence-backed integration decision for the stated use.

The endpoint never executes repository code and redacts credential-shaped evidence. Set optional secrets before deploying:

```sh
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put MCP_AUTH_TOKEN
npx wrangler deploy
```

To connect it in Gemini, open Settings, Connected Apps, Add a custom app, and enter:

```text
https://heimdall-gemini.heimdall-security-2026.workers.dev/mcp
```

If `MCP_AUTH_TOKEN` is set, provide it as the Bearer credential in Gemini's advanced connection settings. For the hackathon demo, invoke the tool with `@Heimdall` and ask it to scan a public GitHub repository.
