# Heimdall Gemini endpoint

This small server keeps the Gemini API key out of the public GitHub Pages app. It accepts only Heimdall's redacted integration report, asks Gemini for a schema-controlled explanation, and returns JSON for the comparison screen.

## Connect it

1. Authenticate Wrangler with the Cloudflare account that will host the endpoint.
2. From this directory, save the key as a Worker secret: `npx wrangler secret put GEMINI_API_KEY`.
3. Deploy with `npx wrangler deploy`.
4. Set the returned Worker URL in `web/config.js` and redeploy the website.

Do not commit the Gemini key. The Worker restricts browser requests to the configured `ALLOWED_ORIGIN`. For another host or a local test, change that value before deployment.
