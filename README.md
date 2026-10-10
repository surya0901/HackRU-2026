# Heimdall — scan, prove, fix, verify

Heimdall performs bounded static analysis of public GitHub source. It reconstructs supported agent/tool capability relationships, explains the evidence, proposes explicit tool-registration changes, and independently rescans another commit to compare the original findings and paths. The existing visual identity is retained.

## Run and test

Requires Node 20 or newer and Python 3 for the example static server.

```sh
npm ci --ignore-scripts
npm run check
python3 -m http.server 4174 --directory web
```

Open http://localhost:4174/. `npm run build` bundles the same analysis modules used by automated tests into `web/core.js`. GitHub Pages runs checks and rebuilds before deploying `draft-1`.

## Real demonstration

Use the **Try live demo** button or paste:

https://github.com/surya0901/HackRU-2026/tree/demo-vulnerable

This is a real source branch containing a support agent that explicitly registers a refund tool. The generic scanner resolves the tool's Stripe refund expression and links direct request input to the agent. No model, refund API, or repository code is executed by Heimdall.

1. Scan `demo-vulnerable` (commit `51c6fb4bddced50c2ee010834a57b9d90b3bff08`).
2. Open the top finding's technical proof. Inspect actual lines at that commit and every graph relationship.
3. Review the **PROPOSED CHANGE** diff removing the tool registration. Nothing is silently applied.
4. Open **Verify / history**, leave that scan as the baseline, and enter `demo-fixed` (commit `170206f9fbd4b7f539a817d9370a30be1cb4f63d`).
5. Rescan. The scanner fetches and analyzes the changed source again. The original capability finding is no longer detected and its static paths are no longer reachable. The standalone refund implementation remains observed in source; the application is not certified safe.

The changed branch is an actual child commit with `tools: [issueRefund]` changed to `tools: []`. There is no special-case detector for either branch or repository. `scripts/create-demo-commits.mjs` creates equivalent source commits locally without switching the worktree, executing the example, or pushing anything.

## Evidence contract

- **OBSERVED:** source/configuration facts or exact package/advisory data.
- **DERIVED:** a deterministic conclusion or graph traversal over observed relationships.
- **UNVERIFIED:** runtime execution, successful manipulation, authorization bypass, credential validity, or a comparison with insufficient evidence.

Findings and graph edges carry repository, commit SHA, file, line, redacted snippet, and rule provenance. Stable semantic fingerprints exclude commit and line numbers. They identify conditions across source line movement; they are identity digests, not signatures or authorization tokens.

Each finding explains the potential consequence, why it matters, what was found, what was not proved, and the proposed change. Downloaded JSON, Markdown, and SARIF retain evidence and commit identity while excluding retrieved raw source.

## Supported analysis and boundaries

The engine uses the [Babel JavaScript/TypeScript parser](https://babeljs.io/docs/babel-parser). It supports explicit `Agent`, `createAgent`, and `createReactAgent` configuration imported from recognized SDKs, explicit named tool arrays, named/local/direct relative imports, supported tool wrappers, direct request-body/query/params input at agent calls, and selected sensitive API expressions in resolved tool bodies. Supported operations include Stripe mutations, selected database mutations, process execution, filesystem mutations, and HTTP mutation calls. JSON MCP server declarations are parsed without inventing agent-to-MCP associations.

This is not whole-program taint analysis. Dynamic configuration, complex helper chains, re-export chains beyond the supported patterns, framework-generated wiring, nested callback behavior, most runtime controls, and other languages are not reconstructed. Their absence is not proof of safety. Supported sensitive operations are observations/capabilities, not necessarily vulnerabilities. No runtime exploit or prompt-injection test is performed.

Text files can receive secret-pattern and credential-name/entropy detection. Values are fully redacted and never externally validated. Private key bodies, companion credentials on the same line, and diagnostic text are redacted. A pattern match is a **LIKELY SECRET**, never a confirmed valid credential.

Dependency support includes npm manifests and npm lockfiles, exact `requirements*.txt` pins, and pinned `go.mod` requirements. Ranges, includes, installer aliases, replacements, unsupported package managers, and unestablished versions stay unresolved. [OSV](https://google.github.io/osv.dev/api/) is queried only for established exact package/version identities; returned advisory data includes affected ranges and source. The advisory database can change independently of source, so disappearance with an unchanged package/version does not verify a source fix.

## Coverage, failure, and verification

One commit is resolved before tree enumeration. All raw file requests use that SHA, never the moving branch name. Selection is deterministic with limits of 120 files, 2 MB total declared source bytes, and 250 KB per file. The Coverage tab lists exclusions, failed reads, parse errors, unsupported languages/configuration, and service status.

Requests time out and can be cancelled. One failed file or an OSV failure does not discard unrelated static findings. Empty or unsupported scans explicitly report their limited scope and do not manufacture informational findings to simulate success.

Verification requires the same repository and engine, changed commits, stable fingerprints, complete provenance, and adequate analysis coverage. Parser failures, unresolved registrations, path-budget limits, skipped files, unavailable advisory services, or reduced coverage produce **UNVERIFIED**, not a successful fix. Verification claims only static absence of a particular supported finding/path.

## Data handling and security model

The browser fetches public source directly from GitHub. Established package names, ecosystems, and versions are sent to OSV. No API key, backend, private repository integration, hosted audit trail, runtime enforcement, or model-generated security judgment is used. Redacted structured evidence is stored in bounded local browser history when available. Storage failures warn without stopping scans; legacy evidence-free history is excluded. Delete local history from Verify / history.

Repository content is untrusted. It is parsed as data and never evaluated or executed. The UI escapes displayed text and links source proof to the immutable commit. Proposed patches require human review and are not generated if their context would expose detected secret material. No simulation is used as proof; scripted Flight Recorder/Security Twin/Action Escrow outcomes were removed from the primary website. The unchanged extension is explicitly experimental and outside the supported workflow.

## Architecture

`src/repository.js` resolves the commit and retrieves bounded evidence. `src/dependencies.js` parses package identities and requests OSV records. `src/engine.js` builds source findings and a normalized capability graph. `src/verification.js` compares finding/path fingerprints conservatively. `src/history.js` validates and safely persists evidence. `src/reports.js` exports structured proof. `web/app.js` renders these results in the existing console.

Tests cover URL parsing, exact dependencies, source redaction, AST detections, capability relationships, graph traversal, missing evidence, fingerprint stability, independent corrected-source scans, actual generated patch application, malformed inputs, API failures, cancellation/timeouts, partial coverage, history validation, and report serialization. Fixtures contain intentionally risky source and are analyzed through the generic pipeline.

Only inspect repositories you are authorized to review. Discovered credential validity and real-system impact are never tested by this application.
