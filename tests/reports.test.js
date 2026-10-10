import test from 'node:test';
import assert from 'node:assert/strict';
import { evidenceReport, markdownReport, sarifReport } from '../src/reports.js';

const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);
const secret = 'sk-proj-' + 'AbCdEf1234567890'.repeat(4);
function scan() {
  return { repo: { owner: 'example', repo: 'project', url: 'https://github.com/example/project' }, branch: 'main', commit: COMMIT_B, engineVersion: '1.0.0', scope: 'Supported static evidence', findings: [{ fingerprint: 'stable-finding', rule: 'secret-literal', title: 'Likely credential in source', evidenceType: 'OBSERVED', sev: 'high', proven: 'A credential-shaped literal was found.', notProven: 'Credential validity was not tested.', fix: 'Rotate a real credential.', provenance: [{ file: 'src/my file.ts', line: 4, commit: COMMIT_B, snippet: `const API_KEY = "${secret}";` }] }], paths: [{ fingerprint: 'static-path', staticStatus: 'REACHABLE', exploitStatus: 'UNVERIFIED' }], graph: { nodes: [], edges: [] }, coverage: { complete: true }, diagnostics: [], diff: { available: true, beforeCommit: COMMIT_A, afterCommit: COMMIT_B, noLongerDetected: [{ fingerprint: 'original-finding' }], paths: { noLongerReachable: [{ fingerprint: 'original-path' }], unverified: [] }, unverified: [] } };
}

test('JSON evidence exports drop raw code and nested scan payloads and redact credential material', () => {
  const input = scan();
  input.sources = [{ content: secret }];
  input.graph.nodes.push({ id: 'observed', label: `Credential ${secret}`, source: secret, content: secret });
  input.diff.previous = { sources: [{ content: secret }] };
  input.osv = { status: 'COMPLETE', vulnerabilities: [{ id: 'GHSA-test-0001', summary: secret, source: 'https://osv.dev/vulnerability/GHSA-test-0001', affectedRanges: [{ type: 'SEMVER', events: [{ fixed: '2.0.0' }] }] }] };
  const report = evidenceReport(input);
  const serialized = JSON.stringify(report);
  assert.equal(serialized.includes(secret), false);
  assert.equal(serialized.includes('"sources"'), false);
  assert.equal(serialized.includes('"content"'), false);
  assert.equal(serialized.includes('"previous"'), false);
  assert.equal(report.osv.vulnerabilities[0].source, 'https://osv.dev/vulnerability/GHSA-test-0001');
  assert.deepEqual(report.osv.vulnerabilities[0].affectedRanges, input.osv.vulnerabilities[0].affectedRanges);
  assert.ok(input.graph.nodes[0].content === secret, 'Export must not mutate the underlying scan.');
});

test('Markdown preserves commit provenance, real before/after comparison and static uncertainty', () => {
  const markdown = markdownReport(scan());
  assert.match(markdown, new RegExp(COMMIT_B));
  assert.match(markdown, new RegExp(COMMIT_A));
  assert.match(markdown, /Original static finding no longer detected/);
  assert.match(markdown, /Original static path no longer reachable/);
  assert.match(markdown, /exploit UNVERIFIED/);
  assert.match(markdown, /Credential validity was not tested/);
  assert.equal(markdown.includes(secret), false);
});

test('SARIF pins repository revision and fingerprints and encodes evidence file URIs', () => {
  const report = sarifReport(scan());
  assert.equal(report.version, '2.1.0');
  assert.deepEqual(report.runs[0].versionControlProvenance, [{ repositoryUri: 'https://github.com/example/project', revisionId: COMMIT_B }]);
  const result = report.runs[0].results[0];
  assert.equal(result.partialFingerprints['heimdall/v1'], 'stable-finding');
  assert.equal(result.properties.exploit, 'UNVERIFIED');
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/my%20file.ts');
  assert.equal(result.locations[0].physicalLocation.region.startLine, 4);
  assert.equal(JSON.stringify(report).includes(secret), false);
});

test('reports omit a secret-containing patch instead of changing an exact source diff', () => {
  const input = scan();
  input.findings[0].patch = { diff: `--- a/secrets.ts\n+++ b/secrets.ts\n-const API_KEY = "${secret}";\n+const API_KEY = process.env.API_KEY;`, status: 'PROPOSED_CHANGE' };
  assert.equal(evidenceReport(input).findings[0].patch, undefined);
  assert.equal(markdownReport(input).includes('Proposed patch (not applied)'), false);
});

test('reports safely ignore circular raw payloads and never fabricate a missing commit', () => {
  const input = scan();
  input.diff.previous = input;
  assert.doesNotThrow(() => JSON.stringify(evidenceReport(input)));
  assert.deepEqual(evidenceReport(null), {});
  assert.deepEqual(sarifReport(null).runs[0].versionControlProvenance, []);
  assert.match(markdownReport(null), /Exploitability and credential validity remain unverified/);
});
