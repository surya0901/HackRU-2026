import test from 'node:test';
import assert from 'node:assert/strict';
import { compareScans } from '../src/verification.js';

const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);
const evidence = (file = 'src/agent.ts') => ({ repository: 'example/project', commit: COMMIT_A, file, line: 4, snippet: 'tools: [customerDelete]', rule: 'sensitive-tool' });
const finding = overrides => ({ fingerprint: 'stable-finding', rule: 'sensitive-tool', file: 'src/agent.ts', provenance: [evidence()], ...overrides });
const path = overrides => ({ fingerprint: 'stable-path', status: 'DERIVED', staticStatus: 'REACHABLE', provenance: [evidence()], nodeIds: ['agent', 'tool', 'sink'], edgeIds: ['agent-tool', 'tool-sink'], edges: [{ id: 'agent-tool', from: 'agent', to: 'tool', relation: 'CAN_CALL', status: 'OBSERVED', evidence: [evidence()] }, { id: 'tool-sink', from: 'tool', to: 'sink', relation: 'WRITES', status: 'OBSERVED', evidence: [evidence()] }], ...overrides });
const scan = overrides => ({ repo: 'example/project', commit: COMMIT_A, engineVersion: '1.0.0', findings: [finding()], paths: [path()], analyzedFiles: ['src/agent.ts'], coverage: { analyzedFiles: ['src/agent.ts'], complete: true, treeFiles: ['src/agent.ts'], treeTruncated: false, failedFiles: [], skipped: [] }, ...overrides });
const fixed = overrides => scan({ commit: COMMIT_B, findings: [], paths: [], ...overrides });

test('changed source identifies the specific absent finding and graph path', () => {
  const result = compareScans(scan(), fixed());
  assert.equal(result.available, true);
  assert.equal(result.counts.noLongerDetected, 1);
  assert.equal(result.paths.counts.noLongerDetected, 1);
  assert.equal(result.paths.noLongerReachable[0].verification, 'NO_LONGER_DETECTED');
  assert.match(result.noLongerDetected[0].verificationReason, /static finding is no longer detected/);
  assert.equal('previous' in result, false);
});

test('line movement retains stable findings and paths', () => {
  const currentFinding = finding({ provenance: [{ ...evidence(), commit: COMMIT_B, line: 99 }] });
  const result = compareScans(scan(), fixed({ findings: [currentFinding], paths: [path()] }));
  assert.equal(result.counts.unchanged, 1);
  assert.equal(result.counts.noLongerDetected, 0);
  assert.equal(result.paths.counts.unchanged, 1);
});

test('new fingerprints are added, duplicates are deduplicated', () => {
  const result = compareScans(scan(), fixed({ findings: [finding({ fingerprint: 'new-finding' }), finding({ fingerprint: 'new-finding' })] }));
  assert.equal(result.counts.added, 1);
  assert.equal(result.counts.noLongerDetected, 1);
});

for (const [name, overrides, reason] of [
  ['same commit', { commit: COMMIT_A }, /same commit/],
  ['different engine', { engineVersion: '2.0.0' }, /engine changed/],
  ['different repository', { repo: 'example/other' }, /different repositories/],
  ['missing commit', { commit: '' }, /commit is missing/],
  ['missing engine metadata', { engineVersion: '' }, /version is missing/],
  ['zero analyzed files', { analyzedFiles: [], coverage: { analyzedFiles: [], complete: true } }, /analyzed no supported files/],
  ['incomplete coverage', { coverage: { complete: false, analyzedFiles: ['src/agent.ts'] } }, /incomplete source coverage/],
  ['tree truncation', { coverage: { treeTruncated: true, analyzedFiles: ['src/agent.ts'] } }, /tree is truncated/],
  ['parse failure', { diagnostics: [{ code: 'PARSE_ERROR', file: 'src/agent.ts' }] }, /Analysis of src\/agent.ts failed/],
  ['unresolved agent configuration', { diagnostics: [{ code: 'UNRESOLVED_AGENT_CONFIG', file: 'src/agent.ts' }] }, /Analysis of src\/agent.ts failed/],
  ['traversal limit', { diagnostics: [{ code: 'PATH_LIMIT', file: '' }] }, /incomplete analysis/],
  ['fetch failure', { coverage: { complete: false, failedFiles: [{ path: 'src/agent.ts', reason: 'HTTP 502' }] } }, /Analysis of src\/agent.ts failed/],
  ['malformed finding collection', { findings: null }, /no valid findings collection/]
]) {
  test(`absence remains unverified for ${name}`, () => {
    const result = compareScans(scan(), fixed(overrides));
    assert.equal(result.counts.noLongerDetected, 0);
    assert.equal(result.counts.unverified, 1);
    assert.match(result.unverified[0].verificationReason, reason);
  });
}

test('a skipped original file cannot be interpreted as a resolved finding', () => {
  const result = compareScans(scan(), fixed({ analyzedFiles: ['src/other.ts'], coverage: { complete: false, skipped: [{ path: 'src/agent.ts', reason: 'File limit' }] } }));
  assert.equal(result.counts.noLongerDetected, 0);
  assert.match(result.unverified[0].verificationReason, /not successfully analyzed/);
});

test('shrinking source coverage without a proven file deletion is inconclusive', () => {
  const before = scan({ analyzedFiles: ['src/agent.ts', 'src/tools.ts'] });
  const result = compareScans(before, fixed({ coverage: { complete: true, treeFiles: ['src/agent.ts', 'src/tools.ts'], treeTruncated: false } }));
  assert.equal(result.counts.noLongerDetected, 0);
  assert.match(result.unverified[0].verificationReason, /Source coverage changed/);
});

test('immutable full repository tree can prove a prior file was deleted', () => {
  const current = fixed({ analyzedFiles: ['src/remaining.ts'], coverage: { complete: true, analyzedFiles: ['src/remaining.ts'], treeFiles: ['src/remaining.ts'], treeTruncated: false } });
  assert.equal(compareScans(scan(), current).counts.noLongerDetected, 1);
  assert.equal(compareScans(scan(), { ...current, coverage: { ...current.coverage, treeTruncated: true } }).counts.noLongerDetected, 0);
});

test('missing or unpinned evidence never becomes successful verification', () => {
  for (const malformed of [finding({ provenance: [] }), finding({ provenance: [{ file: 'src/agent.ts', line: 3 }] }), finding({ provenance: [{ ...evidence(), line: 0 }] }), finding({ fingerprint: '' })]) {
    const result = compareScans(scan({ findings: [malformed] }), fixed());
    assert.equal(result.counts.noLongerDetected, 0);
    assert.equal(result.counts.unverified, 1);
  }
});

test('advisory disappears only with a complete OSV result and analyzed manifest', () => {
  const advisory = finding({ rule: 'dependency-vulnerability', dependency: { ecosystem: 'npm', name: 'test-package', version: '1.0.0' }, advisoryId: 'GHSA-test-0001', provenance: [evidence('package-lock.json')] });
  const before = scan({ findings: [advisory], analyzedFiles: ['package-lock.json'] });
  const current = fixed({ analyzedFiles: ['package-lock.json'], dependencies: [], coverage: { complete: true, analyzedFiles: ['package-lock.json'], treeFiles: ['package-lock.json'], treeTruncated: false } });
  for (const status of ['FAILED', 'PARTIAL', undefined]) {
    assert.equal(compareScans(before, { ...current, osv: { status } }).counts.noLongerDetected, 0);
  }
  assert.equal(compareScans(before, { ...current, osv: { status: 'COMPLETE' } }).counts.noLongerDetected, 1);
  assert.equal(compareScans(before, { ...current, osv: { status: 'NOT_NEEDED' } }).counts.noLongerDetected, 1);
  assert.equal(compareScans(before, { ...current, analyzedFiles: ['src/other.ts'], osv: { status: 'NOT_NEEDED' } }).counts.noLongerDetected, 0);
});

test('a mutable advisory feed or an unresolved version cannot verify a dependency source fix', () => {
  const dependency = { ecosystem: 'npm', name: 'test-package', version: '1.0.0', exact: true };
  const advisory = finding({ rule: 'osv-dependency-advisory', dependency, advisoryId: 'GHSA-test-0001' });
  const before = scan({ findings: [advisory], dependencies: [dependency] });
  const unchangedPackage = fixed({ dependencies: [dependency], osv: { status: 'COMPLETE' } });
  assert.equal(compareScans(before, unchangedPackage).counts.noLongerDetected, 0);
  assert.match(compareScans(before, unchangedPackage).unverified[0].verificationReason, /same package version/);
  const unresolvedPackage = { ...unchangedPackage, dependencies: [{ ...dependency, version: null, exact: false }] };
  assert.equal(compareScans(before, unresolvedPackage).counts.noLongerDetected, 0);
  const upgradedPackage = { ...unchangedPackage, dependencies: [{ ...dependency, version: '1.0.1' }] };
  assert.equal(compareScans(before, upgradedPackage).counts.noLongerDetected, 1);
  assert.equal(compareScans(before, { ...upgradedPackage, dependencies: undefined }).counts.noLongerDetected, 0);
});

test('path evidence must be complete across every relationship', () => {
  const before = scan({ paths: [path({ provenance: [evidence(), evidence('src/tool.ts')] })], analyzedFiles: ['src/agent.ts', 'src/tool.ts'] });
  const result = compareScans(before, fixed({ coverage: { complete: true, treeFiles: ['src/agent.ts', 'src/tool.ts'], treeTruncated: false } }));
  assert.equal(result.paths.counts.noLongerDetected, 0);
  assert.equal(result.paths.counts.unverified, 1);
  const malformedPath = path({ edges: [{ id: 'agent-tool', from: 'agent', to: 'tool', status: 'OBSERVED', evidence: [] }] });
  assert.equal(compareScans(scan({ paths: [malformedPath] }), fixed()).paths.counts.noLongerDetected, 0);
  assert.equal(compareScans(scan(), fixed({ pathAnalysisComplete: false })).paths.counts.noLongerDetected, 0);
});

test('malformed scans fail safely without proclaiming a clean result', () => {
  for (const malformed of [null, undefined, 'invalid', {}, { findings: [] }]) {
    const result = compareScans(scan(), malformed);
    assert.equal(result.counts.noLongerDetected, 0);
    assert.equal(result.counts.unverified, 1);
  }
});
