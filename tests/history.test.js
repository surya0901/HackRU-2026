import test from 'node:test';
import assert from 'node:assert/strict';
import { HISTORY_KEY, loadHistory, saveScan } from '../src/history.js';

const COMMIT = 'a'.repeat(40);
const secret = 'sk-proj-' + 'AbCdEfGh1234567890'.repeat(4);
function storage() {
  const items = new Map();
  return { getItem: key => items.get(key) ?? null, setItem: (key, value) => items.set(key, value), items };
}
function scan(overrides = {}) {
  return { repo: 'example/project', commit: COMMIT, engineVersion: '1.0.0', analyzedFiles: ['src/agent.js'], findings: [{ fingerprint: 'stable', rule: 'secret-exposed', provenance: [{ repository: 'example/project', commit: COMMIT, file: 'src/agent.js', line: 1, snippet: `const OPENAI_API_KEY = "${secret}";` }] }], paths: [], graph: { nodes: [], edges: [] }, coverage: { analyzedFiles: ['src/agent.js'], complete: true, treeFiles: ['src/agent.js'], treeTruncated: false }, ...overrides };
}

test('scan history persists sanitized structured evidence without raw sources or nested scans', () => {
  const target = storage();
  const result = saveScan(scan({ sources: [{ path: 'src/agent.js', content: secret }], diff: { previous: { sources: [{ content: secret }] } }, previous: scan() }), target);
  assert.equal(result.scans.length, 1);
  const serialized = target.getItem(HISTORY_KEY);
  assert.equal(serialized.includes(secret), false);
  assert.equal(serialized.includes('"sources"'), false);
  assert.equal(serialized.includes('"previous"'), false);
  assert.equal(serialized.includes('"diff"'), false);
  const history = loadHistory(target);
  assert.equal(history.scans.length, 1);
  assert.equal(history.scans[0].findings[0].provenance[0].line, 1);
});

test('history deduplicates the same repository commit and keeps at most ten scans', () => {
  const target = storage();
  saveScan(scan(), target);
  saveScan(scan(), target);
  assert.equal(loadHistory(target).scans.length, 1);
  for (let index = 1; index < 14; index++) {
    const commit = index.toString(16).padStart(40, '0');
    saveScan(scan({ commit, findings: [] }), target);
  }
  assert.equal(loadHistory(target).scans.length, 10);
});

test('storage read and quota errors warn without crashing the scanner', () => {
  const blocked = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('quota'); } };
  assert.deepEqual(loadHistory(blocked).scans, []);
  assert.ok(loadHistory(blocked).warnings.length > 0);
  const result = saveScan(scan(), blocked);
  assert.ok(result.warnings.some(warning => /not persisted/.test(warning)));
});

test('legacy, corrupt and evidence-free history records cannot be reused as proof', () => {
  const target = storage();
  for (const value of ['not json', JSON.stringify({ version: 2, scans: [scan()] }), JSON.stringify({ version: 3, scans: [{ ...scan(), commit: '', findings: [] }] }), JSON.stringify({ version: 3, scans: [{ ...scan(), findings: [{ fingerprint: 'old', provenance: [] }] }] })]) {
    target.setItem(HISTORY_KEY, value);
    const result = loadHistory(target);
    assert.equal(result.scans.length, 0);
    assert.ok(result.warnings.length > 0);
  }
});

test('source evidence with a mismatched commit is rejected from history', () => {
  const target = storage();
  const invalid = scan({ findings: [{ fingerprint: 'untrusted', provenance: [{ file: 'src/agent.js', line: 4, commit: 'b'.repeat(40) }] }] });
  const result = saveScan(invalid, target);
  assert.equal(result.scans.length, 0);
  assert.ok(result.warnings.some(warning => /commit-pinned evidence/.test(warning)));
});

test('bounded history marks truncated evidence coverage as incomplete', () => {
  const target = storage();
  const files = Array.from({ length: 900 }, (_, index) => `src/file-${index}.js`);
  const result = saveScan(scan({ analyzedFiles: files, findings: [], coverage: { complete: true, analyzedFiles: files, treeFiles: files, treeTruncated: false } }), target);
  assert.equal(result.scans[0].coverage.complete, false);
  assert.equal(result.scans[0].coverage.treeTruncated, true);
  assert.ok(result.scans[0].diagnostics.some(item => item.code === 'HISTORY_TRUNCATED'));
});

test('history normalizes legacy repository shapes and rejects a stored navigation URL', () => {
  const target = storage();
  const saved = saveScan(scan({ repo: undefined, fullName: 'example/project', repository: { owner: 'example', repo: 'project', url: 'javascript:alert(1)' } }), target);
  assert.deepEqual(saved.scans[0].repo, { owner: 'example', repo: 'project', url: 'https://github.com/example/project' });
  assert.equal(loadHistory(target).scans[0].repo.url, 'https://github.com/example/project');
});
