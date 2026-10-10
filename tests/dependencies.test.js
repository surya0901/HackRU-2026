import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseDependencies, queryVulnerabilities } from '../src/dependencies.js';

test('npm ranges remain unresolved; lockfile packages establish exact versions', async () => {
  const lockfile = await readFile(new URL('./fixtures/package-lock.json', import.meta.url), 'utf8');
  const dependencies = parseDependencies([
    { path: 'package.json', content: JSON.stringify({ dependencies: { ranged: '^1.2.0', exact: '3.4.5', local: 'workspace:*' } }) },
    { path: 'package-lock.json', content: lockfile }
  ]);
  assert.equal(dependencies.find(item => item.name === 'ranged').version, null);
  assert.equal(dependencies.find(item => item.name === 'local').exact, false);
  assert.equal(dependencies.find(item => item.name === 'exact').version, '3.4.5');
  assert.equal(dependencies.find(item => item.name === 'example-exact').version, '1.2.3');
  assert.equal(dependencies.find(item => item.name === 'example-transitive').version, '2.0.1');
  assert.ok(dependencies.every(item => item.file && item.line > 0 && item.provenance.status === 'OBSERVED'));
});

test('requirements pins differ from constraints, markers and unresolved includes', () => {
  const diagnostics = [];
  const dependencies = parseDependencies([{ path: 'requirements.txt', content: 'Requests==2.31.0\nflask>=2.0,<3.0\npackage_name[extra]==1.2.3; python_version > "3.9"\n-r base.txt\n' }], diagnostics);
  assert.equal(dependencies.find(item => item.name === 'requests').version, '2.31.0');
  assert.equal(dependencies.find(item => item.name === 'flask').version, null);
  assert.equal(dependencies.find(item => item.name === 'package-name').version, '1.2.3');
  assert.ok(diagnostics.some(item => item.code === 'DEPENDENCY_DECLARATION_UNSUPPORTED'));
});

test('Go require blocks resolve exact versions, replacements stay unverified', () => {
  const content = 'module example.com/app\nrequire (\n example.com/tool v1.2.3\n example.com/other v2.3.4\n)\nreplace example.com/tool => ../tool\n';
  const deps = parseDependencies([{ path: 'go.mod', content }]);
  assert.equal(deps.find(item => item.name === 'example.com/tool').version, null);
  assert.equal(deps.find(item => item.name === 'example.com/other').version, 'v2.3.4');
});

test('malformed dependency JSON yields diagnostics without losing other files', () => {
  const diagnostics = [];
  const deps = parseDependencies([{ path: 'package.json', content: '{ nope' }, { path: 'requirements.txt', content: 'requests==2.31.0' }], diagnostics);
  assert.equal(deps.length, 1);
  assert.equal(diagnostics[0].code, 'DEPENDENCY_PARSE_FAILED');
  assert.equal(parseDependencies(null, []).length, 0);
  assert.equal(parseDependencies([null, { path: 'package.json' }], []).length, 0);
});

test('OSV queries only repository-observed exact versions and preserves affected ranges', async () => {
  const dependencies = parseDependencies([{ path: 'package.json', content: JSON.stringify({ dependencies: { fixed: '1.2.3', ranged: '^1.2.3' } }) }]);
  const requests = [];
  const advisory = { id: 'GHSA-test-0001', summary: 'Test advisory', affected: [{ package: { name: 'fixed', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.4' }] }] }] };
  const result = await queryVulnerabilities(dependencies, { fetch: async (url, init) => {
    requests.push({ url, body: init?.body ? JSON.parse(init.body) : null });
    return new Response(JSON.stringify(url.endsWith('/querybatch') ? { results: [{ vulns: [{ id: advisory.id }] }] } : advisory), { status: 200 });
  } });
  assert.equal(requests[0].body.queries.length, 1);
  assert.deepEqual(requests[0].body.queries[0], { package: { name: 'fixed', ecosystem: 'npm' }, version: '1.2.3' });
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.unresolvedCount, 1);
  assert.equal(result.vulnerabilities[0].version, '1.2.3');
  assert.deepEqual(result.vulnerabilities[0].affectedRanges, advisory.affected[0].ranges);
  assert.match(result.vulnerabilities[0].source, /osv.dev\/vulnerability/);
});

test('OSV network or malformed response failures remain visible without a false clean result', async () => {
  const deps = parseDependencies([{ path: 'package.json', content: '{"dependencies":{"fixed":"1.2.3"}}' }]);
  for (const fetch of [async () => { throw new Error('offline'); }, async () => new Response('not json', { status: 200 }), async () => new Response('{"results":[]}', { status: 200 })]) {
    const result = await queryVulnerabilities(deps, { fetch });
    assert.equal(result.status, 'FAILED');
    assert.equal(result.checkedCount, 0);
    assert.ok(result.diagnostics.length > 0);
  }
});

test('an unresolved-only inventory sends no vulnerability requests', async () => {
  const deps = parseDependencies([{ path: 'package.json', content: '{"dependencies":{"ranged":"^1.2.3"}}' }]);
  const result = await queryVulnerabilities(deps, { fetch: () => { assert.fail('No exact versions should be queried'); } });
  assert.equal(result.status, 'NOT_NEEDED');
  assert.equal(result.unresolvedCount, 1);
});
