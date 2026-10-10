import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRepository, parseRepository } from '../src/repository.js';

const COMMIT = 'a'.repeat(40);
const TREE = 'b'.repeat(40);

test('GitHub URL parsing accepts repository, .git and explicit branch URLs', () => {
  assert.deepEqual(parseRepository(' https://github.com/example/project.git/ '), { owner: 'example', repo: 'project', url: 'https://github.com/example/project' });
  assert.deepEqual(parseRepository('https://github.com/example/project/tree/feature/security'), { owner: 'example', repo: 'project', url: 'https://github.com/example/project', ref: 'feature/security' });
  assert.equal(parseRepository('https://www.github.com/example/project')?.repo, 'project');
});

test('malformed, credential-bearing and non-GitHub repository URLs are rejected', () => {
  for (const url of ['', null, 'example/project', 'https://github.com/example', 'https://github.com.evil.test/example/project', 'https://github.com@evil.test/example/project', 'https://user:password@github.com/example/project', 'javascript:alert(1)', 'https://github.com:8443/example/project', 'https://github.com/example/project/issues/1', 'https://github.com/example/project/tree/a%2Fb%3Fc', 'https://github.com/example/project/tree/../x', 'https://github.com/example%2Fother/project']) {
    assert.equal(parseRepository(url), null, String(url));
  }
});

function mockedRepository(sources, options = {}) {
  const requests = [];
  const fetch = async (url, init) => {
    requests.push(url);
    if (options.failAll) return new Response('denied', { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1900000000' } });
    if (url === 'https://api.github.com/repos/example/project') return Response.json({ default_branch: 'main', private: false, full_name: 'example/project', html_url: 'https://github.com/example/project' });
    if (url === 'https://api.github.com/repos/example/project/commits/main') return Response.json({ sha: COMMIT, commit: { tree: { sha: TREE } } });
    if (url.includes(`/git/trees/${TREE}`)) return Response.json({ truncated: Boolean(options.truncated), tree: sources.map(source => ({ path: source.path, type: 'blob', mode: '100644', size: source.content.length })) });
    if (url.startsWith(`https://raw.githubusercontent.com/example/project/${COMMIT}/`)) {
      const path = decodeURIComponent(url.slice(`https://raw.githubusercontent.com/example/project/${COMMIT}/`.length));
      if (path === options.failedFile) return new Response('failed', { status: 502 });
      const source = sources.find(item => item.path === path);
      return new Response(source?.content || '', { status: source ? 200 : 404 });
    }
    if (url === 'https://api.osv.dev/v1/querybatch') {
      if (options.osvFailure) throw new Error('OSV offline');
      return Response.json({ results: JSON.parse(init.body).queries.map(() => ({})) });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  return { fetch, requests };
}

test('every source read and evidence record is pinned to the resolved commit', async () => {
  const mock = mockedRepository([{ path: 'src/agent.js', content: 'export const value = eval(input);' }]);
  const stages = [];
  const result = await analyzeRepository('https://github.com/example/project', null, (stage, message, detail) => stages.push({ stage, message, detail }), { fetch: mock.fetch });
  assert.equal(result.commit, COMMIT);
  assert.equal(result.engineVersion.length > 0, true);
  assert.ok(mock.requests.filter(url => url.includes('raw.githubusercontent.com')).every(url => url.includes(`/${COMMIT}/`)));
  assert.ok(result.findings.every(item => item.provenance.every(entry => entry.commit === COMMIT)));
  assert.ok(stages.some(item => item.stage === 'metadata'));
  assert.ok(stages.some(item => item.stage === 'source'));
});

test('OSV failure preserves static findings and marks advisory coverage incomplete', async () => {
  const mock = mockedRepository([{ path: 'src/app.js', content: 'export const result = eval(input);' }, { path: 'package.json', content: '{"dependencies":{"fixture":"1.2.3"}}' }], { osvFailure: true });
  const result = await analyzeRepository('https://github.com/example/project', null, undefined, { fetch: mock.fetch });
  assert.ok(result.findings.length > 0);
  assert.equal(result.osv.status, 'FAILED');
  assert.equal(result.partial, true);
});

test('one unreadable source and truncated trees produce partial scans', async () => {
  const mock = mockedRepository([{ path: 'src/good.js', content: 'export const value = eval(input);' }, { path: 'src/bad.js', content: 'export const bad = true;' }], { failedFile: 'src/bad.js', truncated: true });
  const result = await analyzeRepository('https://github.com/example/project', null, undefined, { fetch: mock.fetch });
  assert.ok(result.coverage.failedFiles.some(item => item.path === 'src/bad.js'));
  assert.equal(result.coverage.treeTruncated, true);
  assert.equal(result.partial, true);
  assert.ok(result.coverage.analyzedFiles.includes('src/good.js'));
});

test('oversized repository limits report skipped source files explicitly', async () => {
  const mock = mockedRepository([{ path: 'src/a.js', content: 'export const a = 1;' }, { path: 'src/b.js', content: 'export const b = 2;' }]);
  const result = await analyzeRepository('https://github.com/example/project', null, undefined, { fetch: mock.fetch, maxFiles: 1 });
  assert.equal(result.coverage.selectedFiles, 1);
  assert.ok(result.coverage.skipped.some(item => item.reason === 'FILE_COUNT_LIMIT'));
  assert.equal(result.coverage.complete, false);
});

test('empty repository analysis does not produce a successful clean scan', async () => {
  const mock = mockedRepository([]);
  const result = await analyzeRepository('https://github.com/example/project', null, undefined, { fetch: mock.fetch });
  assert.equal(result.analyzedFiles.length, 0);
  assert.equal(result.partial, true);
  assert.ok(result.diagnostics.some(item => item.code === 'NO_SUPPORTED_FILES'));
});

test('rate limits and cancellation fail with actionable errors', async () => {
  const mock = mockedRepository([], { failAll: true });
  await assert.rejects(analyzeRepository('https://github.com/example/project', null, undefined, { fetch: mock.fetch }), error => error.code === 'RATE_LIMIT' && Boolean(error.resetAt));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(analyzeRepository('https://github.com/example/project', controller.signal, undefined, { fetch: mock.fetch }), error => error.code === 'CANCELLED');
});
