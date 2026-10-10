import { analyzeSources } from './engine.js';
import { parseDependencies, queryVulnerabilities, fetchWithTimeout, cancellationError } from './dependencies.js';

const DEFAULT_LIMITS = { maxFiles: 120, maxBytes: 2000000, maxFileBytes: 250000, timeoutMs: 15000 };
const STRUCTURAL_SOURCE = /\.(?:[cm]?js|jsx|tsx?|json)$/i;
const TEXT_SOURCE = /\.(?:[cm]?js|jsx|tsx?|py|go|rb|php|java|kt|rs|cs|json|ya?ml|toml|env|ini|sh|sql)$/i;
const MANIFEST = /(?:^|\/)(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|requirements(?:[-_.][^/]*)?\.txt|go\.mod)$/i;
const CONFIG_SOURCE = /(?:^|\/)(?:Dockerfile(?:\.[^/]+)?|\.env(?:\.[^/]+)?|[^/]+\.(?:env|ini))$/i;
const KNOWN_UNSUPPORTED_MANIFEST = /(?:^|\/)(?:yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|uv\.lock|Pipfile(?:\.lock)?|pyproject\.toml|Cargo\.(?:toml|lock)|pom\.xml|build\.gradle(?:\.kts)?|composer\.(?:json|lock)|Gemfile(?:\.lock)?)$/i;
const lexical = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function parseRepository(value) {
  try {
    const trimmed = String(value || '').trim();
    const url = new URL(trimmed);
    if (!['https:', 'http:'].includes(url.protocol) || !['github.com', 'www.github.com'].includes(url.hostname.toLowerCase()) || url.username || url.password || url.port) return null;
    const segments = url.pathname.replace(/\/+$/, '').split('/').slice(1).map(decodeURIComponent);
    if (segments.length < 2 || !segments[0] || !segments[1]) return null;
    const owner = segments[0], repo = segments[1].replace(/\.git$/i, '');
    if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo) || owner === '.' || owner === '..' || repo === '.' || repo === '..') return null;
    if (segments.length > 2 && (segments[2] !== 'tree' || segments.length < 4)) return null;
    const ref = segments.length > 3 ? segments.slice(3).join('/') : undefined;
    if (ref && !validRef(ref)) return null;
    return { owner, repo, url: `https://github.com/${owner}/${repo}`, ...(ref ? { ref } : {}) };
  } catch { return null; }
}

function validRef(ref) {
  return typeof ref === 'string' && ref.length > 0 && ref.length <= 240 && !/[\x00-\x20\x7f\\?*\[\]:]/.test(ref) && !ref.includes('..') && !ref.includes('//') && !ref.includes('@{') && !ref.startsWith('/') && !ref.endsWith('/') && !ref.endsWith('.lock');
}

function scanError(message, code, status) {
  return Object.assign(new Error(message), { code, ...(status ? { status } : {}) });
}

function requestError(response, type) {
  if (response.status === 403 || response.status === 429) {
    const remaining = response.headers?.get?.('x-ratelimit-remaining');
    const reset = response.headers?.get?.('x-ratelimit-reset');
    const retryAfter = response.headers?.get?.('retry-after');
    const rateLimited = response.status === 429 || remaining === '0' || !!retryAfter;
    if (rateLimited) {
      const resetMilliseconds = Number(reset) * 1000;
      const resetAt = /^\d+$/.test(reset || '') && Number.isFinite(resetMilliseconds) && resetMilliseconds <= 8640000000000000 ? new Date(resetMilliseconds).toISOString() : null;
      return Object.assign(scanError(`GitHub public API rate limit reached.${resetAt ? ` The limit resets at ${resetAt}.` : retryAfter ? ` Retry after ${retryAfter} seconds.` : ' Retry later.'}`, 'RATE_LIMIT', response.status), { resetAt, retryAfter });
    }
    return scanError('GitHub denied access to this repository resource. Only public repositories are supported.', 'ACCESS_DENIED', response.status);
  }
  if (response.status === 404) return scanError(type === 'commit' ? 'The requested branch, tag, or commit was not found in this public repository.' : 'Repository not found. Check its URL and confirm that it is public.', type === 'commit' ? 'REF_NOT_FOUND' : 'REPOSITORY_NOT_FOUND', 404);
  if (response.status === 409) return scanError('This repository has no readable commit. Empty repositories cannot be scanned.', 'EMPTY_REPOSITORY', 409);
  return scanError(`GitHub returned HTTP ${response.status}. Retry the scan later.`, 'GITHUB_HTTP_ERROR', response.status);
}

async function githubJSON(path, options, type) {
  const { response, body } = await fetchWithTimeout(`https://api.github.com${path}`, { headers: { Accept: 'application/vnd.github+json' } }, options);
  if (!response.ok) throw requestError(response, type);
  try { return JSON.parse(body); }
  catch { throw scanError('GitHub returned invalid repository data.', 'GITHUB_INVALID_RESPONSE'); }
}

function language(path) {
  if (/\.(?:jsx?|[cm]js)$/i.test(path)) return 'JavaScript';
  if (/\.tsx?$/i.test(path)) return 'TypeScript';
  if (/\.json$/i.test(path)) return 'JSON';
  if (/\.py$/i.test(path)) return 'Python';
  if (/\.go$|(?:^|\/)go\.mod$/i.test(path)) return 'Go';
  if (/requirements(?:[-_.][^/]*)?\.txt$/i.test(path)) return 'Python requirements';
  const ext = path.split('.').pop().toLowerCase();
  return ({ rb: 'Ruby', php: 'PHP', java: 'Java', kt: 'Kotlin', rs: 'Rust', cs: 'C#', yaml: 'YAML', yml: 'YAML', toml: 'TOML', sql: 'SQL', sh: 'Shell' })[ext] || 'Configuration';
}

function selectionPriority(file) {
  return (MANIFEST.test(file.path) ? 500 : 0) + (/(?:agent|mcp|tool|permission|auth|server)/i.test(file.path) ? 150 : 0) + (STRUCTURAL_SOURCE.test(file.path) ? 70 : 0) + (/(?:^|\/)(?:src|app|lib|api)\//i.test(file.path) ? 20 : 0);
}

function chooseFiles(tree, limits) {
  const skipped = [], ignored = [], eligible = [];
  for (const file of tree) {
    if (file.type !== 'blob') { if (file.type === 'commit') skipped.push({ path: file.path, reason: 'SUBMODULE_NOT_FETCHED' }); continue; }
    if (file.mode === '120000') { ignored.push({ path: file.path, reason: 'SYMLINK_NOT_FOLLOWED' }); continue; }
    if (/(?:^|\/)(?:node_modules|vendor|\.git)\//.test(file.path)) { ignored.push({ path: file.path, reason: 'VENDORED_OR_GENERATED' }); continue; }
    if (KNOWN_UNSUPPORTED_MANIFEST.test(file.path)) { skipped.push({ path: file.path, reason: 'DEPENDENCY_FORMAT_UNSUPPORTED' }); continue; }
    if (!TEXT_SOURCE.test(file.path) && !MANIFEST.test(file.path) && !CONFIG_SOURCE.test(file.path)) { ignored.push({ path: file.path, reason: 'FILE_TYPE_UNSUPPORTED' }); continue; }
    if (!Number.isFinite(file.size) || file.size < 0) { skipped.push({ path: file.path, reason: 'SIZE_UNKNOWN' }); continue; }
    if (file.size > limits.maxFileBytes) { skipped.push({ path: file.path, reason: 'FILE_BYTE_LIMIT', bytes: file.size }); continue; }
    eligible.push(file);
  }
  eligible.sort((a, b) => selectionPriority(b) - selectionPriority(a) || lexical(a.path, b.path));
  const selected = [];
  let selectedBytes = 0;
  for (const file of eligible) {
    if (selected.length >= limits.maxFiles) { skipped.push({ path: file.path, reason: 'FILE_COUNT_LIMIT', bytes: file.size }); continue; }
    if (selectedBytes + file.size > limits.maxBytes) { skipped.push({ path: file.path, reason: 'TOTAL_BYTE_LIMIT', bytes: file.size }); continue; }
    selected.push(file); selectedBytes += file.size;
  }
  return { selected, eligible, skipped, ignored, selectedBytes };
}

async function mapLimit(items, limit, mapper) {
  const output = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) { const index = cursor++; output[index] = await mapper(items[index], index); }
  }));
  return output;
}

// All source reads use the commit selected before tree enumeration. A branch
// can move while a scan runs without changing the evidence being inspected.
export async function analyzeRepository(repository, signal, onProgress = () => {}, options = {}) {
  const parsed = parseRepository(typeof repository === 'string' ? repository : repository?.url);
  if (!parsed) throw scanError('Enter a public GitHub repository URL.', 'INVALID_REPOSITORY');
  if (!parsed.ref && typeof repository?.ref === 'string') parsed.ref = repository.ref;
  if (signal?.aborted) throw cancellationError();
  const limits = { ...DEFAULT_LIMITS };
  for (const name of Object.keys(DEFAULT_LIMITS)) {
    if (options[name] !== undefined && Number.isFinite(options[name]) && options[name] > 0) limits[name] = Math.floor(options[name]);
  }
  const requestOptions = { fetch: options.fetch, signal, timeoutMs: limits.timeoutMs };
  const apiRepo = `/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`;
  onProgress('metadata', 'Reading public repository metadata.');
  const metadata = await githubJSON(apiRepo, requestOptions, 'repository');
  if (metadata.private) throw scanError('Private repositories are not supported by this browser scanner.', 'PRIVATE_REPOSITORY');
  if (options.ref !== undefined && typeof options.ref !== 'string') throw scanError('Enter a valid branch, tag, or commit SHA.', 'INVALID_REF');
  const requestedRef = options.ref?.trim() || parsed.ref || metadata.default_branch;
  if (!validRef(requestedRef)) throw scanError('Enter a valid branch, tag, or commit SHA.', 'INVALID_REF');
  onProgress('metadata', `Resolving ${requestedRef} to an immutable commit.`);
  const commitData = await githubJSON(`${apiRepo}/commits/${encodeURIComponent(requestedRef)}`, requestOptions, 'commit');
  const commit = commitData.sha;
  const treeSHA = commitData.commit?.tree?.sha;
  if (!/^[a-f0-9]{40}$/i.test(commit || '') || !/^[a-f0-9]{40}$/i.test(treeSHA || '')) throw scanError('GitHub did not provide a complete commit and tree identity.', 'GITHUB_INVALID_RESPONSE');
  onProgress('metadata', `Enumerating files at commit ${commit.slice(0, 12)}.`);
  const treeData = await githubJSON(`${apiRepo}/git/trees/${treeSHA}?recursive=1`, requestOptions, 'tree');
  if (!Array.isArray(treeData.tree)) throw scanError('GitHub did not return a readable repository tree.', 'GITHUB_INVALID_RESPONSE');
  const tree = treeData.tree.filter(file => typeof file.path === 'string');
  const { selected, eligible, skipped, ignored, selectedBytes } = chooseFiles(tree, limits);
  const failedFiles = [];
  let completed = 0;
  onProgress('source', `Reading ${selected.length} selected source and configuration files.`, { done: 0, total: selected.length });
  const fetched = await mapLimit(selected, 6, async file => {
    if (signal?.aborted) throw cancellationError();
    try {
      const path = file.path.split('/').map(encodeURIComponent).join('/');
      const { response, body } = await fetchWithTimeout(`https://raw.githubusercontent.com/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/${commit}/${path}`, {}, requestOptions);
      if (!response.ok) throw scanError(`Source request returned HTTP ${response.status}.`, 'SOURCE_HTTP_ERROR', response.status);
      const size = new TextEncoder().encode(body).length;
      if (size > limits.maxFileBytes || size > file.size) throw scanError('Source response exceeded its declared tree byte budget.', 'SOURCE_SIZE_MISMATCH');
      if (body.includes('\u0000')) throw scanError('Selected file contains binary data.', 'BINARY_SOURCE');
      return { path: file.path, content: body, size };
    } catch (error) {
      if (error.code === 'CANCELLED' || signal?.aborted) throw cancellationError();
      failedFiles.push({ path: file.path, reason: error.code || 'SOURCE_NETWORK_ERROR', message: error.message });
      return null;
    } finally {
      completed += 1;
      if (!signal?.aborted) onProgress('source', `Read attempt ${completed} of ${selected.length}: ${file.path}`, { done: completed, total: selected.length });
    }
  });
  const sources = fetched.filter(Boolean);
  const diagnostics = [];
  if (treeData.truncated) diagnostics.push({ code: 'TREE_TRUNCATED', message: 'GitHub truncated the repository tree. Coverage is incomplete.' });
  if (!selected.length) diagnostics.push({ code: 'NO_SUPPORTED_FILES', message: 'No files fit the supported scanner scope and configured budgets.' });
  if (failedFiles.length) diagnostics.push({ code: 'SOURCE_READ_FAILURES', message: `${failedFiles.length} selected files could not be read. Findings cover successful reads only.` });
  const unsupportedFormats = skipped.filter(file => file.reason === 'DEPENDENCY_FORMAT_UNSUPPORTED').map(file => file.path);
  if (unsupportedFormats.length) diagnostics.push({ code: 'DEPENDENCY_FORMAT_UNSUPPORTED', message: 'Some dependency formats require unsupported package-manager resolution.', files: unsupportedFormats });
  onProgress('dependencies', 'Parsing package declarations and pinned versions from fetched files.');
  const dependencies = parseDependencies(sources, diagnostics);
  const osv = await queryVulnerabilities(dependencies, { ...requestOptions, onProgress, maxDependencies: options.maxDependencies, maxAdvisories: options.maxAdvisories });
  onProgress('analysis', `Analyzing observed source at ${commit.slice(0, 12)}.`);
  const analysis = await analyzeSources({ repository: parsed, commit, sources, dependencies, osv });
  if (signal?.aborted) throw cancellationError();
  const analyzedFiles = analysis.analyzedFiles || [];
  const dependencyAnalyzedFiles = sources.filter(source => MANIFEST.test(source.path) && !diagnostics.some(diagnostic => diagnostic.file === source.path && diagnostic.code === 'DEPENDENCY_PARSE_FAILED')).map(source => source.path);
  const structuralFiles = sources.filter(source => STRUCTURAL_SOURCE.test(source.path)).map(source => source.path);
  const secretOnlyFiles = sources.filter(source => !STRUCTURAL_SOURCE.test(source.path) && !MANIFEST.test(source.path)).map(source => source.path);
  const analysisIncomplete = (analysis.diagnostics || []).some(diagnostic => /UNRESOLVED|PARSE_ERROR|PATH_LIMIT/.test(diagnostic.code || ''));
  const dependencyIncomplete = diagnostics.some(diagnostic => /DEPENDENCY_PARSE_FAILED|DEPENDENCY_DECLARATION_UNSUPPORTED|GO_REPLACEMENT_UNRESOLVED/.test(diagnostic.code || ''));
  const complete = !treeData.truncated && !failedFiles.length && !skipped.length && !analysisIncomplete && !dependencyIncomplete && selected.length === eligible.length && structuralFiles.every(path => analyzedFiles.includes(path));
  const coverage = {
    totalFiles: tree.filter(file => file.type === 'blob').length,
    treeFiles: tree.filter(file => file.type === 'blob').map(file => file.path).sort(),
    eligibleFiles: eligible.length, selectedFiles: selected.length, readFiles: sources.length,
    selectedPaths: selected.map(file => file.path), analyzedFiles, secretAnalyzedFiles: analysis.secretAnalyzedFiles || [], dependencyAnalyzedFiles,
    skipped: skipped.sort((a, b) => lexical(a.path, b.path)),
    ignored: ignored.sort((a, b) => lexical(a.path, b.path)),
    failedFiles: failedFiles.sort((a, b) => lexical(a.path, b.path)), failures: failedFiles,
    treeTruncated: !!treeData.truncated, selectedBytes,
    readBytes: sources.reduce((sum, source) => sum + source.size, 0),
    maxFiles: limits.maxFiles, maxBytes: limits.maxBytes, maxFileBytes: limits.maxFileBytes,
    languages: [...new Set(sources.map(source => language(source.path)))].sort(),
    parsing: { supported: ['JavaScript/TypeScript AST', 'JSON configuration', 'npm lockfiles and manifests', 'requirements.txt exact pins', 'go.mod require pins'], structuralFiles, secretOnlyFiles, unsupported: unsupportedFormats },
    complete
  };
  const partial = !complete || !sources.length || secretOnlyFiles.length > 0 || ['FAILED', 'PARTIAL'].includes(osv.status) || osv.unresolvedCount > 0 || unsupportedFormats.length > 0;
  const scan = {
    repo: parsed, repoName: `${parsed.owner}/${parsed.repo}`, fullName: `${parsed.owner}/${parsed.repo}`, repository: parsed, url: parsed.url,
    meta: { full_name: metadata.full_name || `${parsed.owner}/${parsed.repo}`, description: metadata.description || '', language: metadata.language || null, default_branch: metadata.default_branch, html_url: parsed.url },
    branch: requestedRef, commit, commitSHA: commit, files: coverage.totalFiles,
    sourceStats: { chosen: selected.length, read: sources.length, bytes: coverage.readBytes },
    coverage, dependencies: analysis.sanitizedDependencies || dependencies, osv: analysis.sanitizedOSV || osv,
    engineVersion: analysis.engineVersion, findings: analysis.findings || [], graph: analysis.graph || { nodes: [], edges: [] }, paths: analysis.paths || [],
    diagnostics: [...diagnostics, ...osv.diagnostics, ...(analysis.diagnostics || [])], analyzedFiles, secretAnalyzedFiles: analysis.secretAnalyzedFiles || [], dependencyAnalyzedFiles,
    partial, scope: 'Public repository static analysis: JavaScript/TypeScript AST, JSON capability configuration, redacted secret patterns, and OSV checks for exact parsed package versions. Runtime exploitability is unverified.',
    createdAt: new Date().toISOString()
  };
  onProgress('complete', `Scan complete at ${commit.slice(0, 12)}${partial ? ' with coverage limitations' : ''}.`, { done: sources.length, total: selected.length });
  return scan;
}
