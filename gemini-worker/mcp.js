const MCP_VERSION = '2025-06-18';
// Two-repository comparisons must stay below Cloudflare's per-request
// subrequest ceiling after GitHub metadata, source, and OSV calls.
const MAX_FILES = 18;
const MAX_FILE_BYTES = 90_000;
const MAX_TOTAL_BYTES = 900_000;

const SOURCE_FILE = /(^|\/)(package\.json|requirements[^/]*\.txt|go\.mod|Dockerfile|SECURITY\.md|[^/]*\.(js|jsx|ts|tsx|py|go|java|rb|php|json|ya?ml|env))$/i;
const SKIP_PATH = /(^|\/)(node_modules|vendor|dist|build|coverage|\.git)(\/|$)|\.min\.js$/i;

const RULES = [
  { id: 'CWE-95', severity: 'high', points: 15, title: 'Dynamic code execution', pattern: /\b(eval\s*\(|new\s+Function\s*\()/g, fix: 'Replace dynamic evaluation with an explicit parser or allowlisted operation map.' },
  { id: 'CWE-78', severity: 'high', points: 15, title: 'Possible operating-system command execution', pattern: /\b(execSync|exec|spawnSync|spawn)\s*\(/g, fix: 'Use an allowlist and avoid passing untrusted text to system commands.' },
  { id: 'CWE-79', severity: 'high', points: 14, title: 'Raw HTML insertion', pattern: /\b(innerHTML\s*=|dangerouslySetInnerHTML\b)/g, fix: 'Render text safely or sanitize trusted markup before insertion.' },
  { id: 'CWE-89', severity: 'high', points: 14, title: 'Possible dynamic database query', pattern: /\b(query|execute)\s*\(\s*(`[^`]*\$\{|[^)]*\+\s*(req\.|request\.|params|body|query))/g, fix: 'Use parameterized queries instead of constructing SQL with input text.' },
  { id: 'CWE-942', severity: 'medium', points: 9, title: 'Broad cross-origin access', pattern: /Access-Control-Allow-Origin[^\n]*\*|cors\s*\(\s*\)/gi, fix: 'Allow only the origins that need access.' },
  { id: 'CWE-327', severity: 'medium', points: 8, title: 'Weak cryptographic hash', pattern: /createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\(/gi, fix: 'Use a modern algorithm appropriate for the security purpose.' }
];

const SECRET_RULES = [
  { id: 'SECRET-AWS', title: 'Possible AWS access key', points: 24, pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'SECRET-GITHUB', title: 'Possible GitHub token', points: 24, pattern: /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/g },
  { id: 'SECRET-PRIVATE-KEY', title: 'Private key material', points: 25, pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { id: 'SECRET-API-KEY', title: 'Possible hard-coded credential', points: 16, pattern: /\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"\n]{12,}['"]/gi }
];

function rpc(id, result) {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), { headers: { 'content-type': 'application/json' } });
}

function rpcError(id, code, message) {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }), { status: code === -32600 ? 400 : 200, headers: { 'content-type': 'application/json' } });
}

function parseRepo(value) {
  const cleaned = String(value || '').trim().replace(/\.git$/, '').replace(/\/$/, '');
  const match = cleaned.match(/(?:https?:\/\/github\.com\/)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  if (!match) throw new Error('Use a public GitHub URL such as https://github.com/owner/repository');
  return { owner: match[1], repo: match[2] };
}

async function github(path, env) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'Heimdall-Security-MCP' };
  if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  const response = await fetch(`https://api.github.com${path}`, { headers });
  if (!response.ok) throw new Error(response.status === 404 ? 'Public repository not found' : `GitHub request failed (${response.status})`);
  return response.json();
}

function lineNumber(content, offset) { return content.slice(0, offset).split('\n').length; }
function safeSnippet(content, offset) {
  return content.slice(Math.max(0, offset - 45), Math.min(content.length, offset + 90)).replace(/[A-Za-z0-9_\-]{12,}/g, value => `${value.slice(0, 4)}…redacted`);
}
function finding(rule, file, content, match) {
  return {
    id: `${rule.id}:${file}:${lineNumber(content, match.index)}`, rule: rule.id,
    severity: rule.severity || 'critical', points: rule.points, title: rule.title,
    evidence: { file, line: lineNumber(content, match.index), redacted_excerpt: safeSnippet(content, match.index) },
    fix: rule.fix || 'Revoke the exposed value, remove it from the repository, and store the replacement in a secret manager.',
    confidence: 'Observed source evidence'
  };
}
function scanText(file, content) {
  const results = [];
  for (const rule of [...SECRET_RULES, ...RULES]) {
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(content)) && results.length < 30) {
      const nearby = content.slice(Math.max(0, match.index - 50), match.index + 100);
      if (/example|placeholder|your[_-]?(?:key|token)|changeme|test[_-]?secret/i.test(nearby)) continue;
      results.push(finding(rule, file, content, match));
      if (!rule.pattern.global) break;
    }
  }
  return results;
}

function dependencies(files) {
  const result = [];
  for (const file of files) {
    if (/package\.json$/i.test(file.path)) {
      try {
        const pkg = JSON.parse(file.content);
        for (const [name, raw] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
          const version = String(raw).match(/\d+\.\d+\.\d+/)?.[0];
          if (version) result.push({ package: { ecosystem: 'npm', name }, version, file: file.path });
        }
      } catch (_) {}
    }
    if (/requirements[^/]*\.txt$/i.test(file.path)) {
      for (const row of file.content.split('\n')) {
        const match = row.trim().match(/^([A-Za-z0-9_.-]+)==([0-9][^\s;#]*)/);
        if (match) result.push({ package: { ecosystem: 'PyPI', name: match[1] }, version: match[2], file: file.path });
      }
    }
  }
  return result.slice(0, 100);
}

async function osvFindings(items) {
  if (!items.length) return { available: true, findings: [] };
  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: items.map(item => ({ package: item.package, version: item.version })) })
    });
    if (!response.ok) throw new Error('OSV unavailable');
    const data = await response.json();
    const findings = [];
    data.results?.forEach((result, index) => result.vulns?.slice(0, 4).forEach(vuln => findings.push({
      id: `OSV:${vuln.id}:${items[index].package.name}`, rule: 'OSV-DEPENDENCY', severity: 'high', points: 12,
      title: `Known vulnerability in ${items[index].package.name}@${items[index].version}`,
      evidence: { file: items[index].file, advisory: vuln.id }, fix: 'Upgrade to a non-affected release and run the project tests.',
      confidence: 'OSV advisory match'
    })));
    return { available: true, findings };
  } catch (_) { return { available: false, findings: [] }; }
}

async function scanRepository(input, env) {
  const repo = parseRepo(input);
  const meta = await github(`/repos/${repo.owner}/${repo.repo}`, env);
  if (meta.private) throw new Error('Only public repositories are supported');
  const branch = meta.default_branch;
  const [tree, commit] = await Promise.all([
    github(`/repos/${repo.owner}/${repo.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`, env),
    github(`/repos/${repo.owner}/${repo.repo}/commits/${encodeURIComponent(branch)}`, env)
  ]);
  const chosen = (tree.tree || []).filter(item => item.type === 'blob' && item.size <= MAX_FILE_BYTES && SOURCE_FILE.test(item.path) && !SKIP_PATH.test(item.path)).sort((a, b) => a.size - b.size).slice(0, MAX_FILES);
  let total = 0;
  const files = [];
  for (const item of chosen) {
    if (total + item.size > MAX_TOTAL_BYTES) break;
    const raw = await fetch(`https://raw.githubusercontent.com/${repo.owner}/${repo.repo}/${encodeURIComponent(branch)}/${item.path}`);
    if (!raw.ok) continue;
    const content = await raw.text();
    total += content.length;
    files.push({ path: item.path, content });
  }
  const findings = files.flatMap(file => scanText(file.path, file.content));
  const paths = new Set((tree.tree || []).map(item => item.path.toLowerCase()));
  if (![...paths].some(path => /(^|\/)security\.md$/.test(path))) findings.push({ id: 'SECURITY-POLICY', rule: 'PROCESS', severity: 'medium', points: 7, title: 'No security reporting policy detected', evidence: { file: 'repository root', observed: 'SECURITY.md not found' }, fix: 'Add SECURITY.md with a private reporting route.', confidence: 'Inferred control gap' });
  if (![...paths].some(path => /^\.github\/workflows\/.*(?:codeql|security|scan).*\.ya?ml$/.test(path))) findings.push({ id: 'SECURITY-WORKFLOW', rule: 'OWASP-A08', severity: 'high', points: 14, title: 'No dedicated security workflow detected', evidence: { file: '.github/workflows/', observed: 'Recognizable security workflow not found' }, fix: 'Add CodeQL or an equivalent scanner to pull requests.', confidence: 'Inferred control gap' });
  const deps = dependencies(files);
  const osv = await osvFindings(deps);
  findings.push(...osv.findings);
  const unique = [...new Map(findings.map(item => [item.id, item])).values()].sort((a, b) => b.points - a.points);
  return {
    repository: meta.full_name, url: meta.html_url, branch, commit: commit.sha,
    score: Math.max(12, 100 - unique.reduce((sum, item) => sum + item.points, 0)),
    findings: unique.slice(0, 40),
    coverage: { public_repository: true, files_checked: files.length, selected_files_limit: MAX_FILES, bytes_read: total, tree_truncated: Boolean(tree.truncated), code_executed: false, osv_available: osv.available },
    disclaimer: 'A bounded static review and prioritization score, not proof that the repository is safe or exploitable.'
  };
}

async function callTool(name, args, env) {
  if (name === 'scan_repository') return scanRepository(args?.repository_url, env);
  if (name === 'check_reference') {
    const [project, reference] = await Promise.all([scanRepository(args?.project_repository_url, env), scanRepository(args?.reference_repository_url, env)]);
    const critical = reference.findings.filter(item => item.severity === 'critical').length;
    const high = reference.findings.filter(item => item.severity === 'high').length;
    return {
      intended_use: String(args?.intended_use || '').slice(0, 1200), project, reference,
      deterministic_decision: critical ? 'Do not add yet' : high ? 'Use after changes' : 'Review before using',
      explanation_instruction: 'Explain how the observed findings affect the intended use. Cite finding IDs. Do not invent exploitability or claim a fix is complete without a rescan.'
    };
  }
  throw new Error('Unknown tool');
}

const tools = [
  {
    name: 'scan_repository',
    description: 'Perform a bounded, read-only Heimdall security scan of a public GitHub repository. Returns redacted evidence, OSV package matches, a readiness score, and explicit coverage limits. Never executes repository code.',
    inputSchema: { type: 'object', properties: { repository_url: { type: 'string', description: 'Public GitHub repository URL' } }, required: ['repository_url'], additionalProperties: false }
  },
  {
    name: 'check_reference',
    description: 'Compare a developer project with a public reference repository for a stated intended use. Scans both repositories and returns a deterministic integration decision with redacted evidence.',
    inputSchema: { type: 'object', properties: {
      project_repository_url: { type: 'string' }, reference_repository_url: { type: 'string' }, intended_use: { type: 'string', maxLength: 1200 }
    }, required: ['project_repository_url', 'reference_repository_url', 'intended_use'], additionalProperties: false }
  }
];

export async function handleMcp(request, env) {
  if (request.method === 'GET') return new Response('Heimdall MCP is ready', { headers: { 'content-type': 'text/plain' } });
  if (request.method !== 'POST') return new Response(null, { status: 405 });
  if (env.MCP_AUTH_TOKEN && request.headers.get('authorization') !== `Bearer ${env.MCP_AUTH_TOKEN}`) return new Response('Unauthorized', { status: 401, headers: { 'www-authenticate': 'Bearer' } });
  let body;
  try { body = await request.json(); } catch (_) { return rpcError(null, -32700, 'Invalid JSON'); }
  const { id, method, params } = body || {};
  if (method === 'initialize') return rpc(id, { protocolVersion: MCP_VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'heimdall-security', title: 'Heimdall Security', version: '1.0.0' }, instructions: 'Use Heimdall for public GitHub repository security checks. Cite finding IDs and preserve its coverage limits.' });
  if (method === 'notifications/initialized') return new Response(null, { status: 202 });
  if (method === 'ping') return rpc(id, {});
  if (method === 'tools/list') return rpc(id, { tools });
  if (method === 'tools/call') {
    try {
      const result = await callTool(params?.name, params?.arguments || {}, env);
      return rpc(id, { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false });
    } catch (error) {
      return rpc(id, { content: [{ type: 'text', text: error?.message || 'Tool failed' }], isError: true });
    }
  }
  return rpcError(id, -32601, 'Method not found');
}
