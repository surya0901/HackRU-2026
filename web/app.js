const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
const esc = (value = '') => String(value).replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

const modal = $('#modal');
const modalPanel = $('#modal > div');
const bar = $('#bar');
const modalTitle = $('#mt');
const modalProgress = $('#mp');
const repoInput = $('#repo');
const compareProjectInput = $('#compareProject');
const toolRepoInput = $('#toolRepo');
const useCaseInput = $('#useCase');
const repoError = $('#repoError');
let scanAbortController = null;
let result = null;
let integrationResult = null;
let lastFocused = null;
let replayTimer = null;
let drawerReturnFocus = null;
let scanMode = 'project';

function parseRepository(value) {
  const trimmed = String(value || '').trim().replace(/\.git\/?$/i, '');
  const match = trimmed.match(/^https?:\/\/(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/?$/i);
  if (!match) return null;
  return {
    owner: match[1],
    repo: match[2],
    url: `https://github.com/${match[1]}/${match[2]}`
  };
}

async function github(path, signal) {
  const response = await fetch(`https://api.github.com${path}`, {
    headers: { Accept: 'application/vnd.github+json' },
    signal
  });
  if (!response.ok) {
    const error = new Error(response.status === 404
      ? 'Repository not found. Confirm that it is public and the URL is correct.'
      : response.status === 403
        ? 'GitHub’s public API limit was reached. Wait a moment, then try again.'
        : `GitHub returned an error (${response.status}). Please try again.`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

const MAX_SOURCE_FILES = 72;
const MAX_SOURCE_BYTES = 1_400_000;
const HISTORY_KEY = 'heimdall-scan-history-v2';
const TEXT_EXTENSIONS = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|java|kt|rs|cs|json|ya?ml|toml|env|ini|sh|sql|md)$/i;
const IMPORTANT_FILES = /(?:^|\/)(?:package\.json|requirements(?:-[^/]+)?\.txt|go\.mod|pyproject\.toml|dockerfile|\.env(?:\.[^/]+)?|mcp[^/]*\.json|[^/]*(?:agent|auth|security|route|api|server|tool)[^/]*)$/i;

function decodeBase64(value) {
  try {
    const bytes = Uint8Array.from(atob(String(value || '').replace(/\n/g, '')), char => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch (_) { return ''; }
}

function redactSecret(value) {
  const text = String(value || '');
  if (text.length < 8) return '••••';
  return `${text.slice(0, 4)}…${text.slice(-3)}`;
}

function shannonEntropy(value) {
  const text = String(value || '');
  if (!text) return 0;
  const counts = {};
  for (const char of text) counts[char] = (counts[char] || 0) + 1;
  return -Object.values(counts).reduce((sum, count) => {
    const p = count / text.length;
    return sum + p * Math.log2(p);
  }, 0);
}

function lineInfo(content, index) {
  const before = content.slice(0, index);
  const line = before.split('\n').length;
  const raw = (content.split('\n')[line - 1] || '').trim();
  return { line, snippet: raw.slice(0, 180) };
}

function fingerprint(finding) {
  return [finding.rule || finding.id, finding.evidence, finding.line || 0].join(':').toLowerCase();
}

async function mapLimit(items, limit, mapper) {
  const output = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor++;
      output[index] = await mapper(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return output;
}

function chooseSourceFiles(files) {
  const candidates = files.filter(file => file.size > 0 && file.size <= 180000 && (TEXT_EXTENSIONS.test(file.path) || IMPORTANT_FILES.test(file.path)));
  return candidates.sort((a, b) => {
    const aScore = (IMPORTANT_FILES.test(a.path) ? 100 : 0) + (/src|app|server|api|lib/i.test(a.path) ? 20 : 0) - a.size / 100000;
    const bScore = (IMPORTANT_FILES.test(b.path) ? 100 : 0) + (/src|app|server|api|lib/i.test(b.path) ? 20 : 0) - b.size / 100000;
    return bScore - aScore;
  }).slice(0, MAX_SOURCE_FILES);
}

async function fetchSources(repository, branch, files, signal, onProgress = () => {}) {
  const chosen = chooseSourceFiles(files);
  let bytes = 0;
  let complete = 0;
  const fetched = await mapLimit(chosen, 6, async file => {
    if (bytes >= MAX_SOURCE_BYTES) return null;
    const response = await fetch(`https://raw.githubusercontent.com/${repository.owner}/${repository.repo}/${encodeURIComponent(branch)}/${file.path.split('/').map(encodeURIComponent).join('/')}`, { signal });
    complete += 1;
    onProgress(complete, chosen.length, file.path);
    if (!response.ok) return null;
    const content = await response.text();
    bytes += content.length;
    if (bytes > MAX_SOURCE_BYTES) return null;
    return { path: file.path, content, size: content.length };
  });
  return { sources: fetched.filter(Boolean), chosen: chosen.length, bytes };
}

function makeFinding(partial) {
  return {
    confidence: 'High-confidence static rule', status: 'Open', line: 0, snippet: '',
    points: 8, mapping: 'CWE review', kind: 'Observed source', ...partial
  };
}

function scanSecrets(sources) {
  const patterns = [
    ['SEC-AWS', 'AWS access key exposed', 'critical', 24, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, 'CWE-798'],
    ['SEC-GITHUB', 'GitHub token exposed', 'critical', 24, /\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g, 'CWE-798'],
    ['SEC-OPENAI', 'OpenAI-style API key exposed', 'critical', 24, /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, 'CWE-798'],
    ['SEC-SLACK', 'Slack token exposed', 'critical', 22, /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g, 'CWE-798'],
    ['SEC-PRIVATE', 'Private key material committed', 'critical', 25, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, 'CWE-321'],
    ['SEC-GENERIC', 'Hard-coded credential candidate', 'high', 16, /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']([^"'\n]{16,})["']/gi, 'CWE-798']
  ];
  const findings = [];
  for (const source of sources) {
    if (/lock|\.min\.|vendor\//i.test(source.path)) continue;
    for (const [rule, title, sev, points, regex, mapping] of patterns) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(source.content)) && findings.length < 40) {
        const secret = match[1] || match[0];
        if (/example|placeholder|your[_-]|changeme|process\.env|import\.meta\.env/i.test(secret)) continue;
        if (rule === 'SEC-GENERIC' && shannonEntropy(secret) < 3.15) continue;
        const at = lineInfo(source.content, match.index);
        findings.push(makeFinding({
          id: `${rule}-${findings.length + 1}`, rule, sev, points, title,
          detail: `A credential-shaped value appears in source. The value is redacted; rotate it if it is active.`,
          fix: 'Remove the value from Git history, rotate it, load it from a secret manager, and add a secret-scanning gate.',
          evidence: source.path, line: at.line, snippet: at.snippet.replace(secret, redactSecret(secret)), mapping, kind: 'Observed secret pattern'
        }));
        if (!match[0].length) regex.lastIndex += 1;
      }
    }
  }
  return findings;
}

function scanCode(sources, aiDependencies) {
  const rules = [
    { rule: 'CODE-EVAL', title: 'Dynamic code execution', sev: 'high', points: 15, re: /\b(?:eval|new\s+Function)\s*\(/g, mapping: 'CWE-95', detail: 'Dynamic code execution can turn untrusted input into executable behavior.', fix: 'Replace dynamic evaluation with an explicit parser or allowlisted command map.' },
    { rule: 'CODE-SHELL', title: 'Shell command execution surface', sev: 'high', points: 15, re: /\b(?:exec|execSync|spawn|system|popen)\s*\(/g, mapping: 'CWE-78', detail: 'A process execution primitive is present and needs strict input boundaries.', fix: 'Use argument arrays, reject metacharacters, and allowlist commands and working directories.' },
    { rule: 'CODE-XSS', title: 'Raw HTML injection sink', sev: 'high', points: 14, re: /dangerouslySetInnerHTML\s*=|\.innerHTML\s*=/g, mapping: 'CWE-79', detail: 'Raw HTML reaches a browser rendering sink.', fix: 'Render text by default or sanitize with a maintained HTML sanitizer and a narrow policy.' },
    { rule: 'CODE-SQL', title: 'Possible dynamic SQL construction', sev: 'high', points: 14, re: /(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/g, mapping: 'CWE-89', detail: 'A database call appears to receive dynamically constructed SQL.', fix: 'Use parameterized queries and keep identifiers behind an explicit allowlist.' },
    { rule: 'CODE-WEAKCRYPTO', title: 'Weak cryptographic primitive', sev: 'medium', points: 8, re: /createHash\s*\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\s*\(/gi, mapping: 'CWE-327', detail: 'MD5 or SHA-1 is used in a security-relevant code path.', fix: 'Use SHA-256+ for integrity or a password-specific KDF such as Argon2id.' },
    { rule: 'CODE-CORS', title: 'Wildcard cross-origin policy', sev: 'medium', points: 9, re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["']/gis, mapping: 'CWE-942', detail: 'A wildcard origin policy may expose sensitive responses cross-origin.', fix: 'Allowlist known origins and never combine wildcard origins with credentials.' },
    { rule: 'AGENT-TOOLS', title: 'Agent can invoke a broad tool or command', sev: 'high', points: 16, re: /(?:shell|terminal|execute_command|run_command|child_process|subprocess)["']?\s*[:=(]/gi, mapping: 'OWASP LLM07', detail: 'Agent-adjacent code exposes a powerful execution capability.', fix: 'Add per-agent tool allowlists, typed arguments, approval gates, timeouts, and an auditable deny-by-default policy.', agentOnly: true },
    { rule: 'AGENT-ENV', title: 'Agent code can reach runtime secrets', sev: 'high', points: 16, re: /(?:process\.env|os\.environ|getenv\s*\()/g, mapping: 'OWASP LLM06', detail: 'Agent-adjacent source reads runtime environment values.', fix: 'Broker secrets server-side, expose only task-scoped credentials, and block secret values from model context and logs.', agentOnly: true },
    { rule: 'AGENT-LOOP', title: 'Agent loop lacks an obvious step budget', sev: 'medium', points: 10, re: /while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;/g, mapping: 'OWASP LLM10', detail: 'An unbounded loop appears in agent-adjacent code.', fix: 'Set maximum steps, tokens, retries, wall-clock time, and total cost for every run.', agentOnly: true }
  ];
  const findings = [];
  const hasAI = aiDependencies.length > 0;
  for (const source of sources) {
    if (/lock|\.min\.|dist\/|vendor\//i.test(source.path)) continue;
    const agentAdjacent = hasAI && /agent|ai|llm|prompt|tool|mcp|openai|anthropic/i.test(`${source.path}\n${source.content.slice(0, 3000)}`);
    for (const rule of rules) {
      if (rule.agentOnly && !agentAdjacent) continue;
      rule.re.lastIndex = 0;
      const match = rule.re.exec(source.content);
      if (!match) continue;
      const at = lineInfo(source.content, match.index);
      findings.push(makeFinding({
        id: `${rule.rule}-${findings.length + 1}`, rule: rule.rule, sev: rule.sev, points: rule.points,
        title: rule.title, detail: rule.detail, fix: rule.fix, evidence: source.path,
        line: at.line, snippet: at.snippet, mapping: rule.mapping,
        kind: rule.agentOnly ? 'Observed agent capability' : 'Observed source sink'
      }));
    }
  }
  return findings;
}

function parseDependencies(sources) {
  const dependencies = [];
  const add = (ecosystem, name, version, file) => {
    const clean = String(version || '').trim().replace(/^[~^<>=v\s]+/, '').split(/\s|\|/)[0];
    if (!name || !clean || /\*|workspace:|file:|git:|latest|:\/\//i.test(clean)) return;
    dependencies.push({ ecosystem, name, version: clean, file });
  };
  for (const source of sources) {
    if (source.path.endsWith('package.json')) {
      try {
        const parsed = JSON.parse(source.content);
        Object.entries({ ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}), ...(parsed.optionalDependencies || {}) }).forEach(([name, version]) => add('npm', name, version, source.path));
      } catch (_) {}
    } else if (/requirements(?:-[^/]+)?\.txt$/i.test(source.path)) {
      source.content.split('\n').forEach(line => {
        const match = line.trim().match(/^([A-Za-z0-9_.-]+)\s*==\s*([^\s;]+)/);
        if (match) add('PyPI', match[1], match[2], source.path);
      });
    } else if (source.path.endsWith('go.mod')) {
      source.content.split('\n').forEach(line => {
        const match = line.trim().match(/^([\w./-]+)\s+v([^\s]+)/);
        if (match && match[1] !== 'module') add('Go', match[1], match[2], source.path);
      });
    }
  }
  return [...new Map(dependencies.map(dep => [`${dep.ecosystem}:${dep.name}:${dep.version}`, dep])).values()].slice(0, 350);
}

async function scanOsv(dependencies, signal) {
  if (!dependencies.length) return { vulnerabilities: [], checked: 0, available: true };
  const vulnerabilities = [];
  const batches = [];
  for (let i = 0; i < dependencies.length; i += 100) batches.push(dependencies.slice(i, i + 100));
  try {
    for (const batch of batches) {
      const response = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST', headers: { 'content-type': 'application/json' }, signal,
        body: JSON.stringify({ queries: batch.map(dep => ({ package: { name: dep.name, ecosystem: dep.ecosystem }, version: dep.version })) })
      });
      if (!response.ok) throw new Error(`OSV ${response.status}`);
      const payload = await response.json();
      (payload.results || []).forEach((entry, index) => {
        (entry.vulns || []).forEach(vuln => vulnerabilities.push({ ...batch[index], id: vuln.id, modified: vuln.modified || '' }));
      });
    }
    return { vulnerabilities, checked: dependencies.length, available: true };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return { vulnerabilities: [], checked: dependencies.length, available: false, error: error.message };
  }
}

function deriveFindings(files, packageJson, sources = [], osv = { vulnerabilities: [] }) {
  const paths = files.map(file => file.path);
  const lowerPaths = paths.map(path => path.toLowerCase());
  const dependencies = { ...(packageJson?.dependencies || {}), ...(packageJson?.devDependencies || {}) };
  const findings = [...scanSecrets(sources), ...scanCode(sources, Object.keys(dependencies).filter(name => /openai|anthropic|langchain|ai-sdk|llamaindex|crewai|autogen|mcp/i.test(name)))];
  const add = finding => findings.push({ confidence: 'Structural signal', status: 'Needs review', ...finding });
  const exposed = paths.filter((path, index) => /(^|\/)(\.env|credentials|secrets?\.json|id_rsa)$/i.test(lowerPaths[index]));

  if (exposed.length) add({
    id: 'SEC-001', sev: 'critical', points: 24,
    title: 'Sensitive configuration appears committed',
    detail: `${exposed.slice(0, 3).join(', ')} ${exposed.length === 1 ? 'appears' : 'appear'} in the public repository tree.`,
    fix: 'Remove the file, rotate affected credentials, and block it with .gitignore plus a secret-scanning check.',
    evidence: exposed[0], mapping: 'CWE-798', kind: 'Observed path'
  });
  if (!lowerPaths.some(path => path.endsWith('security.md'))) add({
    id: 'SEC-002', sev: 'medium', points: 7,
    title: 'No security policy detected',
    detail: 'Contributors do not have a documented private vulnerability-reporting path.',
    fix: 'Add SECURITY.md with supported versions and a private reporting channel.',
    evidence: 'Repository root', mapping: 'Process control', kind: 'Observed absence'
  });
  if (!lowerPaths.some(path => path.includes('.github/workflows/') && /codeql|semgrep|snyk|security/.test(path))) add({
    id: 'SEC-003', sev: 'high', points: 14,
    title: 'No dedicated security workflow found',
    detail: 'The public tree does not show a recognizable security scan in GitHub Actions.',
    fix: 'Run CodeQL or an equivalent scanner on pull requests and protect the required check.',
    evidence: '.github/workflows/', mapping: 'OWASP A08', kind: 'Observed absence'
  });

  const ai = Object.keys(dependencies).filter(name => /openai|anthropic|langchain|ai-sdk|llamaindex|crewai|autogen|mcp/i.test(name));
  if (ai.length) add({
    id: 'AI-001', sev: 'high', points: 16,
    title: 'AI runtime expands the application trust boundary',
    detail: `Detected ${ai.join(', ')}. Inputs, tools, outputs, and run budgets require explicit boundaries.`,
    fix: 'Add tool allowlists, prompt-injection defenses, output validation, and per-run step and token budgets.',
    evidence: 'package.json', mapping: 'OWASP LLM06', kind: 'Observed dependency'
  });
  const hasServer = Object.keys(dependencies).some(name => /express|fastify|hono|koa|next/.test(name));
  const hasRateLimit = Object.keys(dependencies).some(name => /rate.?limit|upstash/.test(name));
  if (hasServer && !hasRateLimit) add({
    id: 'OPS-001', sev: 'medium', points: 9,
    title: 'Common rate-limit control not detected',
    detail: 'A server framework is present, but no common rate-limit dependency was found.',
    fix: 'Enforce request, model-token, tool-call, and agent-step budgets at the edge.',
    evidence: 'package.json', mapping: 'OWASP API4', kind: 'Inferred control gap'
  });
  osv.vulnerabilities.slice(0, 40).forEach((vulnerability, index) => add({
    id: `DEP-${index + 1}`, rule: 'OSV-DEPENDENCY', sev: 'high', points: 12,
    title: `Known vulnerability in ${vulnerability.name}@${vulnerability.version}`,
    detail: `${vulnerability.id} affects the resolved package version according to OSV.`,
    fix: `Upgrade ${vulnerability.name} to a non-affected release and run the package ecosystem's test suite.`,
    evidence: vulnerability.file, mapping: vulnerability.id, kind: 'OSV advisory', status: 'Open'
  }));
  if (!findings.length) add({
    id: 'INFO-001', sev: 'info', points: 2,
    title: 'No high-confidence structural issues found',
    detail: 'The public repository tree passed this browser-safe heuristic review.',
    fix: 'Use a source-level scanner and runtime validation before treating the application as verified.',
    evidence: `${files.length} public files`, mapping: 'Heuristic scope', kind: 'Limited assurance'
  });

  const order = { critical: 0, high: 1, medium: 2, info: 3 };
  findings.sort((a, b) => order[a.sev] - order[b.sev] || b.points - a.points);
  const unique = [...new Map(findings.map(finding => [fingerprint(finding), finding])).values()];
  unique.forEach((finding, index) => { if (!finding.id) finding.id = `SNT-${String(index + 1).padStart(3, '0')}`; });
  unique.sort((a, b) => order[a.sev] - order[b.sev] || b.points - a.points);
  return { ai, findings: unique };
}

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch (_) { return []; }
}

function saveScan(scan) {
  const compact = { ...scan, files: scan.files.map(({ path, size }) => ({ path, size })), sources: undefined, packageJson: undefined };
  const history = loadHistory().filter(item => item.repo.url !== scan.repo.url || item.commit !== scan.commit);
  history.unshift(compact);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 12)));
}

function compareToPrevious(scan) {
  const previous = loadHistory().find(item => item.repo.url === scan.repo.url && item.commit !== scan.commit);
  if (!previous) return { previous: null, added: scan.findings.length, fixed: 0, unchanged: 0 };
  const before = new Set(previous.findings.map(fingerprint));
  const now = new Set(scan.findings.map(fingerprint));
  return {
    previous,
    added: [...now].filter(key => !before.has(key)).length,
    fixed: [...before].filter(key => !now.has(key)).length,
    unchanged: [...now].filter(key => before.has(key)).length
  };
}

async function analyzeRepository(repository, signal, onProgress = () => {}) {
  onProgress('metadata', 'Fetching repository and branch metadata…');
  const meta = await github(`/repos/${repository.owner}/${repository.repo}`, signal);
  const branch = meta.default_branch;
  const [tree, commit] = await Promise.all([
    github(`/repos/${repository.owner}/${repository.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`, signal),
    github(`/repos/${repository.owner}/${repository.repo}/commits/${encodeURIComponent(branch)}`, signal)
  ]);
  const files = (tree.tree || []).filter(item => item.type === 'blob');
  onProgress('source', 'Selecting security-relevant source files…');
  const sourceBundle = await fetchSources(repository, branch, files, signal, (done, total, path) => onProgress('source', `Reading source ${done}/${total} · ${path}`));
  const packageSource = sourceBundle.sources.find(file => file.path === 'package.json');
  let packageJson = null;
  if (packageSource) { try { packageJson = JSON.parse(packageSource.content); } catch (_) {} }
  const dependencies = parseDependencies(sourceBundle.sources);
  onProgress('dependencies', `Checking ${dependencies.length} pinned dependencies against OSV…`);
  const osv = await scanOsv(dependencies, signal);
  onProgress('analysis', 'Building evidence, attack paths, and remediation plan…');
  const derived = deriveFindings(files, packageJson, sourceBundle.sources, osv);
  const score = Math.max(12, 100 - derived.findings.reduce((total, finding) => total + finding.points, 0));
  const scan = {
    repo: repository,
    meta,
    branch,
    commit: commit.sha || '',
    files,
    packageJson,
    sources: sourceBundle.sources,
    sourceStats: { selected: sourceBundle.chosen, read: sourceBundle.sources.length, bytes: sourceBundle.bytes },
    dependencies,
    osv,
    score,
    ...derived,
    live: true,
    partial: Boolean(tree.truncated),
    scope: `${tree.truncated ? 'Partial' : 'Public'} tree · ${sourceBundle.sources.length} source files · OSV dependency check · code is not executed`,
    createdAt: new Date().toISOString()
  };
  scan.diff = compareToPrevious(scan);
  saveScan(scan);
  return scan;
}

function openModal() {
  lastFocused = document.activeElement;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  modalPanel.focus();
}

function closeModal(cancel = true) {
  if (cancel && scanAbortController) scanAbortController.abort();
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  bar.classList.remove('indeterminate');
  document.body.style.overflow = '';
  scanAbortController = null;
  lastFocused?.focus?.();
}

async function startScan(value) {
  const repository = parseRepository(value);
  if (!repository) {
    repoInput.setAttribute('aria-invalid', 'true');
    repoError.textContent = 'Enter a complete public GitHub URL, such as https://github.com/owner/repository.';
    repoInput.focus();
    return;
  }
  repoInput.removeAttribute('aria-invalid');
  repoError.textContent = '';
  if (scanAbortController) scanAbortController.abort();
  scanAbortController = new AbortController();
  openModal();
  modalTitle.textContent = 'Mapping the public repository';
  modalProgress.textContent = 'Fetching repository and branch metadata…';
  bar.style.width = '34%';
  bar.classList.add('indeterminate');
  try {
    const stages = { metadata: 18, source: 48, dependencies: 76, analysis: 92 };
    const scan = await analyzeRepository(repository, scanAbortController.signal, (stage, message) => {
      modalProgress.textContent = message;
      bar.classList.remove('indeterminate');
      bar.style.width = `${stages[stage] || 40}%`;
    });
    result = scan;
    bar.classList.remove('indeterminate');
    bar.style.width = '100%';
    modalTitle.textContent = 'Security map ready';
    modalProgress.textContent = `${scan.sourceStats.read} source files analyzed · ${scan.dependencies.length} dependencies checked · ${scan.findings.length} findings`;
    window.setTimeout(() => {
      closeModal(false);
      openConsole(scan);
    }, 450);
  } catch (error) {
    if (error.name === 'AbortError') return;
    bar.classList.remove('indeterminate');
    bar.style.width = '0%';
    modalTitle.textContent = 'We could not complete this scan';
    modalProgress.textContent = error.message || 'Check the repository URL and try again.';
    repoError.textContent = error.message || 'The scan could not be completed.';
  }
}

function publicFinding(finding) {
  const plain = plainFinding(finding);
  return {
    id: finding.id,
    severity: finding.sev,
    title: plain.title,
    explanation: plain.meaning,
    recommended_action: plain.action,
    evidence_location: finding.evidence,
    line: finding.line || null,
    source: finding.kind,
    standard: finding.mapping
  };
}

function buildIntegrationReview(project, tool, useCase) {
  const toolCritical = tool.findings.filter(finding => finding.sev === 'critical').length;
  const toolHigh = tool.findings.filter(finding => finding.sev === 'high').length;
  const shared = new Map(project.dependencies.map(dep => [`${dep.ecosystem}:${dep.name}`, dep]));
  const conflicts = tool.dependencies.filter(dep => {
    const current = shared.get(`${dep.ecosystem}:${dep.name}`);
    return current && current.version !== dep.version;
  }).map(dep => ({ tool: dep, project: shared.get(`${dep.ecosystem}:${dep.name}`) }));
  const broadTool = tool.findings.some(finding => /AGENT-TOOLS|CODE-SHELL|CODE-EVAL/.test(finding.rule || ''));
  const projectSecrets = project.findings.some(finding => /SEC-|AGENT-ENV/.test(finding.rule || finding.id || ''));
  const groups = [];
  tool.findings.forEach((finding, index) => {
    if (finding.sev === 'info') return;
    const plain = plainFinding(finding);
    const existing = groups.find(group => group.title === plain.title);
    if (existing) existing.items.push(finding);
    else groups.push({ title: plain.title, explanation: plain.meaning, action: plain.action, severity: finding.sev, index, items: [finding] });
  });
  const contextual = [];
  if (broadTool && projectSecrets) contextual.push({
    title: 'This tool may increase access to sensitive project data',
    explanation: 'The tool contains command-running capability and your project contains secret-related signals. Heimdall cannot prove they connect until the integration is built.',
    action: 'Give the tool only the files and environment values it needs, then test the boundary.',
    evidence: 'Inferred from findings in both repositories'
  });
  if (conflicts.length) contextual.push({
    title: `${conflicts.length} shared ${conflicts.length === 1 ? 'package uses' : 'packages use'} different versions`,
    explanation: 'Different versions can create installation failures or reintroduce a security problem.',
    action: 'Choose one supported version and run the project tests before merging.',
    evidence: conflicts.slice(0, 5).map(item => `${item.tool.name}: project ${item.project.version}, tool ${item.tool.version}`).join(' · ')
  });
  const decision = toolCritical
    ? { label: 'Do not add it yet', tone: 'stop', reason: 'The tool contains a critical warning that should be reviewed first.' }
    : toolHigh || tool.osv.vulnerabilities.length
      ? { label: 'Use it after making changes', tone: 'change', reason: 'The tool has important problems, but they may be manageable with the recommended changes.' }
      : groups.length
        ? { label: 'Review before using', tone: 'review', reason: 'Heimdall found a few areas worth checking before this tool reaches your project.' }
        : { label: 'No major gap found', tone: 'clear', reason: 'No major warning appeared in the public files checked. This is not a complete security guarantee.' };
  const report = {
    schema_version: 'heimdall.integration-review.v1',
    intended_use: useCase || 'Not provided',
    decision,
    project: { repository: project.meta.full_name, commit: project.commit, files_checked: project.sourceStats.read, findings: project.findings.slice(0, 15).map(publicFinding) },
    candidate_tool: { repository: tool.meta.full_name, commit: tool.commit, files_checked: tool.sourceStats.read, findings: tool.findings.slice(0, 20).map(publicFinding) },
    compatibility: { dependency_conflicts: conflicts.map(item => ({ name: item.tool.name, project_version: item.project.version, tool_version: item.tool.version })), contextual_gaps: contextual },
    limitations: ['Public repositories only', 'Selected files are checked without executing code', 'Contextual gaps are inferred and require validation after integration']
  };
  return { project, tool, useCase, groups, contextual, conflicts, decision, report, createdAt: new Date().toISOString() };
}

function integrationMarkup(review) {
  const endpointReady = Boolean(window.HEIMDALL_GEMINI_ENDPOINT);
  const gapRows = [...review.contextual.map(gap => ({ ...gap, severity: 'context' })), ...review.groups].slice(0, 8);
  return `
    <div class="console-head">
      <div><button id="backHome" type="button">← Site</button><span class="console-brand"><img src="heimdall-logo.svg" alt=""> Heimdall</span></div>
      <div><button id="newComparison" type="button">New comparison</button><button id="exportIntegration" type="button">Export</button></div>
    </div>
    <main class="integration-main">
      <section class="integration-hero ${esc(review.decision.tone)}">
        <div><span>Integration review</span><h1>${esc(review.decision.label)}</h1><p>${esc(review.decision.reason)}</p></div>
        <div class="integration-score"><strong>${review.tool.score}</strong><span>/100</span><small>Tool readiness</small></div>
      </section>
      <section class="repo-pair" aria-label="Repositories compared">
        <article><small>Your project</small><h2>${esc(review.project.meta.full_name)}</h2><p>${review.project.sourceStats.read} files checked · ${review.project.findings.length} detailed findings</p></article>
        <div aria-hidden="true">+</div>
        <article><small>Tool you want to use</small><h2>${esc(review.tool.meta.full_name)}</h2><p>${review.tool.sourceStats.read} files checked · ${review.tool.findings.length} detailed findings</p></article>
      </section>
      ${review.useCase ? `<p class="integration-intent"><strong>Your plan:</strong> ${esc(review.useCase)}</p>` : ''}
      <section class="integration-section"><header><div><small>Before you integrate</small><h2>What could affect your project</h2></div><p>Technical matches are grouped into plain-language problems.</p></header>
        <div class="integration-gaps">${gapRows.length ? gapRows.map(gap => `<article><div><h3>${esc(gap.title)}${gap.items?.length > 1 ? `<span>Found in ${gap.items.length} places</span>` : ''}</h3><p>${esc(gap.explanation)}</p><strong>What to do: <span>${esc(gap.action)}</span></strong>${gap.evidence ? `<small>${esc(gap.evidence)}</small>` : ''}</div>${Number.isInteger(gap.index) ? `<button type="button" data-tool-fix="${gap.index}">Open evidence</button>` : ''}</article>`).join('') : '<div class="empty-state"><h3>No major compatibility gap was found</h3><p>Review the coverage limits and scan again after integration.</p></div>'}</div>
      </section>
      <section class="gemini-handoff">
        <div><small>Gemini handoff</small><h2>Continue the work in your Gemini conversation</h2><p>Heimdall sends only repository names and redacted findings—not source code or secret values. Gemini can then explain the safest integration plan using this evidence.</p><div class="gemini-actions"><button id="copyGeminiReport" type="button">Copy report for Gemini</button><button id="sendGeminiReport" class="primary" type="button">${endpointReady ? 'Create Gemini plan' : 'Connect Gemini'}</button></div><p class="gemini-status" id="geminiStatus">${endpointReady ? 'Protected Gemini endpoint connected.' : 'Gemini is not connected on this deployment yet. The report can still be copied into Gemini.'}</p></div>
        <div class="gemini-result" id="geminiResult"><strong>No AI-generated plan yet</strong><p>Heimdall’s decision above comes from the real repository scans. Gemini will explain that evidence; it will not create new findings.</p></div>
      </section>
      <p class="integration-limit">Heimdall checks selected public files and known package advisories without running either repository. Scan again after integration to verify what changed.</p>
    </main>`;
}

function copyGeminiReport(review) {
  const text = `I am considering adding ${review.tool.meta.full_name} to ${review.project.meta.full_name}. My intended use is: ${review.useCase || 'not specified'}. Use only this Heimdall evidence. Do not invent vulnerabilities. Explain the decision, give me an ordered integration plan, and list what must be verified afterward.\n\n${JSON.stringify(review.report, null, 2)}`;
  return navigator.clipboard.writeText(text);
}

async function requestGeminiPlan(review, consoleElement) {
  const status = $('#geminiStatus', consoleElement);
  const output = $('#geminiResult', consoleElement);
  if (!window.HEIMDALL_GEMINI_ENDPOINT) {
    status.textContent = 'Gemini needs the protected server endpoint in gemini-worker/. Your API key must never be placed in this website.';
    output.innerHTML = '<strong>Connection required</strong><p>Deploy the included protected endpoint, save GEMINI_API_KEY as a server secret, and set its URL in web/config.js.</p>';
    return;
  }
  status.textContent = 'Creating a plan from Heimdall’s redacted evidence…';
  output.innerHTML = '<strong>Working…</strong><p>Gemini is reading the structured comparison.</p>';
  try {
    const response = await fetch(window.HEIMDALL_GEMINI_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ report: review.report }) });
    if (!response.ok) throw new Error(`Gemini endpoint returned ${response.status}`);
    const plan = await response.json();
    const steps = Array.isArray(plan.steps) ? plan.steps : [];
    output.innerHTML = `${plan.fit ? `<small>FIT FOR YOUR IDEA</small><strong>${esc(plan.fit)}</strong>` : ''}<p>${esc(plan.summary || 'Integration plan')}</p><p>${esc(plan.why || '')}</p>${steps.length ? `<ol>${steps.map(step => `<li>${esc(step)}</li>`).join('')}</ol>` : ''}${plan.verify ? `<p><b>Verify:</b> ${esc(plan.verify)}</p>` : ''}`;
    status.textContent = 'Plan created from the current Heimdall report.';
  } catch (error) {
    status.textContent = 'Gemini could not be reached. The evidence report is still available to copy.';
    output.innerHTML = `<strong>Connection failed</strong><p>${esc(error.message)}</p>`;
  }
}

function openIntegrationConsole(review) {
  let consoleElement = $('#console');
  if (!consoleElement) {
    consoleElement = document.createElement('div');
    consoleElement.id = 'console';
    document.body.append(consoleElement);
  }
  consoleElement.setAttribute('role', 'dialog');
  consoleElement.setAttribute('aria-modal', 'true');
  consoleElement.setAttribute('aria-label', `Integration review for ${review.tool.meta.full_name}`);
  consoleElement.setAttribute('aria-hidden', 'false');
  consoleElement.tabIndex = -1;
  consoleElement.innerHTML = integrationMarkup(review);
  consoleElement.classList.add('open');
  document.body.style.overflow = 'hidden';
  consoleElement.focus();
  $('#backHome', consoleElement).onclick = () => closeConsole(consoleElement);
  $('#newComparison', consoleElement).onclick = () => closeConsole(consoleElement);
  $$('[data-tool-fix]', consoleElement).forEach(button => button.onclick = () => openFixDrawer(review.tool.findings[Number(button.dataset.toolFix)]));
  $('#copyGeminiReport', consoleElement).onclick = async () => {
    try { await copyGeminiReport(review); showToast('Gemini report copied'); } catch (_) { showToast('Copy was blocked by the browser'); }
  };
  $('#sendGeminiReport', consoleElement).onclick = () => requestGeminiPlan(review, consoleElement);
  $('#exportIntegration', consoleElement).onclick = () => download(`heimdall-${review.project.repo.repo}-${review.tool.repo.repo}-integration.json`, JSON.stringify(review.report, null, 2), 'application/json');
}

async function startIntegrationReview(projectValue, toolValue, useCase = '') {
  const projectRepo = parseRepository(projectValue);
  const toolRepo = parseRepository(toolValue);
  if (!projectRepo || !toolRepo) {
    repoError.textContent = 'Enter complete public GitHub links for both your project and the tool you want to use.';
    (!projectRepo ? compareProjectInput : toolRepoInput).focus();
    return;
  }
  repoError.textContent = '';
  if (scanAbortController) scanAbortController.abort();
  scanAbortController = new AbortController();
  openModal();
  bar.classList.remove('indeterminate');
  try {
    modalTitle.textContent = 'Checking your project';
    const project = await analyzeRepository(projectRepo, scanAbortController.signal, (stage, message) => {
      modalProgress.textContent = message;
      bar.style.width = `${({ metadata: 8, source: 20, dependencies: 36, analysis: 46 })[stage] || 16}%`;
    });
    modalTitle.textContent = 'Checking the tool';
    const tool = await analyzeRepository(toolRepo, scanAbortController.signal, (stage, message) => {
      modalProgress.textContent = message;
      bar.style.width = `${({ metadata: 54, source: 68, dependencies: 84, analysis: 94 })[stage] || 62}%`;
    });
    integrationResult = buildIntegrationReview(project, tool, String(useCase || '').trim());
    result = project;
    bar.style.width = '100%';
    modalTitle.textContent = 'Comparison ready';
    modalProgress.textContent = `${project.meta.name} and ${tool.meta.name} checked without running their code.`;
    window.setTimeout(() => { closeModal(false); openIntegrationConsole(integrationResult); }, 350);
  } catch (error) {
    if (error.name === 'AbortError') return;
    bar.style.width = '0%';
    modalTitle.textContent = 'We could not complete the comparison';
    modalProgress.textContent = error.message || 'Check both repository links and try again.';
    repoError.textContent = error.message || 'The comparison could not be completed.';
  }
}

function findingRows(scan) {
  return scan.findings.map((finding, index) => `
    <article class="finding">
      <span class="severity ${esc(finding.sev)}">${esc(finding.sev)}</span>
      <div>
        <h4>${esc(finding.title)}</h4>
        <p>${esc(finding.detail)}</p>
        <div class="finding-evidence">
          <span>${esc(finding.id)}</span><span>${esc(finding.kind)}</span><span>${esc(finding.evidence)}${finding.line ? `:${finding.line}` : ''}</span><span>${esc(finding.mapping)}</span>
        </div>
        ${finding.snippet ? `<pre class="source-snippet"><code>${esc(finding.snippet)}</code></pre>` : ''}
        <small>Next action: ${esc(finding.fix)}</small>
      </div>
      <button type="button" data-fix="${index}">Review fix</button>
    </article>`).join('');
}

function plainFinding(finding) {
  const key = `${finding.rule || ''} ${finding.id || ''} ${finding.title || ''}`.toLowerCase();
  if (/security workflow|sec-003/.test(key)) return {
    title: 'Security checks are not running automatically',
    meaning: 'A risky change could be added without anyone being warned.',
    action: 'Add an automatic security check to every code change.'
  };
  if (/osv|known vulnerability|dep-/.test(key)) return {
    title: 'A software package needs an update',
    meaning: 'This project uses a package with a publicly known security problem.',
    action: `Update ${finding.title.match(/in ([^@\s]+)@/)?.[1] || 'the affected package'}, test the project, and scan again.`
  };
  if (/rate.?limit|ops-001/.test(key)) return {
    title: 'The app may accept too many requests at once',
    meaning: 'Someone could overwhelm the app or create an unexpectedly large bill.',
    action: 'Set limits for requests and expensive AI actions.'
  };
  if (/security policy|sec-002/.test(key)) return {
    title: 'People need a private way to report security problems',
    meaning: 'A researcher may not know how to safely tell your team about a problem.',
    action: 'Add a short security policy with a private contact method.'
  };
  if (/private key|credential|token|password|secret|sec-001/.test(key)) return {
    title: 'Private information may be visible in the code',
    meaning: 'A password or access key could let someone use a service as your team.',
    action: 'Disable the old key, remove it from the code, and store its replacement safely.'
  };
  if (/shell|command execution/.test(key)) return {
    title: 'Part of the app can run computer commands',
    meaning: 'Unsafe input could potentially make the server perform an unintended action.',
    action: 'Limit which commands are allowed and reject unexpected input.'
  };
  if (/html|xss/.test(key)) return {
    title: 'Untrusted content may be shown as webpage code',
    meaning: 'An attacker could potentially place unwanted content on the page.',
    action: 'Treat input as text or clean it with a trusted sanitizer.'
  };
  if (/sql/.test(key)) return {
    title: 'A database request may include unsafe input',
    meaning: 'Someone could potentially change what the database command does.',
    action: 'Use parameterized database queries and test the affected path.'
  };
  if (/ai runtime|agent/.test(key)) return {
    title: 'The AI feature may have broad access',
    meaning: 'An AI action could reach more tools or information than it needs.',
    action: 'Limit its tools, permissions, time, and number of steps.'
  };
  return {
    title: finding.title,
    meaning: finding.detail,
    action: finding.fix
  };
}

function summaryFindingRows(scan) {
  const groups = [];
  scan.findings.forEach((finding, index) => {
    const plain = plainFinding(finding);
    const existing = groups.find(group => group.plain.title === plain.title);
    if (existing) existing.items.push(finding);
    else groups.push({ finding, index, plain, items: [finding] });
  });
  return groups.map(({ finding, index, plain, items }) => {
    const urgency = finding.sev === 'critical' ? 'Fix now' : finding.sev === 'high' ? 'Fix soon' : finding.sev === 'medium' ? 'Improve' : 'Review';
    return `<article class="summary-finding">
      <div class="summary-finding-copy">
        <div class="summary-finding-heading"><h3>${esc(plain.title)}</h3>${items.length > 1 ? `<span class="occurrence">Found in ${items.length} places</span>` : ''}<span class="urgency ${esc(finding.sev)}">${urgency}</span></div>
        <p>${esc(plain.meaning)}</p>
        <div class="summary-next"><strong>What to do:</strong><span>${esc(plain.action)}</span></div>
        <details><summary>See why Heimdall flagged this</summary><p>${esc(finding.detail)}</p><div class="finding-evidence">${items.slice(0, 6).map(item => `<span>${esc(item.evidence)}${item.line ? `:${item.line}` : ''}</span>`).join('')}<span>${esc(finding.mapping)}</span></div></details>
      </div>
      <button type="button" data-fix="${index}" aria-label="Open fix for ${esc(plain.title)}">Open fix</button>
    </article>`;
  }).join('');
}

function permissionGraph(scan) {
  const nodes = [
    ['Repository', 'repo'],
    ...scan.ai.slice(0, 2).map(name => [name, 'agent']),
    ['Application', 'tool'],
    ['Runtime data', 'secret'],
    ['Outbound network', 'network']
  ];
  return `<div class="permission-graph">${nodes.map((node, index) => `
    <div class="g-node ${esc(node[1])}">
      <i aria-hidden="true">${index ? '→' : '◎'}</i><b>${esc(node[0])}</b><small>${esc(node[1])}</small>
    </div>`).join('')}</div>`;
}

function attackPathMarkup(scan) {
  const paths = scan.findings.filter(finding => /AGENT|SECRET|SHELL|XSS|SQL|CORS|DEPENDENCY|SEC-/i.test(`${finding.rule || ''} ${finding.id}`)).slice(0, 5);
  if (!paths.length) return '<div class="empty-state"><h3>No high-confidence attack path was derived</h3><p>The scan did not connect a detected source sink to a meaningful impact. Review the findings individually and test the application dynamically.</p></div>';
  return `<div class="attack-path-list">${paths.map((finding, index) => `
    <article class="attack-path-card">
      <header><span>PATH ${String(index + 1).padStart(2, '0')}</span><b class="severity ${esc(finding.sev)}">${esc(finding.sev)}</b></header>
      <div class="attack-chain"><span>Untrusted input</span><i>→</i><span>${esc(finding.title)}</span><i>→</i><span class="impact">${/secret|env/i.test(finding.title) ? 'Credential exposure' : /shell|eval/i.test(finding.title) ? 'Code execution' : /dependency/i.test(finding.kind) ? 'Supply-chain impact' : 'Security impact'}</span></div>
      <p><strong>Observed:</strong> ${esc(finding.evidence)}${finding.line ? `:${finding.line}` : ''}. <strong>Inferred:</strong> exploitation requires reachable, attacker-controlled input and is not claimed as executed.</p>
      <button type="button" data-fix="${scan.findings.indexOf(finding)}">Contain this path</button>
    </article>`).join('')}</div>`;
}

function dependencyMarkup(scan) {
  if (!scan.dependencies.length) return '<div class="empty-state"><h3>No pinned dependency manifests were read</h3><p>Heimdall checks package.json, requirements files, and go.mod when exact versions are available.</p></div>';
  const vulnerable = new Map(scan.osv.vulnerabilities.map(item => [`${item.ecosystem}:${item.name}:${item.version}`, item.id]));
  return `<div class="dependency-summary"><article><small>PINNED PACKAGES</small><b>${scan.dependencies.length}</b></article><article><small>OSV MATCHES</small><b>${scan.osv.vulnerabilities.length}</b></article><article><small>CHECK STATUS</small><b>${scan.osv.available ? 'Live' : 'Unavailable'}</b></article></div>
    ${!scan.osv.available ? `<p class="service-warning">OSV could not be reached during this scan. Source analysis still completed.</p>` : ''}
    <div class="dependency-table" role="table" aria-label="Dependency inventory">
      <div class="dependency-row head" role="row"><span>Package</span><span>Version</span><span>Ecosystem</span><span>Status</span></div>
      ${scan.dependencies.slice(0, 180).map(dep => {
        const advisory = vulnerable.get(`${dep.ecosystem}:${dep.name}:${dep.version}`);
        return `<div class="dependency-row" role="row"><b>${esc(dep.name)}</b><code>${esc(dep.version)}</code><span>${esc(dep.ecosystem)}</span><span class="${advisory ? 'dep-risk' : 'dep-clear'}">${esc(advisory || 'No OSV match')}</span></div>`;
      }).join('')}
    </div>`;
}

function historyMarkup(scan) {
  const history = loadHistory().filter(item => item.repo.url === scan.repo.url).slice(0, 8);
  const diff = scan.diff || { added: 0, fixed: 0, unchanged: scan.findings.length };
  return `<div class="diff-summary"><article><b>${diff.added}</b><span>New</span></article><article><b>${diff.fixed}</b><span>Fixed</span></article><article><b>${diff.unchanged}</b><span>Unchanged</span></article></div>
    <div class="history-list">${history.map((item, index) => `<article><span><small>${index ? 'PRIOR SCAN' : 'CURRENT SCAN'}</small><b>${new Date(item.createdAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</b></span><code>${esc((item.commit || '').slice(0, 7))}</code><span>${item.score}/100</span><span>${item.findings.length} findings</span></article>`).join('')}</div>
    <p class="scope-note">History is stored on this device. A future hosted workspace can sync private projects and scheduled scans across a team.</p>`;
}

function reportMarkdown(scan) {
  return `# Heimdall security report\n\nRepository: ${scan.meta.full_name}\nBranch: ${scan.branch}\nCommit: ${scan.commit}\nScanned: ${scan.createdAt}\nScope: ${scan.scope}\nPosture indicator: ${scan.score}/100\n\n## Summary\n\n- ${scan.sourceStats.read} source files analyzed\n- ${scan.dependencies.length} pinned dependencies checked\n- ${scan.osv.vulnerabilities.length} OSV advisory matches\n- ${scan.findings.length} prioritized findings\n\n## Findings\n\n${scan.findings.map((finding, index) => `${index + 1}. **[${finding.sev.toUpperCase()}] ${finding.title}** (${finding.id})\n   - Evidence: ${finding.evidence}${finding.line ? `:${finding.line}` : ''}\n   - Classification: ${finding.mapping} · ${finding.kind}\n   - Detail: ${finding.detail}\n   - Fix: ${finding.fix}`).join('\n\n')}\n\n> Heimdall performs bounded static analysis of public source and OSV dependency checks. It does not execute repository code or claim exploitability without runtime validation.\n`;
}

function reportSarif(scan) {
  const rules = [...new Map(scan.findings.map(finding => [finding.rule || finding.id, finding])).values()];
  return {
    version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{
      tool: { driver: { name: 'Heimdall', informationUri: location.origin, rules: rules.map(finding => ({ id: finding.rule || finding.id, name: finding.title, shortDescription: { text: finding.title }, help: { text: finding.fix } })) } },
      results: scan.findings.map(finding => ({
        ruleId: finding.rule || finding.id,
        level: finding.sev === 'critical' || finding.sev === 'high' ? 'error' : finding.sev === 'medium' ? 'warning' : 'note',
        message: { text: `${finding.detail} Remediation: ${finding.fix}` },
        locations: finding.evidence && !/Repository root|public files|\.github\/workflows\/$/.test(finding.evidence) ? [{ physicalLocation: { artifactLocation: { uri: finding.evidence }, region: { startLine: finding.line || 1 } } }] : []
      }))
    }]
  };
}

function consoleMarkup(scan) {
  const date = new Date(scan.createdAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  const topFinding = scan.findings[0];
  const topPlain = plainFinding(topFinding);
  const summaryCount = new Set(scan.findings.map(finding => plainFinding(finding).title)).size;
  const improvement = Math.min(100, scan.score + scan.findings.reduce((total, finding) => total + finding.points, 0));
  return `
    <div class="console-head">
      <div><button id="backHome" type="button">← Site</button><span class="console-brand"><img src="heimdall-logo.svg" alt=""> Heimdall Console</span></div>
      <div><span class="source-note">Public source and package data</span><button id="rescanRepo" type="button">Scan again</button><button id="exportReport" type="button">Export</button></div>
    </div>
    <div class="console-shell">
      <aside>
        <p>WORKSPACE</p>
        <div class="console-tabs" role="tablist" aria-label="Console sections">
        ${[
          ['overview', 'Summary'], ['findings', `Problems (${scan.findings.length})`], ['fixes', 'Fixes'], ['history', 'Progress']
        ].map(([id, label], index) => `<button type="button" role="tab" aria-selected="${index === 0}" aria-controls="panel-${id}" id="tab-${id}" data-tab="${id}" class="${index ? '' : 'active'}">${label}</button>`).join('')}
        </div>
        <hr><small>DEVICE WORKSPACE</small>
        <label><input id="monitorToggle" type="checkbox"> Remember this repo</label>
        <a href="${esc(scan.repo.url)}" target="_blank" rel="noopener noreferrer">Open on GitHub ↗</a>
      </aside>
      <main class="console-main">
        <section id="panel-overview" role="tabpanel" aria-labelledby="tab-overview" data-panel="overview">
          <header class="summary-hero"><div><div class="summary-eyebrow">${esc(scan.meta.full_name)}</div><h2>${summaryCount} ${summaryCount === 1 ? 'problem needs' : 'problems need'} your attention</h2><p>Nothing here means you were hacked. These are practical improvements that can make your project safer.</p><div class="console-provenance"><span>Branch ${esc(scan.branch)}</span><span>Commit ${esc(scan.commit.slice(0, 7))}</span><span>Scanned ${esc(date)}</span></div></div><div class="summary-status" aria-label="Readiness score ${scan.score} out of 100"><div class="summary-score"><strong>${scan.score}</strong><em>/100</em></div><span>Readiness score</span><small>Based on the checks completed</small></div></header>
          <section class="summary-start"><div><small>First, fix this</small><h3>${esc(topPlain.title)}</h3><p>${esc(topPlain.meaning)}</p></div><button type="button" data-fix="0">Show me how</button></section>
          <div class="summary-strip"><span><b>${scan.sourceStats.read}</b> public files checked</span><span><b>${scan.dependencies.length}</b> packages checked</span><span><b>${scan.osv.vulnerabilities.length}</b> known package ${scan.osv.vulnerabilities.length === 1 ? 'problem' : 'problems'}</span><span><b>${scan.diff.fixed}</b> fixed since last scan</span></div>
          <div class="summary-section-heading"><div><small>Your results</small><h2>Problems found</h2></div><p>Explained in plain English, with the most important first.</p></div>
          <div class="summary-findings">${summaryFindingRows(scan)}</div>
          <div class="summary-assurance"><span aria-hidden="true">i</span><div><strong>What this scan can—and cannot—tell you</strong><p>Heimdall reads selected public files and checks known package problems. It does not run your code, access private systems, or guarantee that the whole project is secure.</p></div></div>
        </section>
        <section id="panel-findings" role="tabpanel" aria-labelledby="tab-findings" data-panel="findings" hidden>
          <header class="workspace-title"><div><small>WHAT NEEDS ATTENTION</small><h2>Problems, explained simply</h2><p>Start at the top. Each card tells you what we found, where we found it, and what to do next.</p></div></header>
          <div class="finding-list">${findingRows(scan)}</div>
        </section>
        <section id="panel-fixes" role="tabpanel" aria-labelledby="tab-fixes" data-panel="fixes" hidden>
          <header class="workspace-title"><div><small>YOUR NEXT STEPS</small><h2>Fix the most important problem first</h2><p>You do not need to solve everything at once. Complete these steps, then scan again.</p></div></header>
          <div class="priority-callout"><small>RECOMMENDED FIRST FIX</small><h3>${esc(topFinding.title)}</h3><p>${esc(topFinding.fix)}</p><button type="button" data-fix="0">See the evidence and details</button></div>
          <ul class="fix-checklist"><li>Find the file shown in the evidence</li><li>Make the recommended change</li><li>Replace any exposed password or key if needed</li><li>Run Heimdall again to confirm the warning is gone</li></ul>
          <div class="console-card impact"><h3>Want the full plan?</h3><p>Download a checklist containing every problem, its location, and the recommended next step.</p><button id="applyAll" type="button">Download the fix plan</button></div>
        </section>
        <section id="panel-paths" role="tabpanel" aria-labelledby="tab-paths" data-panel="paths" hidden>
          <header class="workspace-title"><div><small>CAUSAL MODEL</small><h2>Attack paths from evidence to impact</h2><p>Observed source is separated from inferred exploit impact. Heimdall does not claim an exploit ran.</p></div></header>
          ${attackPathMarkup(scan)}
        </section>
        <section id="panel-dependencies" role="tabpanel" aria-labelledby="tab-dependencies" data-panel="dependencies" hidden>
          <header class="workspace-title"><div><small>SUPPLY CHAIN · LIVE OSV CHECK</small><h2>Dependency intelligence</h2><p>Pinned npm, PyPI, and Go modules are matched against the Open Source Vulnerabilities database.</p></div></header>
          ${dependencyMarkup(scan)}
        </section>
        <section id="panel-replay" role="tabpanel" aria-labelledby="tab-replay" data-panel="replay" hidden>
          <header class="workspace-title"><div><small>SAFE SIMULATION</small><h2>Agent Flight Recorder</h2><p>A causal walkthrough grounded in the top structural signal. This does not execute repository code.</p></div></header>
          <div class="replay-track">
            <article><b>01</b><span><small>OBSERVED</small><h3>${esc(topFinding.evidence)}</h3><p>Repository evidence enters the model.</p></span></article><i aria-hidden="true">↓</i>
            <article><b>02</b><span><small>INFERRED</small><h3>${esc(topFinding.title)}</h3><p>${esc(topFinding.detail)}</p></span></article><i aria-hidden="true">↓</i>
            <article><b>03</b><span><small>PROPOSED CONTROL</small><h3>${esc(topFinding.fix)}</h3></span></article><i aria-hidden="true">↓</i>
            <article class="blocked"><b>04</b><span><small>SIMULATED OUTCOME</small><h3>The modeled path stops at the control</h3><p>Verify with source-level analysis and tests before merging.</p></span></article>
          </div>
        </section>
        <section id="panel-twin" role="tabpanel" aria-labelledby="tab-twin" data-panel="twin" hidden>
          <header class="workspace-title"><div><small>COUNTERFACTUAL MODEL</small><h2>Preview controls before merging</h2><p>Review how this heuristic posture indicator could change. Values are calculated from the visible finding weights.</p></div></header>
          <div class="twin-grid"><article><small>CURRENT</small><strong>${scan.score}</strong><span>Posture indicator</span><div class="radius"><i style="width:${100 - scan.score}%"></i></div><p>${scan.findings.length} active signals</p></article><div class="twin-arrow">→</div><article class="after"><small>IF ALL VISIBLE SIGNALS ARE ADDRESSED</small><strong>${improvement}</strong><span>Modeled indicator</span><div class="radius"><i style="width:${100 - improvement}%"></i></div><p>Requires verification after changes</p></article></div>
          <div class="console-card impact"><h3>What the model assumes</h3><p>Each visible finding’s weight is removed only when its proposed control is selected. Heimdall does not claim the code is fixed until a follow-up scan and test evidence confirm it.</p></div>
        </section>
        <section id="panel-history" role="tabpanel" aria-labelledby="tab-history" data-panel="history" hidden>
          <header class="workspace-title"><div><small>BEFORE AND AFTER</small><h2>Did the changes help?</h2><p>Compare this scan with the previous one to see what was fixed, what is new, and what still needs attention.</p></div></header>
          ${historyMarkup(scan)}
        </section>
        <section id="panel-copilot" role="tabpanel" aria-labelledby="tab-copilot" data-panel="copilot" hidden>
          <header class="workspace-title"><div><small>SCAN GUIDE · GROUNDED IN THIS EVIDENCE</small><h2>Repository guide</h2><p>Ask about the visible findings and remediation order. Responses come from this scan, not a connected AI service.</p></div></header>
          <div class="chat"><div id="messages" role="log" aria-live="polite"><article><b>Heimdall</b><p>I mapped ${scan.files.length} public files and found ${scan.findings.length} prioritized signals. Ask “What should I fix first?” or “How is the score calculated?”</p></article></div><form id="chatForm"><label class="sr-only" for="chatInput">Ask about this scan</label><input id="chatInput" autocomplete="off" placeholder="What should I fix first?"><button type="submit">Send</button></form></div>
        </section>
      </main>
    </div>`;
}

function activateTab(button, consoleElement) {
  $$('[data-tab]', consoleElement).forEach(tab => {
    const active = tab === button;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  $$('[data-panel]', consoleElement).forEach(panel => { panel.hidden = panel.dataset.panel !== button.dataset.tab; });
}

function openConsole(scan) {
  let consoleElement = $('#console');
  if (!consoleElement) {
    consoleElement = document.createElement('div');
    consoleElement.id = 'console';
    document.body.append(consoleElement);
  }
  lastFocused = document.activeElement;
  consoleElement.setAttribute('role', 'dialog');
  consoleElement.setAttribute('aria-modal', 'true');
  consoleElement.setAttribute('aria-label', `Heimdall console for ${scan.meta.full_name}`);
  consoleElement.setAttribute('aria-hidden', 'false');
  consoleElement.tabIndex = -1;
  consoleElement.innerHTML = consoleMarkup(scan);
  consoleElement.classList.add('open');
  document.body.style.overflow = 'hidden';
  consoleElement.focus();

  $('#backHome', consoleElement).onclick = () => closeConsole(consoleElement);
  const tabs = $$('[data-tab]', consoleElement);
  tabs.forEach((button, index) => {
    button.onclick = () => activateTab(button, consoleElement);
    button.onkeydown = event => {
      if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp'].includes(event.key)) return;
      event.preventDefault();
      const increment = ['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : -1;
      const next = tabs[(index + increment + tabs.length) % tabs.length];
      activateTab(next, consoleElement);
      next.focus();
    };
  });
  $$('[data-fix]', consoleElement).forEach(button => button.onclick = () => openFixDrawer(scan.findings[Number(button.dataset.fix)]));
  $('#exportReport', consoleElement).onclick = () => openExportDrawer(scan);
  $('#rescanRepo', consoleElement).onclick = () => {
    closeConsole(consoleElement);
    startScan(scan.repo.url);
  };
  const monitor = $('#monitorToggle', consoleElement);
  monitor.checked = localStorage.getItem('heimdall-recent-repo') === scan.repo.url;
  monitor.onchange = event => {
    if (event.target.checked) localStorage.setItem('heimdall-recent-repo', scan.repo.url);
    else localStorage.removeItem('heimdall-recent-repo');
    showToast(event.target.checked ? 'Repository remembered on this device' : 'Repository removed from this device');
  };
  $('#applyAll', consoleElement).onclick = () => {
    const content = `# Heimdall fix plan\n\nRepository: ${scan.meta.full_name}\nBranch: ${scan.branch}\nCommit: ${scan.commit}\nScope: ${scan.scope}\n\n${scan.findings.map((finding, index) => `${index + 1}. **${finding.title}** (${finding.id})\n   Evidence: ${finding.evidence}\n   Action: ${finding.fix}\n   Verification required after change.`).join('\n\n')}\n`;
    download(`heimdall-${scan.repo.repo}-fix-plan.md`, content, 'text/markdown');
    showToast('Fix plan downloaded');
  };
  const chatForm = $('#chatForm', consoleElement);
  chatForm.onsubmit = event => {
    event.preventDefault();
    const input = $('#chatInput', consoleElement);
    const question = input.value.trim();
    if (!question) return;
    const answer = /first|priority|start/i.test(question)
      ? `Start with “${scan.findings[0].title}.” Evidence: ${scan.findings[0].evidence}. Next action: ${scan.findings[0].fix}`
      : /depend|package|osv|supply/i.test(question)
        ? `I checked ${scan.dependencies.length} pinned packages against OSV and found ${scan.osv.vulnerabilities.length} advisory matches. Open Dependencies for the complete inventory.`
        : /change|history|new|fixed|previous/i.test(question)
          ? `Compared with the previous saved commit: ${scan.diff.added} new, ${scan.diff.fixed} fixed, and ${scan.diff.unchanged} unchanged findings. History stays on this device.`
          : /source|file|line|evidence/i.test(question)
            ? `This scan read ${scan.sourceStats.read} security-relevant source files. The top finding points to ${scan.findings[0].evidence}${scan.findings[0].line ? `:${scan.findings[0].line}` : ''}. Open Findings to see redacted snippets.`
      : /score|posture|calculat/i.test(question)
        ? `The posture indicator starts at 100 and subtracts visible structural-signal weights. This scan is ${scan.score}/100. It is a prioritization aid, not a guarantee.`
        : `This bounded static scan found ${scan.findings.length} findings across ${scan.sourceStats.read} source files and ${scan.dependencies.length} pinned dependencies. The top evidence is ${scan.findings[0].evidence}: ${scan.findings[0].detail}`;
    const messages = $('#messages', consoleElement);
    messages.insertAdjacentHTML('beforeend', `<article class="user"><b>You</b><p>${esc(question)}</p></article><article><b>Heimdall</b><p>${esc(answer)}</p></article>`);
    input.value = '';
    messages.scrollTop = messages.scrollHeight;
  };
}

function closeConsole(consoleElement = $('#console')) {
  if (!consoleElement) return;
  consoleElement.classList.remove('open');
  consoleElement.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  lastFocused?.focus?.();
}

function openFixDrawer(finding) {
  const existing = $('.fix-drawer');
  if (existing) existing.remove();
  drawerReturnFocus = document.activeElement;
  const drawer = document.createElement('div');
  drawer.className = 'fix-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-labelledby', 'fixTitle');
  drawer.tabIndex = -1;
  drawer.innerHTML = `<button type="button" aria-label="Close fix preview">×</button><small>${esc(finding.id)} · PROPOSED CONTROL</small><h3 id="fixTitle">${esc(finding.title)}</h3><p>${esc(finding.fix)}</p><div class="finding-evidence"><span>${esc(finding.kind)}</span><span>${esc(finding.evidence)}${finding.line ? `:${finding.line}` : ''}</span><span>${esc(finding.mapping)}</span></div>${finding.snippet ? `<pre class="source-snippet"><code>${esc(finding.snippet)}</code></pre>` : ''}<pre>- risky or missing control\n+ ${esc(finding.fix)}\n\n# Verify with tests and a follow-up scan</pre><button type="button" class="download">Download remediation note</button>`;
  document.body.append(drawer);
  requestAnimationFrame(() => { drawer.classList.add('open'); drawer.focus(); });
  const closeDrawer = () => { drawer.remove(); drawerReturnFocus?.focus?.(); };
  $('button', drawer).onclick = closeDrawer;
  $('.download', drawer).onclick = () => {
    download(`heimdall-${finding.id.toLowerCase()}-remediation.md`, `# ${finding.title}\n\n- Finding: ${finding.id}\n- Evidence: ${finding.evidence}${finding.line ? `:${finding.line}` : ''}\n- Mapping: ${finding.mapping}\n\n## Why it matters\n\n${finding.detail}\n\n## Recommended change\n\n${finding.fix}\n\n## Verification\n\nAdd a regression test, rerun Heimdall, and confirm this fingerprint no longer appears.\n`, 'text/markdown');
    showToast('Remediation note downloaded');
  };
}

function openExportDrawer(scan) {
  const existing = $('.fix-drawer');
  if (existing) existing.remove();
  drawerReturnFocus = document.activeElement;
  const drawer = document.createElement('div');
  drawer.className = 'fix-drawer export-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-labelledby', 'exportTitle');
  drawer.tabIndex = -1;
  drawer.innerHTML = `<button type="button" aria-label="Close export options">×</button><small>PORTABLE EVIDENCE</small><h3 id="exportTitle">Export this scan</h3><p>Use a human-readable report, the complete evidence payload, or SARIF for GitHub code scanning and CI tools.</p><div class="export-options"><button type="button" data-export="markdown"><b>Markdown report</b><span>Findings, evidence, fixes, and scope</span></button><button type="button" data-export="json"><b>Evidence JSON</b><span>Complete machine-readable scan</span></button><button type="button" data-export="sarif"><b>SARIF 2.1</b><span>Standard static-analysis exchange format</span></button></div>`;
  document.body.append(drawer);
  requestAnimationFrame(() => { drawer.classList.add('open'); drawer.focus(); });
  const closeDrawer = () => { drawer.remove(); drawerReturnFocus?.focus?.(); };
  $('button[aria-label]', drawer).onclick = closeDrawer;
  $$('[data-export]', drawer).forEach(button => button.onclick = () => {
    const kind = button.dataset.export;
    if (kind === 'markdown') download(`heimdall-${scan.repo.repo}-report.md`, reportMarkdown(scan), 'text/markdown');
    if (kind === 'json') download(`heimdall-${scan.repo.repo}-evidence.json`, JSON.stringify({ ...scan, sources: undefined }, null, 2), 'application/json');
    if (kind === 'sarif') download(`heimdall-${scan.repo.repo}.sarif`, JSON.stringify(reportSarif(scan), null, 2), 'application/sarif+json');
    showToast(`${kind === 'sarif' ? 'SARIF' : kind[0].toUpperCase() + kind.slice(1)} export downloaded`);
    closeDrawer();
  });
}

function download(name, text, type) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 500);
}

function showToast(message) {
  let toast = $('.toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'toast';
    toast.setAttribute('role', 'status');
    document.body.append(toast);
  }
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 2300);
}

const flightEvidence = [
  { kind: 'SIMULATED ENTRY', title: 'Untrusted instructions enter the agent.', text: 'The example begins with a support request containing hidden adversarial instructions.', source: 'Example prompt', decision: 'Agent receives the request' },
  { kind: 'SIMULATED DECISION', title: 'The agent chooses a connected tool.', text: 'Without a narrow policy, the model can choose a powerful capability to complete the request.', source: 'Agent tool registry', decision: 'shell.exec selected' },
  { kind: 'CONTROL GAP', title: 'The shell tool is too broad.', text: 'A broad command surface can bridge ordinary user input to sensitive runtime resources.', source: 'Illustrative tool policy', decision: 'Command would be allowed' },
  { kind: 'REACHABILITY', title: 'Runtime secrets become reachable.', text: 'The model shows the secret as reachable through the selected capability; no secret value is read.', source: 'Simulated process.env edge', decision: 'Sensitive node reached' },
  { kind: 'POTENTIAL IMPACT', title: 'An outbound action could move the data.', text: 'The final modeled edge demonstrates why least privilege must cover both data access and egress.', source: 'Simulated network edge', decision: 'Path completes' }
];
let flightContained = false;

function setFlightStep(step, blocked = false) {
  const nodes = $$('[data-flight]');
  const edges = $$('[data-edge]');
  nodes.forEach((node, index) => {
    node.classList.toggle('active', index === step && !blocked);
    node.classList.toggle('passed', index < step && !blocked);
    node.classList.toggle('blocked', blocked && index === 2);
    node.classList.toggle('unreachable', blocked && index > 2);
  });
  edges.forEach((edge, index) => {
    edge.classList.toggle('active', index < step && !blocked);
    edge.classList.toggle('blocked', blocked && index === 2);
  });
  if (blocked) {
    $('#evidenceKind').textContent = 'CONTROL VERIFIED IN SIMULATION';
    $('#evidenceTitle').textContent = 'The rerun stops before secret access.';
    $('#evidenceText').textContent = 'The least-privilege policy blocks the broad tool call, so downstream nodes become unreachable in the Security Twin.';
    $('#evidenceSource').textContent = 'Simulated policy evaluation';
    $('#evidenceDecision').textContent = 'shell.exec denied';
    $('#stepCount').textContent = '3 / 5 · stopped';
    $('#pathStatus').textContent = 'Contained — modeled path stopped at shell.exec';
    $('#verificationReceipt').hidden = false;
    return;
  }
  const evidence = flightEvidence[step];
  $('#evidenceKind').textContent = evidence.kind;
  $('#evidenceTitle').textContent = evidence.title;
  $('#evidenceText').textContent = evidence.text;
  $('#evidenceSource').textContent = evidence.source;
  $('#evidenceDecision').textContent = evidence.decision;
  $('#stepCount').textContent = `${step + 1} / 5`;
  $('#pathStatus').textContent = step === 4 ? 'Path complete — containment is recommended' : `Replaying step ${step + 1} of 5`;
}

function playFlightRecorder() {
  window.clearInterval(replayTimer);
  $('#verificationReceipt').hidden = true;
  $('#playReplay').disabled = true;
  let step = 0;
  setFlightStep(step);
  replayTimer = window.setInterval(() => {
    step += 1;
    if (flightContained && step === 3) {
      window.clearInterval(replayTimer);
      setFlightStep(2, true);
      $('#playReplay').disabled = false;
      return;
    }
    if (step >= flightEvidence.length) {
      window.clearInterval(replayTimer);
      $('#playReplay').disabled = false;
      return;
    }
    setFlightStep(step);
  }, 720);
}

const escrowScenario = {
  mandate: { maxCustomers: 5, maxAmount: 500, allowedTools: ['refund.create'], exportAllowed: false },
  poisonedProposal: { customers: 1842, amount: 247819, exportedRecords: 1842, tools: ['refund.create', 'customer.export', 'webhook.send'] },
  safeProposal: { customers: 5, amount: 375, exportedRecords: 0, tools: ['refund.create'] }
};
let escrowState = { phase: 'ready', warrant: null, ledger: [], receipt: null };
const wait = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));

async function sha256(value) {
  if (!window.crypto?.subtle) return Math.random().toString(16).slice(2).padEnd(64, '0');
  const bytes = new TextEncoder().encode(value);
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function setClearStep(step, mode = 'active') {
  $$('[data-clear-step]').forEach((node, index) => {
    node.classList.toggle('active', index === step && mode === 'active');
    node.classList.toggle('complete', index < step || (index === step && mode === 'complete'));
    node.classList.toggle('blocked', index === step && mode === 'blocked');
  });
}

function setClearingStatus(label, message, tone = '') {
  const status = $('#clearingStatus');
  status.className = `clearing-status ${tone}`.trim();
  $('span', status).textContent = label;
  $('b', status).textContent = message;
}

function setConsequence({ customers, amount, exportedRecords }, tone, title) {
  $('#consequenceTitle').textContent = title;
  $('#customerImpact').textContent = customers.toLocaleString();
  $('#moneyImpact').textContent = `$${amount.toLocaleString()}`;
  $('#exportImpact').textContent = exportedRecords.toLocaleString();
  const values = [
    [$('#customerDelta'), customers > 5 ? `+${(customers - 5).toLocaleString()} beyond mandate` : 'Within 5-customer limit'],
    [$('#moneyDelta'), amount > 500 ? `+$${(amount - 500).toLocaleString()} beyond budget` : 'Within $500 budget'],
    [$('#exportDelta'), exportedRecords ? 'Forbidden by mandate' : 'No export requested']
  ];
  values.forEach(([element, text]) => { element.textContent = text; element.className = tone; });
}

function terminal(lines) {
  $('#actionTerminal p').innerHTML = lines.map(line => `<span class="${line.tone ? `terminal-${line.tone}` : ''}">${esc(line.text)}</span>`).join('\n');
}

function resetEscrow() {
  escrowState = { phase: 'ready', warrant: null, ledger: [], receipt: null };
  setClearStep(-1);
  setClearingStatus('READY', 'Waiting for the agent proposal');
  setConsequence({ customers: 0, amount: 0, exportedRecords: 0 }, '', 'No action simulated');
  ['customerDelta', 'moneyDelta', 'exportDelta'].forEach(id => { $(`#${id}`).textContent = '—'; $(`#${id}`).className = ''; });
  $('#warrantCard').hidden = true;
  $('#warrantCard').classList.remove('consumed');
  $('#outcomeCard').hidden = true;
  $('#runProposal').disabled = false;
  $('#runProposal').textContent = 'Run agent proposal →';
  $('#issueWarrant').disabled = true;
  $('#commitWarrant').disabled = true;
  $('#rollbackAction').disabled = true;
  terminal([{ text: 'Ready. No external systems will be contacted.' }]);
}

async function runEscrowProposal() {
  resetEscrow();
  escrowState.phase = 'proposing';
  $('#runProposal').disabled = true;
  setClearStep(0);
  setClearingStatus('RUNNING', 'Agent is constructing a tool plan');
  terminal([
    { text: 'agent → refund.create(customers: "all")' },
    { text: 'agent → customer.export(fields: [email, account_id])' },
    { text: 'source → untrusted support-note-4821.txt' }
  ]);
  await wait(520);
  setClearStep(1);
  setClearingStatus('SIMULATING', 'Consequence Twin is evaluating the proposed diff');
  setConsequence(escrowScenario.poisonedProposal, 'danger', 'Mandate drift detected');
  await wait(720);
  setClearStep(1, 'blocked');
  setClearingStatus('BLOCKED', 'Predicted consequence violates the human mandate', 'danger');
  terminal([
    { text: 'DENY customer.export — mandate forbids data export', tone: 'danger' },
    { text: 'DENY refund.create — 1,842 records exceeds limit of 5', tone: 'danger' },
    { text: 'DENY financial impact — $247,819 exceeds budget of $500', tone: 'danger' },
    { text: 'unsafe proposal stopped before execution', tone: 'safe' }
  ]);
  escrowState.phase = 'blocked';
  $('#issueWarrant').disabled = false;
  $('#runProposal').disabled = false;
  $('#runProposal').textContent = 'Run again';
}

async function issueEscrowWarrant() {
  const nonce = crypto.getRandomValues(new Uint32Array(2));
  const payload = {
    issuer: 'Heimdall Action Clearinghouse', subject: 'finance-agent-demo',
    mandate: escrowScenario.mandate, issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(), nonce: [...nonce].join('-')
  };
  const digest = await sha256(JSON.stringify(payload));
  escrowState.warrant = { ...payload, digest, consumed: false };
  escrowState.phase = 'authorized';
  setClearStep(2, 'complete');
  setClearingStatus('AUTHORIZED', 'One-use authority narrowed to the legitimate task', 'safe');
  setConsequence(escrowScenario.safeProposal, 'safe', 'Safe transaction prepared');
  $('#warrantCard').hidden = false;
  $('#warrantState').textContent = 'ACTIVE · 60s';
  $('#warrantId').textContent = `SNT-${digest.slice(0, 12).toUpperCase()}`;
  terminal([
    { text: `warrant ${digest.slice(0, 12)}… issued`, tone: 'safe' },
    { text: 'ALLOW refund.create — exactly 5 customers · $375' },
    { text: 'DENY all exports · DENY delegation · expires in 60s' },
    { text: 'credentials: task-scoped · one use · not shown to agent' }
  ]);
  $('#issueWarrant').disabled = true;
  $('#commitWarrant').disabled = false;
}

async function commitEscrowWarrant() {
  if (!escrowState.warrant || escrowState.warrant.consumed) return;
  setClearStep(3);
  setClearingStatus('COMMITTING', 'Applying five refunds inside the escrow ledger');
  $('#commitWarrant').disabled = true;
  const before = Array.from({ length: 5 }, (_, index) => ({ id: `C-${48210 + index}`, refunded: false, amount: 75 }));
  const after = before.map(record => ({ ...record, refunded: true }));
  await wait(650);
  const total = after.reduce((sum, record) => sum + record.amount, 0);
  const verified = after.length === 5 && total <= 500 && after.every(record => record.refunded);
  escrowState.ledger = after;
  escrowState.warrant.consumed = true;
  const receiptPayload = { warrant: escrowState.warrant.digest, before, after, verified, committedAt: new Date().toISOString() };
  const receipt = await sha256(JSON.stringify(receiptPayload));
  escrowState.receipt = receipt;
  setClearStep(4, verified ? 'complete' : 'blocked');
  setClearingStatus(verified ? 'VERIFIED' : 'FAILED', verified ? 'Authorized outcome matches the predicted consequence' : 'Postcondition failed; rollback required', verified ? 'safe' : 'danger');
  $('#warrantCard').classList.add('consumed');
  $('#warrantState').textContent = 'CONSUMED';
  $('#outcomeCard').hidden = false;
  $('#receiptHash').textContent = `sha256:${receipt}`;
  $('#receiptText').textContent = '5 of 5 refunds verified · $375 committed · 0 records exported · authority revoked.';
  terminal([
    { text: 'BEGIN escrow transaction' },
    ...after.map(record => ({ text: `refund.create(${record.id}, $${record.amount}) → verified`, tone: 'safe' })),
    { text: `COMMIT · receipt sha256:${receipt.slice(0, 16)}…`, tone: 'safe' },
    { text: 'temporary authority revoked' }
  ]);
  escrowState.phase = 'committed';
  $('#rollbackAction').disabled = false;
}

async function rollbackEscrowAction() {
  if (escrowState.phase !== 'committed') return;
  setClearingStatus('ROLLING BACK', 'Executing the compensating transaction');
  $('#rollbackAction').disabled = true;
  await wait(520);
  escrowState.ledger = escrowState.ledger.map(record => ({ ...record, refunded: false }));
  const rollbackHash = await sha256(JSON.stringify({ receipt: escrowState.receipt, rolledBackAt: new Date().toISOString(), records: escrowState.ledger }));
  escrowState.phase = 'rolled-back';
  setClearingStatus('ROLLED BACK', 'All five simulated refunds were reversed and verified', 'safe');
  $('#receiptHash').textContent = `sha256:${rollbackHash}`;
  $('#receiptText').textContent = 'Compensating transaction verified · ledger restored · original receipt retained in the audit chain.';
  terminal([
    { text: 'BEGIN compensating transaction' },
    { text: '5 refund records reversed', tone: 'safe' },
    { text: 'ledger equals pre-action snapshot', tone: 'safe' },
    { text: `ROLLBACK VERIFIED · sha256:${rollbackHash.slice(0, 16)}…`, tone: 'safe' }
  ]);
}

function setupActionEscrow() {
  resetEscrow();
  $('#runProposal').onclick = runEscrowProposal;
  $('#issueWarrant').onclick = issueEscrowWarrant;
  $('#commitWarrant').onclick = commitEscrowWarrant;
  $('#rollbackAction').onclick = rollbackEscrowAction;
}

function setupLandingInteractions() {
  const journey = $('#journey');
  const journeyCards = $$('.scroll-story-cards article');
  let journeyComplete = false;
  const updateJourneyStory = () => {
    if (!journey || !journeyCards.length) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.innerWidth <= 760;
    if (reduced) {
      journeyCards.forEach(card => { card.style.opacity = ''; card.style.transform = ''; card.classList.remove('story-active', 'story-settled'); });
      return;
    }
    const track = $('.scroll-story-cards');
    const cardWidth = journeyCards[0].offsetWidth;
    const available = track.clientWidth - cardWidth;
    const centerX = available / 2;
    const start = journey.offsetTop;
    const range = Math.max(1, journey.offsetHeight - window.innerHeight);
    const progress = Math.max(0, Math.min(0.999, (window.scrollY - start) / range));
    if (progress >= .94) journeyComplete = true;
    journeyCards.forEach((card, index) => {
      const phase = journeyComplete ? 1 : Math.max(0, Math.min(1, progress * journeyCards.length - index));
      const arrival = Math.min(1, phase / .28);
      const settling = Math.max(0, Math.min(1, (phase - .28) / .72));
      const eased = 1 - Math.pow(1 - settling, 3);
      const finalX = available * (index / (journeyCards.length - 1));
      const x = centerX + (finalX - centerX) * eased;
      const scale = .94 + arrival * .1 - settling * .04;
      const y = 12 + eased * 82;
      card.style.opacity = String(arrival);
      card.style.transform = `translate3d(${x}px, ${y}px, 0) scale(${scale})`;
      card.style.zIndex = String(10 + (phase > 0 && phase < 1 ? 2 : 0) - index);
      card.classList.toggle('story-active', phase > 0 && phase < 1);
      card.classList.toggle('story-settled', phase >= 1);
    });
  };
  const setScanMode = mode => {
    scanMode = mode;
    const reference = mode === 'reference';
    $('#projectPanel').hidden = reference;
    $('#referencePanel').hidden = !reference;
    $('#projectMode').classList.toggle('active', !reference);
    $('#referenceMode').classList.toggle('active', reference);
    $('#projectMode').setAttribute('aria-selected', String(!reference));
    $('#referenceMode').setAttribute('aria-selected', String(reference));
    $('#heroLabel').textContent = reference ? 'Before you reuse outside code' : 'Protect what you are building';
    $('#heroTitle').innerHTML = reference ? 'Know if a reference fits<br><em>your project.</em>' : 'Find security gaps<br><em>before you ship.</em>';
    $('#heroLede').textContent = reference
      ? 'Add your project, the public repository you want to learn from, and how you plan to use it. Heimdall checks the evidence, and Gemini explains whether it is a sensible fit.'
      : 'Paste the public GitHub repository you are building. Heimdall checks its files and packages, explains every problem in normal words, and shows what to fix first.';
    $('#scanSubmit').innerHTML = `${reference ? 'Check this reference' : 'Scan my project'} <span aria-hidden="true">→</span>`;
    repoError.textContent = '';
  };
  $('#projectMode').onclick = () => setScanMode('project');
  $('#referenceMode').onclick = () => setScanMode('reference');
  $('#scan').onsubmit = event => {
    event.preventDefault();
    if (scanMode === 'reference') startIntegrationReview(compareProjectInput.value, toolRepoInput.value, useCaseInput.value);
    else startScan(repoInput.value);
  };
  [repoInput, compareProjectInput, toolRepoInput].forEach(input => input.addEventListener('input', () => { input.removeAttribute('aria-invalid'); repoError.textContent = ''; }));
  $$('.project-demo').forEach(button => button.onclick = () => {
    setScanMode('project');
    repoInput.value = 'https://github.com/OWASP/NodeGoat';
    startScan(repoInput.value);
  });
  $$('.reference-demo').forEach(button => button.onclick = () => {
    setScanMode('reference');
    compareProjectInput.value = 'https://github.com/surya0901/HackRU-2026';
    toolRepoInput.value = 'https://github.com/OWASP/NodeGoat';
    useCaseInput.value = 'Use the tool as a learning example inside my security project';
    document.querySelector('#top').scrollIntoView({ behavior: 'smooth' });
    compareProjectInput.focus({ preventScroll: true });
  });
  $('#close').onclick = () => closeModal(true);
  $('#launchConsole').onclick = () => result ? openConsole(result) : startScan('https://github.com/OWASP/NodeGoat');
  $('#agentButton').onclick = () => result ? openConsole(result) : startScan('https://github.com/OWASP/NodeGoat');
  $('#playReplay').onclick = playFlightRecorder;
  $('#containPath').onclick = () => {
    flightContained = true;
    $('#containmentLine').hidden = false;
    $('#containPath').textContent = 'Control inserted · rerun now';
    $('#pathStatus').textContent = 'Least-privilege policy inserted before secret access';
    playFlightRecorder();
  };

  const nav = $('nav');
  const navToggle = $('#navToggle');
  navToggle.onclick = () => {
    const open = nav.classList.toggle('menu-open');
    navToggle.setAttribute('aria-expanded', String(open));
    navToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    navToggle.textContent = open ? '×' : '☰';
  };
  $$('.links a').forEach(link => link.onclick = () => {
    nav.classList.remove('menu-open');
    navToggle.setAttribute('aria-expanded', 'false');
    navToggle.setAttribute('aria-label', 'Open navigation');
    navToggle.textContent = '☰';
  });

  const revealTargets = $$('.intro,.center,.cards:not(.scroll-story-cards),.stats,.flight-recorder,.extension-showcase,.final');
  if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    revealTargets.forEach(target => target.classList.add('reveal-ready'));
    const revealObserver = new IntersectionObserver(entries => entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('is-visible'); revealObserver.unobserve(entry.target); }
    }), { threshold: 0.12 });
    revealTargets.forEach(target => revealObserver.observe(target));
  }

  const sections = $$('main section[id]');
  const navLinks = $$('.links a');
  const floatHeadings = $$('[data-scroll-float]');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!reduceMotion) {
    floatHeadings.forEach(heading => {
      const label = heading.textContent.trim();
      heading.setAttribute('aria-label', label);
      heading.textContent = '';
      [...label].forEach((character, index) => {
        const span = document.createElement('span');
        span.className = 'scroll-float-char';
        span.setAttribute('aria-hidden', 'true');
        span.style.setProperty('--char-index', index);
        span.textContent = character === ' ' ? '\u00a0' : character;
        heading.append(span);
      });
    });
  }
  const updateScrollFloat = () => {
    if (reduceMotion) return;
    floatHeadings.forEach(heading => {
      const bounds = heading.getBoundingClientRect();
      const travel = window.innerHeight * 0.72;
      const progress = heading.dataset.floatComplete === 'true'
        ? 1
        : Math.max(0, Math.min(1, (window.innerHeight - bounds.top) / travel));
      if (progress >= 0.995) heading.dataset.floatComplete = 'true';
      const characters = $$('.scroll-float-char', heading);
      characters.forEach((character, index) => {
        const start = index / Math.max(1, characters.length) * 0.32;
        const local = Math.max(0, Math.min(1, (progress - start) / 0.68));
        const eased = 1 - Math.pow(1 - local, 3);
        character.style.opacity = eased;
        character.style.transform = `translateY(${(1 - eased) * 105}%) scaleX(${0.76 + eased * 0.24}) scaleY(${1.85 - eased * 0.85})`;
      });
    });
  };
  const updateScroll = () => {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    $('#scrollProgress').style.width = `${max > 0 ? Math.min(100, window.scrollY / max * 100) : 0}%`;
    let current = sections[0]?.id;
    sections.forEach(section => { if (section.getBoundingClientRect().top <= 120) current = section.id; });
    navLinks.forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${current}`));
    updateJourneyStory();
    updateScrollFloat();
  };
  updateScroll();
  window.addEventListener('scroll', updateScroll, { passive: true });
  window.addEventListener('resize', updateJourneyStory, { passive: true });

  const tiltCard = $('[data-tilt-card]');
  if (tiltCard && window.matchMedia('(pointer: fine)').matches && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const resetTilt = () => {
      tiltCard.style.setProperty('--tilt-x', '0deg');
      tiltCard.style.setProperty('--tilt-y', '0deg');
      tiltCard.style.setProperty('--lift', '0px');
    };
    tiltCard.addEventListener('pointermove', event => {
      const bounds = tiltCard.getBoundingClientRect();
      const x = (event.clientX - bounds.left) / bounds.width - 0.5;
      const y = (event.clientY - bounds.top) / bounds.height - 0.5;
      tiltCard.style.setProperty('--tilt-x', `${(-y * 4).toFixed(2)}deg`);
      tiltCard.style.setProperty('--tilt-y', `${(x * 5).toFixed(2)}deg`);
      tiltCard.style.setProperty('--lift', '-5px');
    });
    tiltCard.addEventListener('pointerleave', resetTilt);
    tiltCard.addEventListener('blur', resetTilt);
  }
}

document.addEventListener('keydown', event => {
  const drawer = $('.fix-drawer');
  const activeDialog = drawer || (modal.classList.contains('open') ? modal : $('#console.open'));
  if (event.key === 'Tab' && activeDialog) {
    const focusable = $$('a[href],button:not([disabled]),input:not([disabled]),[tabindex]:not([tabindex="-1"])', activeDialog)
      .filter(element => !element.hidden && element.offsetParent !== null);
    if (focusable.length) {
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  }
  if (event.key !== 'Escape') return;
  if (drawer) { drawer.remove(); drawerReturnFocus?.focus?.(); return; }
  if (modal.classList.contains('open')) { closeModal(true); return; }
  if ($('#console.open')) closeConsole();
});

setupLandingInteractions();
setupActionEscrow();
