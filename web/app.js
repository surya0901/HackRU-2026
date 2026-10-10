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
const repoError = $('#repoError');
let scanAbortController = null;
let result = null;
let lastFocused = null;
let replayTimer = null;
let drawerReturnFocus = null;

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
  const grade = scan.score >= 90 ? 'A' : scan.score >= 80 ? 'B' : scan.score >= 70 ? 'C' : scan.score >= 60 ? 'D' : 'F';
  const date = new Date(scan.createdAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  const topFinding = scan.findings[0];
  const improvement = Math.min(100, scan.score + scan.findings.reduce((total, finding) => total + finding.points, 0));
  return `
    <div class="console-head">
      <div><button id="backHome" type="button">← Site</button><span class="console-brand"><img src="heimdall-logo.svg" alt=""> Heimdall Console</span></div>
      <div><span class="live-data">● Live source + OSV</span><button id="rescanRepo" type="button">Rescan</button><button id="exportReport" type="button">Export</button></div>
    </div>
    <div class="console-shell">
      <aside>
        <p>WORKSPACE</p>
        <div class="console-tabs" role="tablist" aria-label="Console sections">
        ${[
          ['overview', 'Overview'], ['findings', `Findings (${scan.findings.length})`], ['paths', 'Attack paths'], ['dependencies', `Dependencies (${scan.dependencies.length})`], ['replay', 'Flight recorder'], ['twin', 'Security Twin'], ['history', 'History'], ['copilot', 'Guide']
        ].map(([id, label], index) => `<button type="button" role="tab" aria-selected="${index === 0}" aria-controls="panel-${id}" id="tab-${id}" data-tab="${id}" class="${index ? '' : 'active'}">${label}</button>`).join('')}
        </div>
        <hr><small>DEVICE WORKSPACE</small>
        <label><input id="monitorToggle" type="checkbox"> Remember this repo</label>
        <a href="${esc(scan.repo.url)}" target="_blank" rel="noopener noreferrer">Open on GitHub ↗</a>
      </aside>
      <main class="console-main">
        <section id="panel-overview" role="tabpanel" aria-labelledby="tab-overview" data-panel="overview">
          <header class="workspace-title"><div><small>${esc(scan.meta.full_name)}</small><h2>What needs attention now</h2><p>${esc(scan.meta.description || 'Public repository security posture.')}</p></div><div class="trust" style="--score:${scan.score}%"><strong>${scan.score}</strong><span>/100 · ${grade}</span></div></header>
          <div class="console-provenance"><span>Branch ${esc(scan.branch)}</span><span>Commit ${esc(scan.commit.slice(0, 7))}</span><span>${esc(date)}</span><span>${esc(scan.scope)}</span></div>
          <div class="priority-callout"><small>FIX FIRST · ${esc(topFinding.id)}</small><h3>${esc(topFinding.title)}</h3><p>${esc(topFinding.detail)}</p><button type="button" data-fix="0">Review the evidence and fix</button></div>
          <div class="metrics"><article><small>SOURCE ANALYZED</small><b>${scan.sourceStats.read}</b><span>${Math.round(scan.sourceStats.bytes / 1024)} KB of relevant code</span></article><article><small>DEPENDENCIES CHECKED</small><b>${scan.dependencies.length}</b><span>${scan.osv.vulnerabilities.length} OSV advisory matches</span></article><article><small>PRIORITY FINDINGS</small><b>${scan.findings.length}</b><span>${scan.diff.added} new · ${scan.diff.fixed} fixed</span></article></div>
          <div class="console-card"><header><h3>Capability path</h3><span>Derived from source evidence; impact remains inferred until runtime validation</span></header>${permissionGraph(scan)}<p class="scope-note">Posture indicator = 100 minus weighted findings. It helps prioritize review; it is not a certification or guarantee.</p></div>
        </section>
        <section id="panel-findings" role="tabpanel" aria-labelledby="tab-findings" data-panel="findings" hidden>
          <header class="workspace-title"><div><small>PRIORITIZED</small><h2>Evidence before opinion</h2><p>Every signal shows its source, classification, mapping, and next action.</p></div></header>
          <div class="finding-list">${findingRows(scan)}</div>
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
          <div class="console-card impact"><h3>What the model assumes</h3><p>Each visible finding’s weight is removed only when its proposed control is selected. Heimdall does not claim the code is fixed until a follow-up scan and test evidence confirm it.</p><button id="applyAll" type="button">Download the fix plan</button></div>
        </section>
        <section id="panel-history" role="tabpanel" aria-labelledby="tab-history" data-panel="history" hidden>
          <header class="workspace-title"><div><small>REGRESSION VIEW</small><h2>What changed since the last commit</h2><p>Heimdall fingerprints findings by rule, file, and line so rescans can separate new, fixed, and unchanged risk.</p></div></header>
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
  $('#scan').onsubmit = event => { event.preventDefault(); startScan(repoInput.value); };
  repoInput.addEventListener('input', () => { repoInput.removeAttribute('aria-invalid'); repoError.textContent = ''; });
  $$('.demo').forEach(button => button.onclick = () => {
    repoInput.value = 'https://github.com/OWASP/NodeGoat';
    startScan(repoInput.value);
  });
  $('#close').onclick = () => closeModal(true);
  $('#launchConsole').onclick = () => result ? openConsole(result) : startScan('https://github.com/OWASP/NodeGoat');
  $('#agentButton').onclick = () => result ? openConsole(result) : startScan('https://github.com/OWASP/NodeGoat');
  $('#previewExtension').onclick = () => {
    const panel = $('.extension-panel');
    panel.classList.add('highlight');
    panel.scrollIntoView({ behavior: 'smooth', block: 'center' });
    showToast('The companion stays beside the active GitHub page');
    window.setTimeout(() => panel.classList.remove('highlight'), 1600);
  };
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

  const revealTargets = $$('.intro,.center,.cards,.stats,.flight-recorder,.extension-showcase,.final');
  if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    revealTargets.forEach(target => target.classList.add('reveal-ready'));
    const revealObserver = new IntersectionObserver(entries => entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('is-visible'); revealObserver.unobserve(entry.target); }
    }), { threshold: 0.12 });
    revealTargets.forEach(target => revealObserver.observe(target));
  }

  const sections = $$('main section[id]');
  const navLinks = $$('.links a');
  const updateScroll = () => {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    $('#scrollProgress').style.width = `${max > 0 ? Math.min(100, window.scrollY / max * 100) : 0}%`;
    let current = sections[0]?.id;
    sections.forEach(section => { if (section.getBoundingClientRect().top <= 120) current = section.id; });
    navLinks.forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${current}`));
  };
  updateScroll();
  window.addEventListener('scroll', updateScroll, { passive: true });
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
