// Only versions established by repository data are sent to OSV. A declaration
// such as ^1.2.3 is not the version installed by the application.
const SEMVER = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
const PYTHON_VERSION = /^(?:\d+!)?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[a-zA-Z0-9.]+)?$/;
const GO_VERSION = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const lexical = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function exactVersion(value, ecosystem) {
  if (typeof value !== 'string') return null;
  const version = value.trim();
  if (ecosystem === 'Go') return GO_VERSION.test(version) ? version : null;
  if (ecosystem === 'PyPI') return PYTHON_VERSION.test(version) ? version : null;
  return SEMVER.exec(version)?.[1] || null;
}

function lineOf(content, key) {
  const index = content.indexOf(key);
  return index < 0 ? 1 : content.slice(0, index).split('\n').length;
}

function declaredText(value, name = '') {
  const text = String(value || '');
  if (/(?:api[_-]?key|secret|password|passwd|token|credential|private[_-]?key)/i.test(name) && text.length >= 16) {
    const counts = new Map();
    for (const char of text) counts.set(char, (counts.get(char) || 0) + 1);
    const entropy = -[...counts.values()].reduce((total, count) => { const fraction = count / text.length; return total + fraction * Math.log2(fraction); }, 0);
    if (entropy >= 3.2 && !/^(?:\$\{|\$[A-Z_]+$|<|\[|(?:your|example|sample|placeholder|dummy|test)[_-]|changeme|replace|redacted|process\.env)/i.test(text)) return '[redacted credential candidate]';
  }
  return text.replace(/(https?:\/\/)[^/@\s]+:[^/@\s]+@/gi, '$1[redacted]@')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, '[redacted credential]')
    .slice(0, 300);
}

// Preserve exact JSON-property locations, including escaped keys and nested
// lock entries. JSON.parse alone discards these source coordinates.
function jsonLocations(content) {
  const locations = new Map();
  let cursor = 0, currentLine = 1;
  const whitespace = () => { while (cursor < content.length && /\s/.test(content[cursor])) { if (content[cursor] === '\n') currentLine++; cursor++; } };
  const quoted = () => {
    const start = cursor++;
    while (cursor < content.length) { if (content[cursor] === '\\') cursor += 2; else if (content[cursor++] === '"') break; }
    return JSON.parse(content.slice(start, cursor));
  };
  const value = path => {
    whitespace(); locations.set(JSON.stringify(path), currentLine);
    const char = content[cursor];
    if (char === '{') {
      cursor++; whitespace();
      while (content[cursor] !== '}' && cursor < content.length) {
        const key = quoted(); whitespace(); cursor++; value([...path, key]); whitespace();
        if (content[cursor] !== ',') break;
        cursor++; whitespace();
      }
      cursor++;
    } else if (char === '[') {
      cursor++; whitespace(); let index = 0;
      while (content[cursor] !== ']' && cursor < content.length) { value([...path, index++]); whitespace(); if (content[cursor] !== ',') break; cursor++; whitespace(); }
      cursor++;
    } else if (char === '"') quoted();
    else while (cursor < content.length && !/[\s,}\]]/.test(content[cursor])) cursor++;
  };
  value([]);
  return path => locations.get(JSON.stringify(path)) || 1;
}

function dependency(name, declaredVersion, ecosystem, source, parser, line) {
  const safeName = declaredText(name);
  const safeDeclaration = declaredText(declaredVersion, name);
  const version = safeName === name && safeDeclaration === String(declaredVersion || '') ? exactVersion(declaredVersion, ecosystem) : null;
  return {
    ecosystem, name: safeName, version, declaredVersion: safeDeclaration,
    file: source.path, line: line || lineOf(source.content, JSON.stringify(name)),
    resolved: !!version, exact: !!version,
    status: version ? 'RESOLVED_VERSION' : 'UNRESOLVED_VERSION',
    provenance: { status: 'OBSERVED', file: source.path, line: line || lineOf(source.content, JSON.stringify(name)), parser }
  };
}

export function parseDependencies(sources, diagnostics = []) {
  if (!Array.isArray(diagnostics)) diagnostics = [];
  const dependencies = [];
  if (!Array.isArray(sources)) { diagnostics.push({ code: 'DEPENDENCY_SOURCES_INVALID', message: 'Dependency sources must be an array.' }); return dependencies; }
  const validSources = sources.filter(source => source && typeof source.path === 'string' && typeof source.content === 'string');
  if (validSources.length !== sources.length) diagnostics.push({ code: 'DEPENDENCY_SOURCE_INVALID', message: 'One or more dependency source records were malformed.' });
  for (const source of [...validSources].sort((a, b) => lexical(a.path, b.path))) {
    const basename = source.path.split('/').pop();
    if (['package.json', 'package-lock.json', 'npm-shrinkwrap.json'].includes(basename)) {
      let manifest;
      try { manifest = JSON.parse(source.content); }
      catch { diagnostics.push({ file: source.path, code: 'DEPENDENCY_PARSE_FAILED', message: 'Dependency JSON could not be parsed.' }); continue; }
      if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
        diagnostics.push({ file: source.path, code: 'DEPENDENCY_PARSE_FAILED', message: 'Expected a dependency object.' }); continue;
      }
      let locationAt;
      try { locationAt = jsonLocations(source.content); }
      catch { diagnostics.push({ file: source.path, code: 'DEPENDENCY_PARSE_FAILED', message: 'Dependency source location parser could not handle this JSON structure.' }); continue; }
      if (basename === 'package.json') {
        for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
          const declarations = manifest[section];
          if (declarations === undefined) continue;
          if (!declarations || typeof declarations !== 'object' || Array.isArray(declarations)) {
            diagnostics.push({ file: source.path, code: 'DEPENDENCY_PARSE_FAILED', message: `Expected ${section} to contain package/version declarations.` }); continue;
          }
          for (const [name, declaredVersion] of Object.entries(declarations)) {
            if (typeof declaredVersion === 'string') dependencies.push(dependency(name, declaredVersion, 'npm', source, `npm-manifest:${section}`, locationAt([section, name])));
            else diagnostics.push({ file: source.path, line: locationAt([section, name]), code: 'DEPENDENCY_DECLARATION_UNSUPPORTED', message: 'A package declaration did not contain a version string.' });
          }
        }
      } else if (manifest.packages && typeof manifest.packages === 'object' && !Array.isArray(manifest.packages)) {
        for (const [location, entry] of Object.entries(manifest.packages)) {
          if (!location || !entry || entry.link || !location.includes('node_modules/')) continue;
          const name = entry.name || location.slice(location.lastIndexOf('node_modules/') + 13);
          if (name) {
            const line = locationAt(entry.version === undefined ? ['packages', location] : ['packages', location, 'version']);
            dependencies.push(dependency(name, typeof entry.version === 'string' ? entry.version : '', 'npm', source, 'npm-lock', line));
          }
        }
      } else {
        if (Number(manifest.lockfileVersion) >= 2 || (manifest.dependencies !== undefined && (!manifest.dependencies || typeof manifest.dependencies !== 'object' || Array.isArray(manifest.dependencies)))) {
          diagnostics.push({ file: source.path, code: 'DEPENDENCY_PARSE_FAILED', message: 'The lockfile did not contain a supported package-resolution structure.' }); continue;
        }
        const visit = (entries, path = ['dependencies']) => {
          for (const [name, entry] of Object.entries(entries || {})) {
            if (!entry || typeof entry !== 'object') continue;
            dependencies.push(dependency(name, typeof entry.version === 'string' ? entry.version : '', 'npm', source, 'npm-lock-v1', locationAt(entry.version === undefined ? [...path, name] : [...path, name, 'version'])));
            visit(entry.dependencies, [...path, name, 'dependencies']);
          }
        };
        visit(manifest.dependencies);
      }
    } else if (/^requirements(?:[-_.][^/]*)?\.txt$/i.test(basename)) {
      source.content.split(/\r?\n/).forEach((raw, index) => {
        const line = raw.trim();
        if (!line || line.startsWith('#')) return;
        // Includes, URLs, editable installs and arbitrary equality are not
        // resolved here: they require installer/workspace semantics.
        if (/^(?:-|https?:|git\+)/.test(line)) {
          diagnostics.push({ file: source.path, line: index + 1, code: 'DEPENDENCY_DECLARATION_UNSUPPORTED', message: 'Requirements include or source URL was not resolved.' }); return;
        }
        const match = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*([^;#]*)(?:;[^#]*)?(?:#.*)?$/);
        if (!match) { diagnostics.push({ file: source.path, line: index + 1, code: 'DEPENDENCY_DECLARATION_UNSUPPORTED', message: 'Requirement declaration could not be parsed.' }); return; }
        const constraint = match[2].trim();
        const pin = constraint.match(/^==\s*([^\s,]+)$/);
        const item = dependency(match[1].toLowerCase().replace(/[-_.]+/g, '-'), pin ? pin[1] : constraint, 'PyPI', source, 'requirements', index + 1);
        if (!pin) { item.version = null; item.resolved = false; item.exact = false; item.status = 'UNRESOLVED_VERSION'; }
        item.declaredVersion = declaredText(constraint, match[1]);
        dependencies.push(item);
      });
    } else if (basename === 'go.mod') {
      let inRequire = false;
      const replacements = new Set();
      for (const raw of source.content.split(/\r?\n/)) {
        const direct = raw.match(/^\s*replace\s+(\S+)(?:\s+\S+)?\s*=>/);
        if (direct) replacements.add(direct[1]);
      }
      source.content.split(/\r?\n/).forEach((raw, index) => {
        const line = raw.replace(/\/\/.*$/, '').trim();
        if (/^require\s*\(/.test(line)) { inRequire = true; return; }
        if (line === ')') { inRequire = false; return; }
        const match = (inRequire ? line : line.replace(/^require\s+/, '')).match(/^(\S+)\s+(v\S+)$/);
        if (!match || (!inRequire && !/^require\s+/.test(line))) {
          if (line && (inRequire || /^require\s+/.test(line))) diagnostics.push({ file: source.path, line: index + 1, code: 'DEPENDENCY_DECLARATION_UNSUPPORTED', message: 'A Go require declaration could not be resolved to an exact module/version pair.' });
          return;
        }
        const item = dependency(match[1], match[2], 'Go', source, 'go.mod', index + 1);
        if (replacements.has(match[1]) || /\breplace\s*\(/.test(source.content)) {
          item.version = null; item.resolved = false; item.exact = false; item.status = 'UNRESOLVED_VERSION';
          diagnostics.push({ file: source.path, line: index + 1, code: 'GO_REPLACEMENT_UNRESOLVED', message: 'Go module replacement semantics require installer resolution.' });
        }
        dependencies.push(item);
      });
    }
  }
  const unique = new Map();
  for (const item of dependencies) {
    const key = [item.ecosystem, item.name, item.version || item.declaredVersion, item.file].join('\u0000');
    if (!unique.has(key)) unique.set(key, item);
  }
  return [...unique.values()].sort((a, b) => lexical(a.file, b.file) || lexical(a.name, b.name) || lexical(String(a.version), String(b.version)));
}

export function cancellationError() {
  const error = new Error('Scan cancelled.');
  error.name = 'AbortError'; error.code = 'CANCELLED';
  return error;
}

export async function fetchWithTimeout(url, init = {}, options = {}) {
  if (options.signal?.aborted) throw cancellationError();
  const controller = new AbortController();
  let timedOut = false;
  let rejectInterrupted;
  const interrupted = new Promise((resolve, reject) => { rejectInterrupted = reject; });
  const abort = () => { controller.abort(); rejectInterrupted(cancellationError()); };
  options.signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true; controller.abort();
    rejectInterrupted(Object.assign(new Error('Request timed out.'), { code: 'TIMEOUT' }));
  }, options.timeoutMs || 15000);
  try {
    const completed = (async () => {
      const response = await (options.fetch || globalThis.fetch)(url, { ...init, credentials: 'omit', signal: controller.signal });
      // Reading the response is part of the timeout; a server can send headers
      // promptly and then stall while transferring the body.
      return { response, body: await response.text() };
    })();
    const result = await Promise.race([completed, interrupted]);
    if (options.signal?.aborted) throw cancellationError();
    if (timedOut) { const error = new Error('Request timed out.'); error.code = 'TIMEOUT'; throw error; }
    return result;
  } catch (error) {
    if (options.signal?.aborted) throw cancellationError();
    if (timedOut) { const timeout = new Error('Request timed out.'); timeout.code = 'TIMEOUT'; throw timeout; }
    throw error;
  } finally {
    clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
  }
}

async function mapLimit(items, concurrency, mapper) {
  const result = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) { const index = cursor++; result[index] = await mapper(items[index], index); }
  }));
  return result;
}

async function osvJSON(url, init, options) {
  const { response, body } = await fetchWithTimeout(url, init, options);
  if (!response.ok) { const error = new Error(`OSV returned HTTP ${response.status}.`); error.code = 'OSV_HTTP_ERROR'; throw error; }
  try { return JSON.parse(body); }
  catch { const error = new Error('OSV returned invalid JSON.'); error.code = 'OSV_INVALID_RESPONSE'; throw error; }
}

function samePackage(a, b, ecosystem) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (ecosystem === 'PyPI') return a.toLowerCase().replace(/[-_.]+/g, '-') === b.toLowerCase().replace(/[-_.]+/g, '-');
  return a === b;
}

export async function queryVulnerabilities(dependencies, options = {}) {
  const diagnostics = [];
  if (!Array.isArray(dependencies)) dependencies = [];
  const budget = (value, fallback, maximum) => Number.isFinite(value) && value >= 0 ? Math.min(maximum, Math.floor(value)) : fallback;
  const unique = new Map();
  for (const item of dependencies) if (item && item.exact && exactVersion(item.version, item.ecosystem) && typeof item.name === 'string' && item.name && ['npm', 'PyPI', 'Go'].includes(item.ecosystem)) {
    const key = [item.ecosystem, item.name, item.version].join('\u0000');
    if (!unique.has(key)) unique.set(key, item);
  }
  const allExact = [...unique.values()];
  const selected = allExact.slice(0, budget(options.maxDependencies, 128, 512));
  const checks = selected.map(item => ({ dependency: item, status: 'PENDING', advisoryIds: [] }));
  const unresolvedCount = dependencies.filter(item => !item || !item.exact || !exactVersion(item.version, item.ecosystem)).length;
  const result = { status: 'NOT_NEEDED', available: true, checks, vulnerabilities: [], matches: [], checkedCount: 0, checked: 0, exactCount: allExact.length, unresolvedCount, skippedCount: allExact.length - selected.length, diagnostics };
  if (result.skippedCount) diagnostics.push({ code: 'OSV_DEPENDENCY_LIMIT', message: `${result.skippedCount} exact package versions were outside the advisory request budget.` });
  if (!selected.length) { if (allExact.length) { result.status = 'PARTIAL'; result.available = false; } return result; }
  for (let offset = 0; offset < selected.length; offset += 64) {
    const batch = selected.slice(offset, offset + 64);
    options.onProgress?.('dependencies', `Checking ${batch.length} exact package versions against OSV.`, { done: offset, total: selected.length });
    try {
      const payload = await osvJSON('https://api.osv.dev/v1/querybatch', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: batch.map(item => ({ package: { name: item.name, ecosystem: item.ecosystem }, version: item.version })) })
      }, options);
      if (!Array.isArray(payload.results) || payload.results.length !== batch.length) throw Object.assign(new Error('OSV returned an incomplete batch response.'), { code: 'OSV_INVALID_RESPONSE' });
      payload.results.forEach((entry, index) => {
        if (!entry || (entry.vulns !== undefined && !Array.isArray(entry.vulns))) throw Object.assign(new Error('OSV returned an invalid package response.'), { code: 'OSV_INVALID_RESPONSE' });
        if ((entry.vulns || []).some(vuln => !vuln || typeof vuln.id !== 'string' || !vuln.id || vuln.id.length >= 200)) throw Object.assign(new Error('OSV returned an invalid advisory identity.'), { code: 'OSV_INVALID_RESPONSE' });
        const check = checks[offset + index];
        check.status = 'CHECKED';
        check.advisoryIds = [...new Set((entry.vulns || []).map(vuln => vuln.id).filter(id => typeof id === 'string' && id.length < 200))];
      });
    } catch (error) {
      if (error.code === 'CANCELLED' || options.signal?.aborted) throw cancellationError();
      for (let index = offset; index < offset + batch.length; index++) { checks[index].status = 'LOOKUP_FAILED'; checks[index].advisoryIds = []; }
      diagnostics.push({ code: error.code || 'OSV_NETWORK_ERROR', message: `Advisory lookup failed for ${batch.length} exact package versions: ${error.message}` });
    }
  }
  const ids = [...new Set(checks.flatMap(check => check.advisoryIds))].sort();
  const selectedIds = ids.slice(0, budget(options.maxAdvisories, 80, 200));
  const details = new Map();
  await mapLimit(selectedIds, 4, async id => {
    try {
      const advisory = await osvJSON(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {}, options);
      if (advisory.id !== id || !Array.isArray(advisory.affected)) throw Object.assign(new Error('Advisory details were invalid.'), { code: 'OSV_INVALID_RESPONSE' });
      details.set(id, advisory);
    } catch (error) {
      if (error.code === 'CANCELLED' || options.signal?.aborted) throw cancellationError();
      diagnostics.push({ code: error.code || 'OSV_DETAIL_FAILED', advisory: id, message: `Advisory details unavailable: ${error.message}` });
    }
  });
  if (ids.length > selectedIds.length) diagnostics.push({ code: 'OSV_ADVISORY_LIMIT', message: `${ids.length - selectedIds.length} advisory details were outside the request budget.` });
  for (const check of checks) for (const id of check.advisoryIds) {
    const advisory = details.get(id);
    const affected = (advisory?.affected || []).filter(entry => entry.package?.ecosystem === check.dependency.ecosystem && samePackage(entry.package?.name, check.dependency.name, check.dependency.ecosystem));
    result.vulnerabilities.push({
      id, dependency: check.dependency, ecosystem: check.dependency.ecosystem,
      package: check.dependency.name, name: check.dependency.name, version: check.dependency.version,
      summary: advisory?.summary || '', affected,
      affectedRanges: affected.flatMap(entry => entry.ranges || []),
      severity: advisory?.severity || [], references: advisory?.references || [],
      databaseSpecific: advisory?.database_specific || {},
      aliases: advisory?.aliases || [], source: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      detailsStatus: advisory ? 'AVAILABLE' : 'UNAVAILABLE', status: 'OBSERVED',
      provenance: { ...check.dependency.provenance, advisory: id, source: 'OSV exact-version query' }
    });
  }
  result.matches = result.vulnerabilities;
  result.checkedCount = checks.filter(check => check.status === 'CHECKED').length;
  result.checked = result.checkedCount;
  result.status = result.checkedCount === 0 ? 'FAILED' : diagnostics.length ? 'PARTIAL' : 'COMPLETE';
  result.available = result.status === 'COMPLETE';
  options.onProgress?.('dependencies', `OSV checked ${result.checkedCount} of ${selected.length} exact package versions.`, { done: result.checkedCount, total: selected.length });
  return result;
}
