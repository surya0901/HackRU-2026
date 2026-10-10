import { redactSecrets } from './engine.js';

export const HISTORY_KEY = 'heimdall-scan-history-v3';
const HISTORY_VERSION = 3;
const MAX_SCANS = 10;
const MAX_SERIALIZED_BYTES = 550_000;
const MAX_ARRAY_ITEMS = 800;
const MAX_STRING_LENGTH = 4000;
const unsafeKeys = new Set(['sources', 'source', 'content', 'raw', 'rawSource', 'rawSources', 'token', 'accessToken', 'apiKey', 'password', 'secret', 'previous', 'before', 'scanA', 'scanB', '__proto__', 'prototype', 'constructor']);
const scanKeys = ['id', 'repo', 'repository', 'fullName', 'url', 'meta', 'files', 'sourceStats', 'scope', 'commit', 'commitSHA', 'commitSha', 'branch', 'engineVersion', 'scannedAt', 'createdAt', 'timestamp', 'summary', 'findings', 'graph', 'paths', 'pathAnalysisComplete', 'dependencies', 'diagnostics', 'analyzedFiles', 'secretAnalyzedFiles', 'dependencyAnalyzedFiles', 'coverage', 'osv', 'partial'];

function storageOrDefault(storage) {
  if (storage) return storage;
  try { return globalThis.localStorage; } catch { return null; }
}

function sanitize(value, depth = 0) {
  if (depth > 12 || value === undefined || typeof value === 'function') return undefined;
  if (typeof value === 'string') return redactSecrets(value).slice(0, MAX_STRING_LENGTH);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.slice(0, MAX_ARRAY_ITEMS).map(item => sanitize(item, depth + 1)).filter(item => item !== undefined);
  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      if ((unsafeKeys.has(key) && !(key === 'source' && typeof item === 'string' && /^https:\/\//.test(item))) || /^(raw|full)(source|content|secret|token)$/i.test(key)) continue;
      const safe = sanitize(item, depth + 1);
      if (safe !== undefined) output[key] = safe;
    }
    return output;
  }
  return undefined;
}

function commitOf(scan) { return scan?.commitSHA || scan?.commitSha || scan?.commit; }

function repositoryOf(scan) {
  if (typeof scan?.repo === 'string') return scan.repo;
  if (typeof scan?.fullName === 'string') return scan.fullName;
  if (typeof scan?.repository === 'string') return scan.repository.replace(/^https:\/\/github\.com\//, '').replace(/\/$/, '');
  if (scan?.repository?.owner && scan?.repository?.repo) return `${scan.repository.owner}/${scan.repository.repo}`;
  return '';
}

function validEvidence(entry, commit) {
  return entry && typeof entry === 'object' && typeof entry.file === 'string' && entry.file.length > 0 && Number.isInteger(entry.line) && entry.line > 0 && (entry.commit || entry.commitSHA) === commit;
}

function validRecord(record, commit) {
  return record && typeof record === 'object' && typeof record.fingerprint === 'string' && record.fingerprint.length > 0 && Array.isArray(record.provenance) && record.provenance.length > 0 && record.provenance.every(entry => validEvidence(entry, commit));
}

function validScan(scan) {
  if (!scan || typeof scan !== 'object' || Array.isArray(scan)) return false;
  const commit = commitOf(scan);
  if (typeof commit !== 'string' || !/^[a-f\d]{7,64}$/i.test(commit)) return false;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repositoryOf(scan))) return false;
  if (typeof scan.engineVersion !== 'string' || !scan.engineVersion) return false;
  if (!Array.isArray(scan.findings) || !Array.isArray(scan.paths || scan.graph?.paths)) return false;
  if (!scan.findings.every(item => validRecord(item, commit))) return false;
  if (!(scan.paths || scan.graph?.paths).every(item => validRecord(item, commit))) return false;
  const analyzed = scan.analyzedFiles || scan.coverage?.analyzedFiles;
  return Array.isArray(analyzed) && analyzed.every(file => typeof file === 'string' && file.length > 0);
}

function safeScan(scan) {
  if (!validScan(scan)) return null;
  const output = {};
  for (const key of scanKeys) if (scan[key] !== undefined) output[key] = sanitize(scan[key]);
  // Rebuild the parsed repository consumed by the console from its validated
  // identity; a persisted URL or legacy string must not control source links.
  const [owner, repo] = repositoryOf(scan).split('/');
  output.repo = { owner, repo, url: `https://github.com/${owner}/${repo}` };
  output.repository = output.repo;
  output.fullName = `${owner}/${repo}`;
  output.meta = { ...(output.meta || {}), full_name: `${owner}/${repo}` };
  // Bounded persistence must not masquerade as a complete scan if a collection was cut.
  const cutCollections = [scan.findings, scan.paths, scan.analyzedFiles, scan.secretAnalyzedFiles, scan.dependencyAnalyzedFiles, scan.coverage?.analyzedFiles, scan.coverage?.secretAnalyzedFiles, scan.coverage?.dependencyAnalyzedFiles, scan.coverage?.treeFiles, scan.graph?.nodes, scan.graph?.edges].some(value => Array.isArray(value) && value.length > MAX_ARRAY_ITEMS);
  if (cutCollections) {
    output.partial = true;
    output.coverage = { ...(output.coverage || {}), complete: false, treeTruncated: true };
    output.diagnostics = [...(output.diagnostics || []), { code: 'HISTORY_TRUNCATED', message: 'Some scan data could not fit in local history. Rescan to verify changes.' }];
  }
  return output;
}

export function loadHistory(storage) {
  const target = storageOrDefault(storage);
  const warnings = [];
  if (!target || typeof target.getItem !== 'function') return { scans: [], warnings: ['Local scan history is unavailable in this browser.'] };
  try {
    const serialized = target.getItem(HISTORY_KEY);
    if (!serialized) {
      if (target.getItem('heimdall-scan-history-v2') || target.getItem('heimdall-scan-history')) warnings.push('Older scan history was excluded because it lacks the current evidence schema.');
      return { scans: [], warnings };
    }
    if (serialized.length > MAX_SERIALIZED_BYTES) return { scans: [], warnings: ['Local scan history exceeded its storage limit and was excluded.'] };
    const parsed = JSON.parse(serialized);
    if (!parsed || parsed.version !== HISTORY_VERSION || !Array.isArray(parsed.scans)) return { scans: [], warnings: ['Local scan history has an unsupported schema and was excluded.'] };
    const scans = parsed.scans.slice(0, MAX_SCANS).map(safeScan).filter(Boolean);
    if (scans.length !== parsed.scans.length) warnings.push('Invalid or excess scan history records were excluded. Run a new scan before comparing changes.');
    return { scans, warnings };
  } catch {
    return { scans: [], warnings: ['Local scan history could not be read. Scanning can continue.'] };
  }
}

export function saveScan(scan, storage) {
  const target = storageOrDefault(storage);
  const history = loadHistory(target);
  const safe = safeScan(scan);
  if (!safe) return { ...history, warnings: [...history.warnings, 'This scan lacks valid commit-pinned evidence and was not saved.'] };
  const scans = [safe, ...history.scans.filter(item => !(repositoryOf(item).toLowerCase() === repositoryOf(safe).toLowerCase() && commitOf(item) === commitOf(safe) && item.engineVersion === safe.engineVersion))].slice(0, MAX_SCANS);
  let serialized = JSON.stringify({ version: HISTORY_VERSION, scans });
  while (serialized.length > MAX_SERIALIZED_BYTES && scans.length > 1) {
    scans.pop();
    serialized = JSON.stringify({ version: HISTORY_VERSION, scans });
  }
  if (serialized.length > MAX_SERIALIZED_BYTES) return { scans: history.scans, warnings: [...history.warnings, 'This scan is too large for local history. Keep its exported report or rescan to compare changes.'] };
  if (!target || typeof target.setItem !== 'function') return { scans, warnings: [...history.warnings, 'Local scan history is unavailable; this scan was not persisted.'] };
  try {
    target.setItem(HISTORY_KEY, serialized);
    return { scans, warnings: history.warnings };
  } catch {
    return { scans, warnings: [...history.warnings, 'Browser storage is full or inaccessible; this scan was not persisted.'] };
  }
}
