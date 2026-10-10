import { redactSecrets } from './engine.js';

const reportKeys = ['repo', 'fullName', 'branch', 'commit', 'commitSHA', 'engineVersion', 'createdAt', 'scope', 'partial', 'coverage', 'sourceStats', 'analyzedFiles', 'secretAnalyzedFiles', 'dependencyAnalyzedFiles', 'dependencies', 'osv', 'findings', 'graph', 'paths', 'pathAnalysisComplete', 'diagnostics', 'diff'];
const rawKeys = new Set(['sources', 'source', 'content', 'raw', 'rawSource', 'rawSources', 'previous', 'scanA', 'scanB', 'token', 'apiKey', 'password', 'secret', '__proto__', 'constructor', 'prototype']);
const list = value => Array.isArray(value) ? value : [];

function sanitize(value, ancestors = new Set(), depth = 0) {
  if (depth > 20 || value === undefined || typeof value === 'function') return undefined;
  if (typeof value === 'string') return redactSecrets(value).slice(0, 100000);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (!value || typeof value !== 'object' || ancestors.has(value)) return undefined;
  ancestors.add(value);
  let output;
  if (Array.isArray(value)) output = value.slice(0, 10000).map(item => sanitize(item, ancestors, depth + 1)).filter(item => item !== undefined);
  else {
    output = {};
    for (const [key, item] of Object.entries(value)) {
      if (rawKeys.has(key) && !(key === 'source' && typeof item === 'string' && /^https:\/\//.test(item))) continue;
      // Redaction would alter an exact proposed patch. Exclude that proposal
      // instead of exporting modified patch bytes as the original source diff.
      if (key === 'patch' && (typeof item?.diff !== 'string' || item.diff.length > 100000 || redactSecrets(item.diff) !== item.diff)) continue;
      const safe = sanitize(item, ancestors, depth + 1);
      if (safe !== undefined) output[key] = safe;
    }
  }
  ancestors.delete(value);
  return output;
}

// Serialize structured evidence; raw source and nested earlier scans stay out.
export function evidenceReport(scan = {}) {
  const input = scan && typeof scan === 'object' ? scan : {};
  return sanitize(Object.fromEntries(reportKeys.filter(key => input[key] !== undefined).map(key => [key, input[key]])));
}

function reportDefaults(report) {
  const repository = report.repo;
  const identity = typeof repository === 'string' ? repository.replace(/^https:\/\/github\.com\//, '').replace(/\/$/, '') : (repository?.owner && repository?.repo ? `${repository.owner}/${repository.repo}` : report.fullName);
  const url = typeof identity === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(identity) ? `https://github.com/${identity}` : '';
  return { ...report, repo: { ...(typeof repository === 'object' ? repository : {}), url }, commit: report.commit || report.commitSHA || '', findings: list(report.findings).filter(f => f && typeof f === 'object'), paths: list(report.paths).filter(p => p && typeof p === 'object') };
}

const words = value => Array.isArray(value) ? value.join('; ') : String(value || '');
function verificationMarkdown(scan) {
  const diff = scan.diff;
  if (!diff) return '\n## Verification\n\nNo comparison with changed source is available.\n';
  const lines = ['\n## Verification\n', `Before: ${diff.beforeCommit || 'Unavailable'}`, `After: ${diff.afterCommit || 'Unavailable'}`, diff.reason || ''];
  if (diff.available) {
    for (const finding of list(diff.noLongerDetected)) lines.push(`- ${finding.fingerprint || finding.id}: Original static finding no longer detected.`);
    for (const path of list(diff.paths?.noLongerReachable)) lines.push(`- ${path.fingerprint || path.id}: Original static path no longer reachable.`);
  }
  for (const record of [...list(diff.unverified), ...list(diff.paths?.unverified)]) lines.push(`- ${record.fingerprint || record.id}: UNVERIFIED — ${record.verificationReason || 'Insufficient comparable evidence.'}`);
  lines.push('This compares supported static evidence. Runtime exploitability and complete application security remain unverified.');
  return lines.join('\n') + '\n';
}
export function markdownReport(scan) {
  scan = reportDefaults(evidenceReport(scan));
  const body = `# Heimdall static security evidence\n\nRepository: ${scan.repo.url}\nRef: ${scan.branch}\nCommit: ${scan.commit}\nEngine: ${scan.engineVersion}\nScope: ${scan.scope}\n\nNo repository code was executed. Exploitability and credential validity remain unverified.\n\n## Findings\n\n${scan.findings.map(f => `### ${f.title}\n\n- ID: ${f.fingerprint || f.id}\n- Evidence type: ${f.evidenceType}\n- What can happen: ${words(f.whatCanHappen || f.detail)}\n- Why it matters: ${words(f.whyItMatters || f.detail)}\n- Actually found: ${words(f.proven)}\n- Not proved: ${words(f.notProven)}\n- Proposed change: ${f.fix}\n\n${(f.provenance || []).map(p => `- ${p.file}:${p.line} @ ${p.commit || scan.commit} (${p.rule || f.rule})\n\n    ${p.snippet || ''}`).join('\n')}\n${f.patch?.diff ? `\nProposed patch (not applied):\n\n\`\`\`diff\n${f.patch.diff}\n\`\`\`\n` : ''}`).join('\n\n')}\n\n## Capability paths\n\n${scan.paths.map(p => `- ${p.fingerprint || p.id}: static path ${p.staticStatus || 'UNVERIFIED'}; exploit UNVERIFIED`).join('\n')}\n\n## Coverage and diagnostics\n\n\`\`\`json\n${JSON.stringify({ coverage: scan.coverage, diagnostics: scan.diagnostics }, null, 2)}\n\`\`\`\n`;
  return body + verificationMarkdown(scan);
}

export function sarifReport(scan) {
  scan = reportDefaults(evidenceReport(scan));
  const rules = [...new Map(scan.findings.map(f => [f.rule, f])).values()];
  return {
    version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'Heimdall', version: scan.engineVersion, informationUri: 'https://github.com/surya0901/HackRU-2026', rules: rules.map(f => ({ id: f.rule, shortDescription: { text: f.title }, help: { text: f.fix } })) } },
      versionControlProvenance: scan.repo.url && scan.commit ? [{ repositoryUri: scan.repo.url, revisionId: scan.commit }] : [],
      results: scan.findings.map(f => ({
        ruleId: f.rule, level: ['critical','high'].includes(f.sev) ? 'error' : f.sev === 'medium' ? 'warning' : 'note',
        message: { text: `${words(f.proven)} ${words(f.notProven)} Proposed change: ${f.fix}` },
        partialFingerprints: { 'heimdall/v1': f.fingerprint || f.id },
        properties: { evidenceType: f.evidenceType, exploit: 'UNVERIFIED' },
        locations: list(f.provenance).filter(p => typeof p.file === 'string' && Number.isInteger(p.line) && p.line > 0).map(p => ({ physicalLocation: { artifactLocation: { uri: p.file.split('/').map(encodeURIComponent).join('/') }, region: { startLine: p.line, snippet: { text: p.snippet || '' } } } }))
      }))
    }]
  };
}
