/** Compare two real scans without turning missing coverage into a successful fix. */
const text = value => typeof value === 'string' ? value.trim() : '';
const normalizeFile = value => text(value).replace(/\\/g, '/').replace(/^\.\//, '');
const commitOf = scan => text(scan?.commitSHA || scan?.commitSha || scan?.commit);
const repositoryOf = scan => {
  const candidate = scan?.repo || scan?.fullName || scan?.repository;
  if (typeof candidate === 'string') return candidate.replace(/^https:\/\/github\.com\//i, '').replace(/\/$/, '').toLowerCase();
  if (candidate && typeof candidate === 'object') return text(candidate.fullName || (candidate.owner && candidate.repo ? `${candidate.owner}/${candidate.repo}` : '')).toLowerCase();
  return '';
};
const list = value => Array.isArray(value) ? value : [];
const fingerprintOf = item => text(item?.fingerprint);
const collection = (scan, kind) => kind === 'paths' ? list(scan?.paths || scan?.graph?.paths) : list(scan?.findings);

function evidenceFor(item) {
  const evidence = [];
  const add = value => {
    if (Array.isArray(value)) value.forEach(add);
    else if (value && typeof value === 'object') evidence.push(value);
  };
  add(item?.provenance);
  add(item?.evidence);
  for (const edge of list(item?.edges)) {
    add(edge.provenance);
    add(edge.evidence);
  }
  return evidence;
}

function analyzedFiles(scan, item) {
  const rule = text(item?.rule || item?.ruleId || item?.detector);
  let files = scan?.analyzedFiles || scan?.coverage?.analyzedFiles;
  if (/secret|credential.literal/i.test(rule)) files = scan?.secretAnalyzedFiles || scan?.coverage?.secretAnalyzedFiles || files;
  if (isDependencyFinding(item)) files = scan?.dependencyAnalyzedFiles || scan?.coverage?.dependencyAnalyzedFiles || files;
  return new Set(list(files).map(value => normalizeFile(typeof value === 'string' ? value : value?.path || value?.file)).filter(Boolean));
}

function fileFailures(scan) {
  const errors = [...list(scan?.coverage?.failedFiles), ...list(scan?.coverage?.failures)];
  for (const diagnostic of list(scan?.diagnostics)) {
    if (/parse|fail|error|unsupported|timeout|truncat|unresolved|path.limit/i.test(`${diagnostic?.code || ''} ${diagnostic?.status || ''}`)) errors.push(diagnostic);
  }
  return new Set(errors.map(value => normalizeFile(value?.file || value?.path)).filter(Boolean));
}

function comparisonReason(previous, current) {
  if (!previous || typeof previous !== 'object') return 'No earlier scan is available for comparison.';
  if (!current || typeof current !== 'object') return 'The new scan is missing.';
  if (!repositoryOf(previous) || !repositoryOf(current)) return 'Repository identity is missing; the scans cannot be compared.';
  if (repositoryOf(previous) !== repositoryOf(current)) return 'These scans belong to different repositories.';
  if (!text(previous.engineVersion) || !text(current.engineVersion)) return 'Analysis-engine version is missing.';
  if (previous.engineVersion !== current.engineVersion) return 'The analysis engine changed; disappearance cannot verify a source fix.';
  if (!commitOf(previous) || !commitOf(current)) return 'An immutable repository commit is missing.';
  if (commitOf(previous) === commitOf(current)) return 'Both scans analyzed the same commit; no source change has been verified.';
  return '';
}

function isDependencyFinding(item) {
  return Boolean(item?.advisory || item?.advisoryId || item?.vulnerability || item?.vulnerabilityId || item?.dependency || /osv|dependency|vulnerable.package/i.test(text(item?.rule || item?.ruleId || item?.detector)));
}

function absenceReason(item, previous, current, generalReason) {
  if (generalReason) return generalReason;
  const analyzed = analyzedFiles(current, item);
  if (!analyzed.size) return 'The new scan analyzed no supported files; absence is inconclusive.';
  const evidence = evidenceFor(item);
  if (!evidence.length || evidence.some(entry => !normalizeFile(entry.file || entry.path) || !Number.isInteger(entry.line) || entry.line < 1)) return 'The original record lacks complete source provenance.';
  if (evidence.some(entry => text(entry.commit || entry.commitSHA) !== commitOf(previous))) return 'Original evidence is not pinned to the earlier scan commit.';
  const failures = fileFailures(current);
  const treeFiles = new Set(list(current?.coverage?.treeFiles || current?.treeFiles).map(normalizeFile));
  const hasCompleteTree = Array.isArray(current?.coverage?.treeFiles || current?.treeFiles) && current?.coverage?.treeTruncated === false;
  const files = new Set(evidence.map(entry => normalizeFile(entry.file || entry.path)));
  for (const file of files) {
    if (failures.has(file)) return `Analysis of ${file} failed; the original condition remains unverified.`;
    if (!analyzed.has(file) && !(hasCompleteTree && !treeFiles.has(file))) return `${file} was not successfully analyzed in the new scan.`;
  }
  // A skipped or failed file may contain an imported capability needed by the same rule.
  // Do not infer a fix when the analysis universe became smaller or incomplete.
  if (current?.coverage?.treeTruncated === true) return 'The repository tree is truncated; the new scan cannot establish absence.';
  if (list(current?.diagnostics).some(diagnostic => /UNRESOLVED_|PATH_LIMIT|HISTORY_TRUNCATED|PARSE_ERROR/.test(text(diagnostic?.code)))) return 'The new scan has unresolved or incomplete analysis; absence remains unverified.';
  if (current?.coverage?.complete === false || list(current?.coverage?.skipped).length || failures.size) return 'The new scan has incomplete source coverage; absence remains unverified.';
  for (const file of analyzedFiles(previous, item)) {
    if (!analyzed.has(file) && !(hasCompleteTree && !treeFiles.has(file))) return 'Source coverage changed between scans; an earlier analyzed file is now missing.';
  }
  if (isDependencyFinding(item)) {
    const status = text(current?.osv?.status).toUpperCase();
    if (status !== 'COMPLETE' && status !== 'NOT_NEEDED') return 'Dependency advisory checks are unavailable or incomplete; advisory resolution is unverified.';
    if (!Array.isArray(current?.dependencies)) return 'The new scan did not establish its dependency inventory.';
    const original = item.dependency;
    if (!original || !text(original.name) || !text(original.ecosystem) || !text(original.version)) return 'The original advisory lacks an exact dependency identity.';
    const matches = current.dependencies.filter(dependency => dependency?.name === original.name && dependency?.ecosystem === original.ecosystem);
    if (matches.some(dependency => !text(dependency.version) || dependency.exact === false)) return 'The package remains present with an unresolved version; advisory resolution is unverified.';
    if (matches.some(dependency => dependency.version === original.version)) return 'The same package version is still present; a changed advisory feed cannot verify a source fix.';
  }
  return '';
}

function record(item, verification, verificationReason) {
  return { ...(item && typeof item === 'object' ? item : {}), verification, verificationReason };
}

function completePathEvidence(item) {
  if (!Array.isArray(item?.nodeIds) || item.nodeIds.length < 3 || !Array.isArray(item?.edgeIds) || !Array.isArray(item?.edges) || item.edgeIds.length !== item.nodeIds.length - 1 || item.edges.length !== item.edgeIds.length) return false;
  return item.edges.every((edge, index) => edge?.id === item.edgeIds[index] && edge.from === item.nodeIds[index] && edge.to === item.nodeIds[index + 1] && edge.status === 'OBSERVED' && Array.isArray(edge.evidence) && edge.evidence.length > 0 && edge.evidence.every(proof => normalizeFile(proof?.file) && Number.isInteger(proof.line) && proof.line > 0 && text(proof.rule) && typeof proof.snippet === 'string'));
}

function compareCollection(previous, current, kind, reason) {
  const output = { added: [], unchanged: [], noLongerDetected: [], unverified: [] };
  const currentCollection = kind === 'paths' ? current?.paths || current?.graph?.paths : current?.findings;
  const effectiveReason = reason || (!Array.isArray(currentCollection) ? `The new scan has no valid ${kind} collection.` : '');
  const before = new Map();
  const after = new Map();
  for (const item of collection(previous, kind)) {
    const fingerprint = fingerprintOf(item);
    if (!fingerprint) output.unverified.push(record(item, 'UNVERIFIED', 'The original record has no stable fingerprint.'));
    else if (!before.has(fingerprint)) before.set(fingerprint, item);
  }
  for (const item of collection(current, kind)) {
    const fingerprint = fingerprintOf(item);
    if (!fingerprint) output.unverified.push(record(item, 'UNVERIFIED', 'The new record has no stable fingerprint.'));
    else if (!after.has(fingerprint)) after.set(fingerprint, item);
  }
  for (const [fingerprint, item] of after) {
    if (before.has(fingerprint)) output.unchanged.push(record(item, 'UNCHANGED', 'This specific static condition is still detected in the new scan.'));
    else output.added.push(record(item, 'ADDED', 'This static condition is detected in the new scan.'));
  }
  for (const [fingerprint, item] of before) {
    if (after.has(fingerprint)) continue;
    const inconclusive = kind === 'paths' && current?.pathAnalysisComplete === false ? 'The new graph traversal was incomplete; path absence remains unverified.' : kind === 'paths' && !completePathEvidence(item) ? 'The original path lacks complete evidence for each graph relationship.' : absenceReason(item, previous, current, effectiveReason);
    output[inconclusive ? 'unverified' : 'noLongerDetected'].push(record(item, inconclusive ? 'UNVERIFIED' : 'NO_LONGER_DETECTED', inconclusive || (kind === 'paths' ? 'The original static capability path is no longer reachable in the recomputed graph.' : 'The original static finding is no longer detected in the analyzed source.')));
  }
  output.counts = {
    added: output.added.length,
    unchanged: output.unchanged.length,
    noLongerDetected: output.noLongerDetected.length,
    unverified: output.unverified.length,
    fixed: output.noLongerDetected.length
  };
  return output;
}

export function compareScans(previous, current) {
  const reason = comparisonReason(previous, current);
  const findings = compareCollection(previous, current, 'findings', reason);
  const paths = compareCollection(previous, current, 'paths', reason);
  paths.noLongerReachable = paths.noLongerDetected;
  return {
    available: !reason,
    reason,
    beforeCommit: commitOf(previous),
    afterCommit: commitOf(current),
    ...findings,
    paths
  };
}
