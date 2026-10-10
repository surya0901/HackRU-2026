import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeSources, derivePaths, redactSecrets, stableFingerprint, ENGINE_VERSION } from '../src/engine.js';
import { compareScans } from '../src/verification.js';

const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);
async function fixtures(kind = 'vulnerable') {
  return Promise.all(['support-agent.js', 'customer-agent.ts', 'customer-tools.ts', 'mcp.json'].map(async path => ({ path: `src/${path}`, content: await readFile(new URL(`./fixtures/${path === 'customer-tools.ts' ? 'vulnerable' : kind}/${path}`, import.meta.url), 'utf8') })));
}
function analyze(sources, commit = COMMIT_A) {
  return { repo: 'example/project', commit, ...analyzeSources({ repository: 'example/project', commit, sources }) };
}

test('the generic source engine establishes real agent, tool, operation and credential evidence', async () => {
  const result = analyze(await fixtures());
  const capabilities = result.findings.filter(item => item.rule === 'agent-sensitive-capability');
  assert.equal(capabilities.length, 2);
  assert.ok(capabilities.some(item => item.relatedAgent === 'SupportAgent' && item.relatedTool === 'issueRefund'));
  assert.ok(capabilities.some(item => item.relatedAgent === 'CustomerAgent' && item.relatedTool === 'customerDelete'));
  assert.ok(result.graph.nodes.some(node => node.type === 'CredentialReference'));
  assert.ok(result.graph.nodes.some(node => node.type === 'MCPServer'));
  assert.ok(result.graph.edges.some(edge => edge.relation === 'CAN_CALL'));
  assert.ok(result.graph.edges.some(edge => edge.relation === 'RECEIVES_INPUT_FROM' || edge.relation === 'CAN_TRIGGER'));
  for (const edge of result.graph.edges) {
    assert.equal(edge.status, 'OBSERVED');
    assert.ok(edge.evidence.length > 0);
    for (const evidence of edge.evidence) {
      assert.equal(evidence.commit, COMMIT_A);
      assert.equal(evidence.repository, 'example/project');
      assert.ok(evidence.file && evidence.line > 0 && typeof evidence.snippet === 'string');
    }
  }
  for (const finding of capabilities) {
    assert.ok(finding.whatCanHappen && finding.whyItMatters && finding.proven && finding.notProven && finding.fix);
    assert.equal(finding.exploitStatus, 'UNVERIFIED');
    assert.equal(finding.patch.status, 'PROPOSED_CHANGE');
    assert.equal(finding.patch.baseCommit, COMMIT_A);
    assert.equal(finding.patch.automaticallyApplied, false);
    assert.match(finding.patch.diff, new RegExp(`--- a/${finding.evidence.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  }
});

test('paths traverse only evidenced graph relationships and retain untested exploit prerequisites', async () => {
  const result = analyze(await fixtures());
  assert.equal(result.paths.length, 4);
  const edges = new Map(result.graph.edges.map(edge => [edge.id, edge]));
  assert.ok(result.paths.some(path => path.prerequisites.externalInput));
  for (const path of result.paths) {
    assert.equal(path.status, 'DERIVED');
    assert.equal(path.staticStatus, 'REACHABLE');
    assert.equal(path.exploitStatus, 'UNVERIFIED');
    assert.equal(path.prerequisites.successfulManipulation, false);
    assert.ok(path.provenance.length > 0);
    assert.equal(path.edgeIds.length, path.nodeIds.length - 1);
    path.edgeIds.forEach((id, index) => {
      assert.equal(edges.get(id).from, path.nodeIds[index]);
      assert.equal(edges.get(id).to, path.nodeIds[index + 1]);
    });
  }
});

test('the corrected source is independently scanned and removes original static paths', async () => {
  const before = analyze(await fixtures('vulnerable'));
  const after = analyze(await fixtures('fixed'), COMMIT_B);
  assert.equal(after.findings.filter(item => item.rule === 'agent-sensitive-capability').length, 0);
  assert.equal(after.paths.length, 0);
  const comparison = compareScans(before, after);
  assert.equal(comparison.noLongerDetected.filter(item => item.rule === 'agent-sensitive-capability').length, 2);
  assert.equal(comparison.paths.counts.noLongerDetected, 4);
  assert.ok(comparison.unchanged.some(item => item.rule === 'sensitive-source-operation'));
  assert.equal(after.engineVersion, ENGINE_VERSION);
});

test('a proposed patch applies to the actual source and the engine independently recomputes its removal', async () => {
  const sources = await fixtures();
  const before = analyze(sources);
  const finding = before.findings.find(item => item.rule === 'agent-sensitive-capability' && item.relatedAgent === 'SupportAgent');
  assert.ok(finding?.patch?.diff);
  const directory = await mkdtemp(join(tmpdir(), 'heimdall-patch-test-'));
  try {
    await mkdir(join(directory, 'src'));
    await writeFile(join(directory, finding.patch.file), sources.find(source => source.path === finding.patch.file).content);
    const checked = spawnSync('git', ['apply', '--check', '-'], { cwd: directory, input: finding.patch.diff, encoding: 'utf8', timeout: 10000 });
    assert.equal(checked.status, 0, checked.stderr);
    const applied = spawnSync('git', ['apply', '-'], { cwd: directory, input: finding.patch.diff, encoding: 'utf8', timeout: 10000 });
    assert.equal(applied.status, 0, applied.stderr);
    const changedContent = await readFile(join(directory, finding.patch.file), 'utf8');
    const after = analyze(sources.map(source => source.path === finding.patch.file ? { ...source, content: changedContent } : source), COMMIT_B);
    assert.equal(after.findings.some(item => item.fingerprint === finding.fingerprint), false);
    const comparison = compareScans(before, after);
    assert.ok(comparison.noLongerDetected.some(item => item.fingerprint === finding.fingerprint));
    assert.ok(comparison.paths.noLongerReachable.some(path => path.nodes.some(node => node.label === 'SupportAgent')));
    assert.ok(after.findings.some(item => item.relatedAgent === 'CustomerAgent'));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('exact patch generation preserves terminal newline and trailing-comma variants', async () => {
  const base = 'import {Agent,tool} from "@openai/agents";\nimport Stripe from "stripe";\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\nconst issueRefund = tool({name:"issueRefund",execute:()=>stripe.refunds.create({amount:5})});\nconst agent = new Agent({name:"SupportAgent",tools:[issueRefund]});';
  for (const ending of ['', '\n']) {
    for (const trailingComma of [false, true]) {
      const content = (trailingComma ? base.replace('tools:[issueRefund]', 'tools:[issueRefund,]') : base) + ending;
      const before = analyze([{ path: 'src/agent.js', content }]);
      const finding = before.findings.find(item => item.rule === 'agent-sensitive-capability');
      assert.ok(finding?.patch?.diff);
      const directory = await mkdtemp(join(tmpdir(), 'heimdall-patch-format-'));
      try {
        await mkdir(join(directory, 'src'));
        await writeFile(join(directory, 'src/agent.js'), content);
        const applied = spawnSync('git', ['apply', '-'], { cwd: directory, input: finding.patch.diff, encoding: 'utf8', timeout: 10000 });
        assert.equal(applied.status, 0, applied.stderr);
        const changed = await readFile(join(directory, 'src/agent.js'), 'utf8');
        assert.equal(changed.endsWith('\n'), ending === '\n');
        const after = analyze([{ path: 'src/agent.js', content: changed }], COMMIT_B);
        assert.equal(after.diagnostics.some(item => item.code === 'PARSE_ERROR'), false);
        assert.equal(after.findings.some(item => item.fingerprint === finding.fingerprint), false);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  }
});

test('finding and path identity survives moving lines and source enumeration order', async () => {
  const sources = await fixtures();
  const before = analyze(sources);
  const after = analyze(sources.slice().reverse().map(source => ({ ...source, content: '// line moved\n\n' + source.content })), COMMIT_B);
  assert.deepEqual(after.findings.map(item => item.fingerprint).sort(), before.findings.map(item => item.fingerprint).sort());
  assert.deepEqual(after.paths.map(item => item.fingerprint).sort(), before.paths.map(item => item.fingerprint).sort());
  assert.equal(compareScans(before, after).counts.noLongerDetected, 0);
  assert.equal(stableFingerprint(['same', 'semantic', 'identity']), stableFingerprint(['same', 'semantic', 'identity']));
  assert.notEqual(stableFingerprint(['file', 'agentA']), stableFingerprint(['file', 'agentB']));
});

test('credential findings and every exported evidence snippet redact complete values', () => {
  const key = 'sk-proj-' + 'aBcDeF0987654321'.repeat(4);
  const entropySecret = 'AbC123!xYz987#UvW456$pQr890';
  const content = `export const OPENAI_API_KEY = '${key}'; const SERVICE_TOKEN = '${entropySecret}';`;
  const result = analyze([{ path: 'src/secrets.js', content }]);
  assert.ok(result.findings.some(item => item.rule === 'secret-literal'));
  assert.ok(result.findings.filter(item => item.rule === 'secret-literal').every(item => item.secretStatus === 'LIKELY_SECRET'));
  assert.equal(JSON.stringify(result).includes(key), false);
  assert.equal(JSON.stringify(result).includes(entropySecret), false);
  const redacted = redactSecrets(content);
  assert.equal(redacted.includes(key), false);
  assert.equal(redacted.includes(entropySecret), false);
  assert.match(redacted, /\[REDACTED\]/);
});

test('malformed source files do not erase unrelated source findings', () => {
  const result = analyze([{ path: 'src/broken.ts', content: 'export const broken =' }, { path: 'src/good.js', content: 'export const result = eval(input);' }, { path: 'mcp.json', content: '{ no json' }]);
  assert.ok(result.diagnostics.some(item => item.file === 'src/broken.ts' && item.code === 'PARSE_ERROR'));
  assert.ok(result.diagnostics.some(item => item.file === 'mcp.json' && item.code === 'PARSE_ERROR'));
  assert.ok(result.analyzedFiles.includes('src/good.js'));
  assert.equal(result.analyzedFiles.includes('src/broken.ts'), false);
  assert.ok(result.findings.some(item => item.evidence === 'src/good.js'));
  for (const input of [null, undefined, {}, { sources: [null, {}, { path: 'x.js' }] }]) {
    assert.equal(analyzeSources(input).findings.length, 0);
  }
});

test('unsupported structural languages receive no fabricated capability paths', () => {
  const result = analyze([{ path: 'src/app.py', content: 'agent = Agent(tools=[delete_customer])\nagent.run(request.body)' }]);
  assert.equal(result.paths.length, 0);
  assert.equal(result.graph.edges.length, 0);
  assert.ok(result.diagnostics.some(item => item.code === 'UNSUPPORTED_LANGUAGE'));
});

test('agent names and dangerous tool labels alone cannot create sensitive capability evidence', () => {
  const result = analyze([{ path: 'src/agent.js', content: 'class Agent {}\nconst agent = new Agent({tools: ["customer.delete"]});\n// eval(userInput)\n' }, { path: 'mcp.json', content: '{"mcpServers":{"customer":{"tools":["customer.delete"]}}}' }]);
  assert.equal(result.paths.length, 0);
  assert.equal(result.findings.some(item => item.rule === 'agent-sensitive-capability'), false);
  assert.equal(result.findings.some(item => item.rule === 'sensitive-source-operation'), false);
});

test('unresolved tool imports cannot fabricate links to missing implementation', () => {
  const result = analyze([{ path: 'src/agent.js', content: 'import {Agent} from "@openai/agents"; import {issueRefund} from "./missing-tools.js"; const agent = new Agent({name:"SupportAgent",tools:[issueRefund]});' }]);
  assert.equal(result.paths.length, 0);
  assert.equal(result.graph.edges.some(edge => edge.relation === 'CAN_CALL'), false);
  assert.ok(result.diagnostics.length > 0);
});

test('switching to a dynamic tool list cannot verify disappearance of the original path', async () => {
  const sources = await fixtures();
  const before = analyze(sources);
  const dynamicSources = sources.map(source => source.path.endsWith('support-agent.js') ? { ...source, content: source.content.replace('tools: [issueRefund]', 'tools: getConfiguredTools()') } : source);
  const after = analyze(dynamicSources, COMMIT_B);
  assert.ok(after.diagnostics.some(item => /UNRESOLVED_/.test(item.code)));
  const comparison = compareScans(before, after);
  assert.equal(comparison.noLongerDetected.some(item => item.relatedAgent === 'SupportAgent'), false);
  assert.ok(comparison.unverified.some(item => item.relatedAgent === 'SupportAgent'));
  assert.equal(comparison.paths.counts.noLongerDetected, 0);
  assert.ok(comparison.paths.counts.unverified > 0);
});

test('traversal excludes unverified, malformed or missing-provenance edges', () => {
  const nodes = [{ id: 'agent', type: 'Agent', label: 'Agent' }, { id: 'tool', type: 'Tool', label: 'Tool' }, { id: 'sink', type: 'SensitiveResource', label: 'Deletion' }];
  const evidence = [{ repository: 'example/project', commit: COMMIT_A, file: 'src/agent.js', line: 1, rule: 'test-rule', snippet: 'agent.tools = [tool]' }];
  const edgeA = { id: 'a', from: 'agent', to: 'tool', relation: 'CAN_CALL', status: 'OBSERVED', evidence };
  const edgeB = { id: 'b', from: 'tool', to: 'sink', relation: 'WRITES', status: 'OBSERVED', evidence };
  assert.equal(derivePaths({ nodes, edges: [edgeA, edgeB] }, { repository: 'example/project' }).length, 1);
  for (const incomplete of [{ ...edgeB, status: 'UNVERIFIED' }, { ...edgeB, evidence: [] }, { ...edgeB, evidence: [{ file: 'src/agent.js', line: 0 }] }, { ...edgeB, to: 'missing-node' }]) {
    assert.equal(derivePaths({ nodes, edges: [edgeA, incomplete] }, { repository: 'example/project' }).length, 0);
  }
  assert.equal(derivePaths({ nodes: [null], edges: [null] }).length, 0);
});
