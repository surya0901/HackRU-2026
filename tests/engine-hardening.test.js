import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSources, derivePaths } from '../src/engine.js';

const repository = 'acme/static-fixture';
const commit = 'a'.repeat(40);
const analyze = (content, path = 'agent.ts') => analyzeSources({ repository, commit, sources: [{ path, content }] });
const sdkHeader = `import { Agent, tool, run } from '@openai/agents';
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const issueRefund = tool({ name: 'issueRefund', execute: async (amount) => stripe.refunds.create({ amount }) });
`;

test('SDK run receives explicit request data and an imported alias preserves the relationship', () => {
  const result = analyze(`${sdkHeader}
const supportAgent = new Agent({ tools: [issueRefund] });
export async function handler(req) { return run(supportAgent, req.body); }
`);
  assert.ok(result.paths.some(path => path.prerequisites.externalInput));
  const alias = analyze(`${sdkHeader.replace('{ Agent, tool, run }', '{ Agent as Assistant, tool, run as executeAgent }')}
const supportAgent = new Assistant({ tools: [issueRefund] });
export async function handler(req) { return executeAgent(supportAgent, req.query); }
`);
  assert.ok(alias.paths.some(path => path.prerequisites.externalInput));
  assert.ok(alias.graph.edges.every(edge => edge.evidence.every(proof => proof.repository === repository && proof.commit === commit)));
});

test('type-only imports and unrelated constructors never fabricate an agent', () => {
  for (const declaration of [
    "import type { Agent } from '@openai/agents';",
    "import { type Agent } from '@openai/agents';",
    "import { Agent } from './custom-runtime';",
  ]) {
    const result = analyze(`${declaration}
import { tool } from '@openai/agents';
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const issueRefund = tool({ name: 'issueRefund', execute: async () => stripe.refunds.create({}) });
const supportAgent = new Agent({ tools: [issueRefund] });
`);
    assert.equal(result.graph.nodes.filter(node => node.type === 'Agent').length, 0);
    assert.equal(result.paths.length, 0);
  }
});

test('later unknown spreads cannot preserve a tool property they may overwrite', () => {
  const overwritten = analyze(`${sdkHeader}
const supportAgent = new Agent({ tools: [issueRefund], ...runtimeConfig });
`);
  assert.equal(overwritten.graph.edges.filter(edge => edge.relation === 'CAN_CALL').length, 0);
  assert.equal(overwritten.paths.length, 0);
  const explicitAfterSpread = analyze(`${sdkHeader}
const supportAgent = new Agent({ ...runtimeConfig, tools: [issueRefund] });
`);
  assert.equal(explicitAfterSpread.graph.edges.filter(edge => edge.relation === 'CAN_CALL').length, 1);
  assert.ok(explicitAfterSpread.paths.length > 0);
});

test('function parameters hiding imported processes or service bindings have no sensitive-operation edge', () => {
  const result = analyze(`import { Agent } from '@openai/agents';
import { exec } from 'node:child_process';
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
async function issueRefund(stripe) { return stripe.refunds.create({}); }
function launch(exec) { return exec('arbitrary'); }
const supportAgent = new Agent({ tools: [issueRefund, launch] });
`);
  assert.equal(result.graph.edges.filter(edge => edge.relation === 'CAN_CALL').length, 2);
  assert.equal(result.graph.nodes.filter(node => node.type === 'SensitiveResource').length, 0);
  assert.equal(result.findings.filter(finding => finding.rule === 'sensitive-source-operation').length, 0);
  assert.equal(result.paths.length, 0);
});

test('request text inside callbacks or unknown helper calls is not claimed as direct agent input', () => {
  for (const argument of ['() => req.body', 'sanitize(req.body)']) {
    const result = analyze(`${sdkHeader}
const supportAgent = new Agent({ tools: [issueRefund] });
export async function handler(req) { return run(supportAgent, ${argument}); }
`);
    assert.equal(result.graph.nodes.filter(node => node.type === 'InputSource').length, 0);
    assert.ok(result.paths.every(path => !path.prerequisites.externalInput));
  }
});

test('MCP evidence points to each actual nested server property even when keys are repeated', () => {
  for (const nested of [false, true]) {
    const servers = {
      alpha: { command: 'node-alpha', env: { SERVICE_TOKEN: '$TOKEN_ALPHA' }, tools: ['read-record'] },
      beta: { command: 'node-beta', env: { SERVICE_TOKEN: '$TOKEN_BETA' }, tools: ['delete-record'] },
    };
    const content = JSON.stringify(nested ? { mcp: { servers } } : { mcpServers: servers }, null, 2);
    const result = analyze(content, 'mcp.json');
    const lines = content.split('\n');
    for (const [name, command, token] of [['alpha', 'node-alpha', '$TOKEN_ALPHA'], ['beta', 'node-beta', '$TOKEN_BETA']]) {
      const server = result.graph.nodes.find(node => node.type === 'MCPServer' && node.label === name);
      const commandEdge = result.graph.edges.find(edge => edge.from === server.id && edge.evidence.some(proof => proof.rule === 'mcp-command-configuration'));
      const tokenEdge = result.graph.edges.find(edge => edge.from === server.id && edge.evidence.some(proof => proof.rule === 'mcp-credential-configuration'));
      assert.equal(commandEdge.evidence[0].line, lines.findIndex(line => line.includes(command)) + 1);
      assert.equal(tokenEdge.evidence[0].line, lines.findIndex(line => line.includes(token)) + 1);
    }
    // Declarative tool names cannot by themselves establish their side effects.
    assert.equal(result.graph.nodes.filter(node => node.type === 'SensitiveResource').length, 0);
    assert.equal(result.paths.length, 0);
  }
});

test('a PEM interior line is redacted wherever it recurs and cannot appear in a proposed patch', () => {
  const payload = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7';
  const result = analyze(`import { Agent, tool } from '@openai/agents';
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const privateKey = \`-----BEGIN PRIVATE KEY-----
${payload}
-----END PRIVATE KEY-----\`;
const issueRefund = tool({ name: 'issueRefund', execute: async () => stripe.refunds.create({}) }); // ${payload}
const supportAgent = new Agent({ tools: [issueRefund] });
`);
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes(payload));
  assert.ok(serialized.includes('[REDACTED]'));
  assert.equal(result.findings.find(finding => finding.rule === 'agent-sensitive-capability').patch, undefined);
});

test('dependency metadata is sanitized using credential values discovered in source', () => {
  const secret = 'AbCdEfGhIjKlMnOpQrStUvWx0123456789';
  const result = analyzeSources({ repository, commit, sources: [{ path: 'package.json', content: `{"dependencies":{"password":"${secret}"}}` }],
    dependencies: [{ name: 'password', file: 'package.json', declaredVersion: secret, version: null }],
    osv: { status: 'UNAVAILABLE', diagnostics: [{ message: secret }] } });
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal(result.sanitizedDependencies[0].declaredVersion, '[REDACTED]');
  assert.equal(result.sanitizedOSV.diagnostics[0].message, '[REDACTED]');
});

test('a known advisory match does not invent a high severity when its source has no rating', () => {
  const dependency = { name: 'example-package', version: '1.0.0', ecosystem: 'npm', file: 'package-lock.json', line: 3 };
  const result = analyzeSources({ repository, commit, sources: [], dependencies: [dependency], osv: { vulnerabilities: [{ id: 'OSV-EXAMPLE', dependency, severity: [] }] } });
  const finding = result.findings.find(item => item.rule === 'osv-dependency-advisory');
  assert.equal(finding.severitySource, 'UNKNOWN');
  assert.equal(finding.sev, 'medium');
  assert.match(finding.reasoning, /local review priority/);
});

test('path provenance from another repository or commit cannot be used as this scan evidence', () => {
  const result = analyze(`${sdkHeader}
const supportAgent = new Agent({ tools: [issueRefund] });
`);
  assert.ok(result.paths.length > 0);
  assert.equal(derivePaths(result.graph, { repository: 'other/project', commit }).length, 0);
  assert.equal(derivePaths(result.graph, { repository, commit: 'b'.repeat(40) }).length, 0);
});
