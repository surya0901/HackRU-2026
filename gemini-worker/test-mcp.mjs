import { handleMcp } from './mcp.js';

const env = {};
const call = body => handleMcp(new Request('https://heimdall.test/mcp', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
}), env);

const initialized = await (await call({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })).json();
if (initialized.result?.serverInfo?.name !== 'heimdall-security') throw new Error('initialize failed');

const listed = await (await call({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })).json();
if (listed.result?.tools?.length !== 2) throw new Error('tools/list failed');
if (!listed.result.tools.some(tool => tool.name === 'scan_repository')) throw new Error('scan_repository missing');
if (!listed.result.tools.some(tool => tool.name === 'check_reference')) throw new Error('check_reference missing');

console.log('MCP protocol smoke test passed');
