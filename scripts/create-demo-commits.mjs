// Creates actual source commits without switching or modifying the working tree.
// Never invokes the example application, model, or Stripe API. Does not push.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const git = (args, input) => execFileSync('git', args, { input, encoding: 'utf8' }).trim();
const agent = readFileSync('examples/scan-demo/agent.js', 'utf8');
const tools = readFileSync('examples/scan-demo/tools.js', 'utf8');
const readme = '# Real static capability demonstration\n\nThe source deliberately registers a financial tool on a customer-support agent. Heimdall never executes this code, validates credentials, issues refunds, or claims an exploit. The corrected commit only removes the tool registration; it does not certify the application. No credentials are committed.\n\nScan demo-vulnerable, inspect the actual source and proposed diff, then rescan demo-fixed. Both refs use the same generic engine as any other repository.\n';
function tree(source) {
  const files = { 'agent.js': source, 'tools.js': tools, 'README.md': readme };
  const rows = Object.entries(files).sort(([a],[b]) => a.localeCompare(b)).map(([name, content]) => `100644 blob ${git(['hash-object','-w','--stdin'],content)}\t${name}`).join('\n') + '\n';
  return git(['mktree'], rows);
}
const vulnerable = git(['commit-tree', tree(agent), '-m', 'Demo: register financial tool on support agent']);
const fixed = git(['commit-tree', tree(agent.replace('tools: [issueRefund]', 'tools: []')), '-p', vulnerable, '-m', 'Demo: remove financial tool from support agent']);
console.log(JSON.stringify({ vulnerable, fixed }, null, 2));
