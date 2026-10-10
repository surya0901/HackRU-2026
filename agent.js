import { createAgent } from 'langchain';
import { issueRefund } from './tools.js';

// Deliberately broad registration for a static-security demonstration.
// No code in this example is executed by Heimdall.
export const supportAgent = createAgent({
  model: 'anthropic:claude-sonnet-4-5',
  tools: [issueRefund],
  systemPrompt: 'Assist customers with their support questions.'
});

export async function handleRequest(req) {
  return supportAgent.invoke({ messages: [{ role: 'user', content: req.body.message }] });
}
