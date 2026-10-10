import { Agent, tool } from '@openai/agents';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export const issueRefund = tool({
  name: 'issueRefund',
  description: 'Issue a customer refund.',
  execute: async ({ amount }) => stripe.refunds.create({ amount })
});
export const supportAgent = new Agent({
  name: 'SupportAgent',
  tools: []
});
export async function handleRequest(req) {
  return supportAgent.run(req.body);
}
