import { Agent } from '@openai/agents';
import { customerRead } from './customer-tools';

export const customerAgent = new Agent({
  name: 'CustomerAgent',
  tools: [customerRead]
});

export function handleCustomerRequest(req: { body: string }) {
  return customerAgent.invoke(req.body);
}
