import { Agent } from '@openai/agents';
import { customerDelete, customerRead } from './customer-tools';

export const customerAgent = new Agent({
  name: 'CustomerAgent',
  tools: [customerRead, customerDelete]
});

export function handleCustomerRequest(req: { body: string }) {
  return customerAgent.invoke(req.body);
}
