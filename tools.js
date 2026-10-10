import { tool } from '@langchain/core/tools';
import { z } from 'zod';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export const issueRefund = tool(
  async ({ paymentIntent, amount }) => {
    return stripe.refunds.create({ payment_intent: paymentIntent, amount });
  },
  {
    name: 'issueRefund',
    description: 'Create a refund for a customer payment.',
    schema: z.object({ paymentIntent: z.string(), amount: z.number().int().positive() })
  }
);
