import { PrismaClient } from '@prisma/client';

const database = new PrismaClient();
export async function customerDelete(customerId: string) {
  return database.customer.delete({ where: { id: customerId } });
}

export async function customerRead(customerId: string) {
  return database.customer.findUnique({ where: { id: customerId } });
}
