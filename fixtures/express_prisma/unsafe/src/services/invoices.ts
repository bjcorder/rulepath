import { prisma } from "../db"

export async function updateInvoice(invoiceId: string, body: any) {
  return prisma.invoice.update({
    where: { id: invoiceId },
    data: body,
  })
}
