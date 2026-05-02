import { prisma } from "../db"

type UpdateInvoiceInput = {
  invoiceId: string
  clientId: string
  data: { memo: string }
}

export async function updateInvoice(input: UpdateInvoiceInput) {
  return prisma.invoice.update({
    where: {
      id_clientId: {
        id: input.invoiceId,
        clientId: input.clientId,
      },
    },
    data: input.data,
  })
}
