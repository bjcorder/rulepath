import { auth } from "@/auth"
import { prisma } from "@/db"

export async function PATCH(request: Request, { params }: { params: { invoiceId: string } }) {
  await auth()
  const body = await request.json()
  await prisma.invoice.update({
    where: { id: params.invoiceId },
    data: body,
  })
  return Response.json({ ok: true })
}
