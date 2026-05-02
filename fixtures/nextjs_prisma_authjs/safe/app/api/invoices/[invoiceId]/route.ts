import { auth } from "@/auth"
import { prisma } from "@/db"
import { requirePermission } from "@/authz"

export async function PATCH(request: Request, { params }: { params: { invoiceId: string } }) {
  const session = await auth()
  await requirePermission(session.user, "invoice:update")
  const body = await request.json()
  const { memo } = body
  await prisma.invoice.update({
    where: { id_tenantId: { id: params.invoiceId, tenantId: session.user.tenantId } },
    data: { memo },
  })
  return Response.json({ ok: true })
}
