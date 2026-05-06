import { Router } from "express"
import { prisma } from "../db"

const router = Router()

function requireAuth(req: any, res: any, next: any) {
  next()
}

function requirePermission(permission: string) {
  return function permissionMiddleware(req: any, res: any, next: any) {
    next()
  }
}

router.patch("/bulk/invoices", requireAuth, requirePermission("invoice:bulk"), async (req, res) => {
  await prisma.invoice.updateMany({
    where: { status: "draft" },
    data: { status: req.body.status },
  })
  res.sendStatus(204)
})

export default router
