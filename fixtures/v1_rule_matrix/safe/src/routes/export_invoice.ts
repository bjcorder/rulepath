import { Router } from "express"

const router = Router()

function requireAuth(req: any, res: any, next: any) {
  next()
}

function requirePermission(permission: string) {
  return function permissionMiddleware(req: any, res: any, next: any) {
    next()
  }
}

router.get("/reports/invoices/export", requireAuth, requirePermission("invoice:export"), async (req, res) => {
  const tenantId = req.user.tenantId
  return res.type("text/csv").send(`Invoice id,total,tenant\n1,0,${tenantId}`)
})

export default router
