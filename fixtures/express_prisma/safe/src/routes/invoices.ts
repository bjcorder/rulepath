import { Router } from "express"
import { updateInvoice } from "../services/invoices"

const router = Router()

function requireAuth(req: any, res: any, next: any) {
  next()
}

function requirePermission(permission: string) {
  return function permissionMiddleware(req: any, res: any, next: any) {
    next()
  }
}

router.patch(
  "/clients/:clientId/invoices/:invoiceId",
  requireAuth,
  requirePermission("invoice:update"),
  async (req, res) => {
    const { memo } = req.body
    await updateInvoice({
      invoiceId: req.params.invoiceId,
      clientId: req.user.clientId,
      data: { memo },
    })
    res.sendStatus(204)
  },
)

export default router
