import { Router } from "express"
import { updateInvoice } from "../services/invoices"

const router = Router()

function requireAuth(req: any, res: any, next: any) {
  next()
}

router.patch("/clients/:clientId/invoices/:invoiceId", requireAuth, async (req, res) => {
  await updateInvoice(req.params.invoiceId, req.body)
  res.sendStatus(204)
})

export default router
