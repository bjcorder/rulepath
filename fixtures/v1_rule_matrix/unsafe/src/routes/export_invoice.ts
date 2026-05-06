import { Router } from "express"

const router = Router()

function requireAuth(req: any, res: any, next: any) {
  next()
}

router.get("/reports/invoices/export", requireAuth, async (req, res) => {
  return res.type("text/csv").send("Invoice id,total")
})

export default router
