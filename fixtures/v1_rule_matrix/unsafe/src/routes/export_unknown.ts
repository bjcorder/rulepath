import { Router } from "express"

const router = Router()

router.get("/download/export", async (req, res) => {
  return res.type("text/csv").send("id,value")
})

export default router
