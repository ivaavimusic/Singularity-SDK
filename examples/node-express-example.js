const express = require('express')
const { createX402ReceiptMiddleware } = require('../packages/node')

const app = express()

app.get('/premium', createX402ReceiptMiddleware({
  requiredSourceSlug: 'your-endpoint-slug'
}), (req, res) => {
  res.json({ ok: true, receipt: req.x402Receipt })
})

app.listen(3000, () => {
  console.log('Listening on :3000')
})
