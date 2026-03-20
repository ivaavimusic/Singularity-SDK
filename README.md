<p align="center">
  <h1 align="center">Singularity SDK</h1>
  <p align="center">
    Server-side receipt and webhook verification helpers for the x402 payment protocol — Node.js &amp; Python
  </p>
  <p align="center">
    <a href="https://studio.x402layer.cc/docs/developer/sdk-receipts">Documentation</a>
    &nbsp;·&nbsp;
    <a href="https://api.x402layer.cc/.well-known/jwks.json">JWKS Endpoint</a>
    &nbsp;·&nbsp;
    <a href="https://studio.x402layer.cc">x402 Studio</a>
  </p>
</p>

---

## Overview

When a buyer completes an x402 payment, the worker issues a **signed receipt JWT** containing the transaction details. When a seller webhook fires, the worker also signs the raw webhook body with an HMAC secret. This SDK helps you verify both layers safely.

Both the Node and Python implementations handle:

- receipt JWT verification via RS256 + JWKS
- webhook HMAC verification
- optional webhook-to-receipt cross-checking
- optional source-slug binding

---

## Installation

### Node.js

```bash
npm install x402sgl
```

```js
const {
  verifyX402ReceiptToken,
  createX402ReceiptMiddleware,
  verifyX402WebhookSignature,
  verifyX402WebhookEvent,
} = require('x402sgl');
```

### Python

```bash
pip install git+https://github.com/ivaavimusic/Singularity-SDK.git#subdirectory=python
```

```python
from x402layer_middleware import X402ReceiptVerifier, require_x402_receipt
```

**Python dependencies** (installed automatically): `PyJWT`, `cryptography`. FastAPI is optional — install with `pip install x402layer-sdk[fastapi]`.

---

## Node.js

### Receipt API

```js
const {
  verifyX402ReceiptToken,
  createX402ReceiptMiddleware,
  verifyX402WebhookSignature,
  verifyX402WebhookEvent,
} = require('x402sgl');
```

**`verifyX402ReceiptToken(token, options?)`**

Verifies the receipt JWT and returns the decoded claims. Throws on invalid signature, expired token, or claim mismatch.

```js
const claims = await verifyX402ReceiptToken(token, {
  requiredSourceSlug: 'my-endpoint', // optional — prevents token replay
});
```

**`createX402ReceiptMiddleware(options?)`**

Express middleware that reads the token from `X-X402-Receipt-Token` or `Authorization: Bearer`, verifies it, and attaches the claims to `req.x402Receipt`.

```js
app.get(
  '/v1/resource',
  createX402ReceiptMiddleware({ requiredSourceSlug: 'my-endpoint' }),
  (req, res) => {
    res.json({ data: '...', payer: req.x402Receipt.payer_wallet });
  }
);
```

Returns `401` if the token is missing or invalid, `403` if the source slug does not match.

---

### Webhook API

**`verifyX402WebhookSignature(rawBody, signatureHeader, secret, options?)`**

Verifies `X-X402-Signature` using the shared webhook secret.

```js
verifyX402WebhookSignature(rawBody, req.headers['x-x402-signature'], process.env.X402_WEBHOOK_SECRET)
```

**`verifyX402WebhookEvent(rawBody, signatureHeader, secret, options?)`**

Verifies the webhook signature, parses the JSON payload, and if `data.receipt_token` exists, verifies the receipt too.

```js
const { payload, receipt } = await verifyX402WebhookEvent(
  rawBody,
  req.headers['x-x402-signature'],
  process.env.X402_WEBHOOK_SECRET,
  {
    requiredSourceSlug: 'claude',
    requireReceipt: true,
  }
)

const purchaseId = payload.data.client_reference_id
```

If `requireReceipt: true`, the helper rejects webhook payloads that do not include `data.receipt_token`.

---

## Python

### Receipt API

```python
from x402layer_middleware import (
    X402ReceiptVerifier,
    require_x402_receipt,
    verify_x402_webhook_signature,
    verify_x402_webhook_event,
)
```

**`X402ReceiptVerifier`**

```python
verifier = X402ReceiptVerifier(
    jwks_url="https://api.x402layer.cc/.well-known/jwks.json",  # default
    issuer="https://api.x402layer.cc",                           # default
    audience="x402layer:receipt",                                # default
)
```

**`require_x402_receipt(verifier, required_source_slug?)`**

FastAPI dependency that reads the token from `X-X402-Receipt-Token` or `Authorization: Bearer`, verifies it, and returns the decoded claims.

```python
@app.get("/v1/resource")
async def resource(receipt=require_x402_receipt(verifier, required_source_slug="my-endpoint")):
    return {"payer": receipt["payer_wallet"], "amount": receipt["amount"]}
```

Raises `HTTP 401` if the token is missing or invalid, `HTTP 403` if the source slug does not match.

---

### Webhook API

```python
result = verify_x402_webhook_event(
    raw_body,
    signature_header,
    secret,
    verifier=X402ReceiptVerifier(),
    require_receipt=True,
)

payload = result["payload"]
receipt = result["receipt"]
purchase_id = payload["data"].get("client_reference_id")
```

`verify_x402_webhook_signature(...)` is also available if you only want HMAC verification.

---

## Receipt Claims

| Claim | Type | Description |
|-------|------|-------------|
| `event` | `string` | Always `"payment.succeeded"` |
| `source` | `string` | `"endpoint"` or `"product"` |
| `source_id` | `string` | UUID of the paid resource |
| `source_slug` | `string` | Slug of the resource |
| `amount` | `string` | Payment amount (e.g. `"1.00"`) |
| `currency` | `string` | Asset symbol (e.g. `"USDC"`) |
| `tx_hash` | `string` | On-chain transaction hash |
| `payer_wallet` | `string` | Buyer wallet address |
| `network` | `string` | `"base"` or `"solana"` |
| `client_reference_id` | `string \| null` | Seller-supplied correlation id, if provided |
| `metadata` | `object` | Seller-supplied correlation metadata, if provided |
| `status` | `string` | Settlement status |
| `iat` | `number` | Issued-at (Unix timestamp) |
| `exp` | `number` | Expiry (Unix timestamp) |
| `jti` | `string` | Unique receipt ID — use for idempotency |

---

## Token Contract

| Property | Value |
|----------|-------|
| Format | JWT (JWS) |
| Algorithm | `RS256` |
| JWKS URL | `https://api.x402layer.cc/.well-known/jwks.json` |
| Issuer | `https://api.x402layer.cc` |
| Audience | `x402layer:receipt` |

The token is delivered in the `X-X402-Receipt-Token` response header after a successful payment.

---

## Webhook Payload Contract

Seller webhook payloads are signed with:

- `X-X402-Signature: t=<timestamp>,v1=<hex_hmac_sha256>`

The signed message is:

- `<timestamp>.<raw_request_body>`

Current `payment.succeeded` payloads may include:

- `data.client_reference_id`
- `data.metadata`
- `data.receipt_token`
- `data.jwks_url`

That makes deterministic purchase correlation possible for hosted checkout flows like:

```text
/pay/request/claude?amount=1&client_reference_id=abc-123
```

---

## Security

- **Always set `requiredSourceSlug`** in production to prevent receipt replay across resources.
- **Always verify the webhook signature before parsing or trusting the payload.**
- If you rely on settlement authenticity, require and verify `data.receipt_token`.
- The SDK caches JWKS keys in memory (default 5-minute TTL) to avoid excessive network calls.
- To rotate signing keys: publish a new JWKS entry with a new `kid`, then update the worker private key. Tokens signed with old keys remain verifiable until they expire.

---

## License

MIT
