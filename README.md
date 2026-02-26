# x402layer SDK (Preview)

This folder contains reference middleware for verifying x402layer signed receipt tokens locally.

## Receipt Token Contract (JWS)

- Format: JWT (JWS), `alg=RS256`
- JWKS URL: `https://api.x402layer.cc/.well-known/jwks.json`
- Issuer: `https://api.x402layer.cc`
- Audience: `x402layer:receipt`
- Event claim: `event = payment.succeeded`

### Core Claims

- `source`: `endpoint` | `product`
- `source_id`: UUID/string resource id
- `source_slug`: slug of resource
- `amount`, `currency`
- `tx_hash`
- `payer_wallet`
- `network`
- `status`
- `iat`, `exp`, `jti`

## Node

- File: `sdk/node/x402layer-middleware.js`
- Exports:
  - `verifyX402ReceiptToken(token, options)`
  - `createX402ReceiptMiddleware(options)`

## Python / FastAPI

- File: `sdk/python/x402layer_middleware.py`
- Install deps from `sdk/python/requirements.txt`
- Use:
  - `X402ReceiptVerifier`
  - `require_x402_receipt(verifier, required_source_slug=None)`

## Notes

- Keep `required_source_slug` enabled in production routes to prevent token replay across services.
- Rotate signing keys by publishing a new JWKS key with a new `kid` and updating the worker private key.
