/*
  x402layer receipt middleware (Node/Express)
  - Verifies RS256 payment receipt JWTs issued by x402layer worker
  - Uses JWKS from https://api.x402layer.cc/.well-known/jwks.json
*/

const crypto = require('crypto')

const jwksCache = new Map()

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4))
  return Buffer.from(normalized + pad, 'base64')
}

function parseJwt(token) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('Invalid JWT format')
  const [headerB64, payloadB64, signatureB64] = parts
  const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'))
  const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'))
  const signature = base64UrlDecode(signatureB64)
  return { header, payload, signature, signingInput: `${headerB64}.${payloadB64}` }
}

async function fetchJwks(jwksUrl, cacheTtlMs = 5 * 60 * 1000) {
  const cached = jwksCache.get(jwksUrl)
  if (cached && Date.now() - cached.fetchedAt < cacheTtlMs) {
    return cached.keys
  }

  const res = await fetch(jwksUrl)
  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`)
  const json = await res.json()
  if (!json.keys || !Array.isArray(json.keys)) throw new Error('Invalid JWKS payload')

  jwksCache.set(jwksUrl, { keys: json.keys, fetchedAt: Date.now() })
  return json.keys
}

function verifyJwtSignature(parsedJwt, jwk) {
  if (!jwk) throw new Error('Signing key not found')
  if (jwk.kty !== 'RSA') throw new Error(`Unsupported key type: ${jwk.kty}`)
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' })
  return crypto.verify(
    'RSA-SHA256',
    Buffer.from(parsedJwt.signingInput),
    publicKey,
    parsedJwt.signature
  )
}

function validateClaims(payload, options = {}) {
  const now = Math.floor(Date.now() / 1000)
  const issuer = options.issuer || 'https://api.x402layer.cc'
  const audience = options.audience || 'x402layer:receipt'

  if (payload.iss !== issuer) throw new Error('Invalid issuer')
  if (payload.aud !== audience) throw new Error('Invalid audience')
  if (!payload.exp || payload.exp < now) throw new Error('Receipt token expired')
  if (payload.iat && payload.iat > now + 60) throw new Error('Invalid iat')
  if (payload.event !== 'payment.succeeded') throw new Error('Invalid receipt event')
}

async function verifyX402ReceiptToken(token, options = {}) {
  const jwksUrl = options.jwksUrl || 'https://api.x402layer.cc/.well-known/jwks.json'
  const parsed = parseJwt(token)

  if (parsed.header.alg !== 'RS256') {
    throw new Error(`Unsupported algorithm: ${parsed.header.alg}`)
  }

  const keys = await fetchJwks(jwksUrl, options.cacheTtlMs)
  const jwk = keys.find((key) => key.kid === parsed.header.kid) || keys[0]
  const validSignature = verifyJwtSignature(parsed, jwk)
  if (!validSignature) throw new Error('Invalid receipt signature')

  validateClaims(parsed.payload, options)
  return parsed.payload
}

function createX402ReceiptMiddleware(options = {}) {
  return async function x402ReceiptMiddleware(req, res, next) {
    try {
      const headerToken = req.headers['x-x402-receipt-token']
      const authHeader = req.headers.authorization || ''
      const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
      const token = headerToken || bearerToken

      if (!token) {
        return res.status(401).json({ error: 'Missing receipt token' })
      }

      const claims = await verifyX402ReceiptToken(token, options)

      if (options.requiredSourceSlug && claims.source_slug !== options.requiredSourceSlug) {
        return res.status(403).json({ error: 'Token source mismatch' })
      }

      req.x402Receipt = claims
      return next()
    } catch (err) {
      return res.status(401).json({ error: err.message || 'Invalid receipt token' })
    }
  }
}

module.exports = {
  verifyX402ReceiptToken,
  createX402ReceiptMiddleware
}
