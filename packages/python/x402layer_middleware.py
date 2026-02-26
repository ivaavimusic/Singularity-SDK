"""
x402layer receipt middleware (FastAPI)
- Verifies RS256 payment receipt JWTs issued by x402layer worker
- Uses JWKS from https://api.x402layer.cc/.well-known/jwks.json
"""

from typing import Dict, Any, Optional

import jwt
from fastapi import Depends, Header, HTTPException
from jwt import PyJWKClient


class X402ReceiptVerifier:
    def __init__(
        self,
        jwks_url: str = "https://api.x402layer.cc/.well-known/jwks.json",
        issuer: str = "https://api.x402layer.cc",
        audience: str = "x402layer:receipt",
    ) -> None:
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.jwk_client = PyJWKClient(jwks_url)

    def verify(self, token: str) -> Dict[str, Any]:
        signing_key = self.jwk_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
        )

        if payload.get("event") != "payment.succeeded":
            raise HTTPException(status_code=401, detail="Invalid receipt event")

        return payload


def bearer_or_header_token(
    authorization: Optional[str],
    x_x402_receipt_token: Optional[str],
) -> Optional[str]:
    if x_x402_receipt_token:
        return x_x402_receipt_token
    if authorization and authorization.startswith("Bearer "):
        return authorization[len("Bearer "):]
    return None


def require_x402_receipt(
    verifier: X402ReceiptVerifier,
    required_source_slug: Optional[str] = None,
):
    async def _dependency(
        authorization: Optional[str] = Header(default=None),
        x_x402_receipt_token: Optional[str] = Header(default=None),
    ) -> Dict[str, Any]:
        token = bearer_or_header_token(authorization, x_x402_receipt_token)
        if not token:
            raise HTTPException(status_code=401, detail="Missing receipt token")

        try:
            claims = verifier.verify(token)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=401, detail=f"Invalid receipt token: {exc}") from exc

        if required_source_slug and claims.get("source_slug") != required_source_slug:
            raise HTTPException(status_code=403, detail="Token source mismatch")

        return claims

    return Depends(_dependency)


# Example:
# verifier = X402ReceiptVerifier()
#
# @app.get("/premium")
# async def premium_endpoint(receipt= require_x402_receipt(verifier, required_source_slug="my-endpoint")):
#     return {"ok": True, "receipt": receipt}
