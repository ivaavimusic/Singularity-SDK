"""
x402layer receipt + webhook helpers
- Verifies RS256 payment receipt JWTs issued by x402layer worker
- Verifies webhook HMAC signatures
- Can cross-check webhook payloads against embedded receipt tokens
"""

from typing import Dict, Any, Optional, Tuple
import hashlib
import hmac
import json
import time

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


def parse_webhook_signature(signature_header: str) -> Tuple[int, str]:
    if not signature_header:
        raise ValueError("Missing webhook signature")

    parts: Dict[str, str] = {}
    for segment in signature_header.split(","):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        key, value = segment.split("=", 1)
        parts[key] = value

    if "t" not in parts or "v1" not in parts:
        raise ValueError("Invalid webhook signature format")

    try:
        timestamp = int(parts["t"])
    except ValueError as exc:
        raise ValueError("Invalid webhook timestamp") from exc

    return timestamp, parts["v1"]


def verify_x402_webhook_signature(
    raw_body: str,
    signature_header: str,
    secret: str,
    *,
    tolerance_seconds: int = 300,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    if not secret:
        raise ValueError("Missing webhook secret")

    timestamp, signature = parse_webhook_signature(signature_header)
    current_time = int(time.time()) if now is None else now

    if tolerance_seconds > 0 and abs(current_time - timestamp) > tolerance_seconds:
        raise ValueError("Webhook timestamp outside tolerance")

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.{raw_body}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid webhook signature")

    return {"timestamp": timestamp, "signature": signature}


def verify_x402_webhook_event(
    raw_body: str,
    signature_header: str,
    secret: str,
    verifier: Optional[X402ReceiptVerifier] = None,
    *,
    require_receipt: bool = False,
    verify_receipt: bool = True,
    tolerance_seconds: int = 300,
) -> Dict[str, Any]:
    signature = verify_x402_webhook_signature(
        raw_body,
        signature_header,
        secret,
        tolerance_seconds=tolerance_seconds,
    )

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid webhook JSON") from exc

    if not isinstance(payload, dict):
        raise ValueError("Invalid webhook payload")

    receipt = None
    receipt_token = payload.get("data", {}).get("receipt_token") if isinstance(payload.get("data"), dict) else None
    if receipt_token and verify_receipt:
        receipt_verifier = verifier or X402ReceiptVerifier()
        receipt = receipt_verifier.verify(receipt_token)

        data = payload.get("data", {})
        if data.get("tx_hash") and receipt.get("tx_hash") != data.get("tx_hash"):
            raise ValueError("Webhook receipt tx_hash mismatch")
        if data.get("source_slug") and receipt.get("source_slug") != data.get("source_slug"):
            raise ValueError("Webhook receipt source_slug mismatch")
        if data.get("amount") is not None and float(receipt.get("amount", 0)) != float(data.get("amount")):
            raise ValueError("Webhook receipt amount mismatch")
    elif require_receipt:
        raise ValueError("Missing receipt token in webhook payload")

    return {"payload": payload, "signature": signature, "receipt": receipt}


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
