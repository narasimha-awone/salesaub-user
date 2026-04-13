"""
JWT helpers for the SalesHub user service.

Provides:
- Access token minting  (select-campaign flow)
- Temporary token minting / decoding  (login → campaign-selection handoff)
- Bearer-token extraction from requests
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request, status

from app.settings import settings


def _require_setting(value: str, env_name: str) -> str:
    if not value:
        raise RuntimeError(f"{env_name} must be set in environment variables")
    return value


# ---------------------------------------------------------------------------
# Access token
# ---------------------------------------------------------------------------

def create_access_token(claims: dict[str, Any]) -> str:
    """Mint a signed JWT access token (RS256)."""
    import jwt as pyjwt
    private_key = _require_setting(settings.jwt_private_key, "JWT_PRIVATE_KEY")
    token = pyjwt.encode(claims, private_key, algorithm=settings.jwt_algorithm)
    return token if isinstance(token, str) else token.decode()


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT access token. Returns all raw claims."""
    import jwt as pyjwt
    public_key = _require_setting(settings.jwt_public_key, "JWT_PUBLIC_KEY")
    return pyjwt.decode(
        token,
        public_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_aud": False},
    )


# ---------------------------------------------------------------------------
# Temporary token (login → campaign-selection handoff)
# ---------------------------------------------------------------------------

def create_temporary_token(claims: dict[str, Any]) -> str:
    """Mint a signed temporary token (RS256, separate key pair)."""
    import jwt as pyjwt
    private_key = _require_setting(settings.temporary_token_private_key, "TEMPORARY_TOKEN_PRIVATE_KEY")
    token = pyjwt.encode(claims, private_key, algorithm="RS256")
    return token if isinstance(token, str) else token.decode()


def decode_temporary_token(token: str) -> dict[str, Any]:
    """Decode and verify a temporary token."""
    import jwt as pyjwt
    public_key = _require_setting(settings.temporary_token_public_key, "TEMPORARY_TOKEN_PUBLIC_KEY")
    return pyjwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={"verify_aud": False},
    )


# ---------------------------------------------------------------------------
# Bearer-token extraction
# ---------------------------------------------------------------------------

def extract_bearer_token(request: Request) -> str:
    """Extract the raw Bearer token from the Authorization header."""
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header.",
        )
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
        )
    return token
