"""
Shared FastAPI dependencies for the user service.

Re-exports saleshub_core auth dependencies so routes only need to import from here.
Also provides service-specific dependencies (e.g. session-aware logout).
"""

from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from saleshub_core.auth.dependencies import require_auth, require_roles
from saleshub_core.auth.schemas import TokenPayload
from saleshub_core.database import get_db_session

from app.auth import decode_access_token, extract_bearer_token
from app.services.auth_service import AuthService
from app.services.user_service import UserService

__all__ = [
    "get_db_session",
    "require_auth",
    "require_roles",
    "require_session_for_logout",
    "TokenPayload",
    "get_user_service",
    "get_auth_service",
]


async def require_session_for_logout(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Dependency for the logout endpoint.

    Extracts the bearer token, decodes it to obtain ``login_id``, then
    fetches the matching active row from ``user_logins``.  Allows logout
    even when the account is suspended/inactive (intentional).
    """
    token = extract_bearer_token(request)

    try:
        claims: dict[str, Any] = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        ) from exc

    login_id = claims.get("login_id")
    user_id = claims.get("user_id") or claims.get("sub")

    if not login_id or not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing session claims.",
        )

    result = await session.execute(
        text(
            """
            SELECT login_id, login_start_time
            FROM user_logins
            WHERE login_id = :login_id
              AND user_id  = :user_id
              AND login_status = 'active'
              AND login_end_time IS NULL
            """
        ),
        {"login_id": login_id, "user_id": user_id},
    )
    login = result.mappings().fetchone()
    if not login:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active session found.",
        )

    return {"login_id": login["login_id"], "login_start_time": login["login_start_time"]}


def get_user_service(session: AsyncSession = Depends(get_db_session)) -> UserService:
    return UserService(session)


def get_auth_service(session: AsyncSession = Depends(get_db_session)) -> AuthService:
    return AuthService(session)
