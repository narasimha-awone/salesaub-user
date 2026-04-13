"""
User business-logic handlers.

Adapted from the monolith's app/handler/user.py.
Uses SQLAlchemy AsyncSession instead of psycopg2.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

import saleshub_core.repositories.user as user_repo

from app.auth import create_access_token, decode_temporary_token
from app.schemas.user import (
    SelectCampaignRequest,
    SelectCampaignResponse,
    UserChangePasswordRequest,
    UserChangePasswordResponse,
    UserLogoutResponse,
)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _current_epoch_millis() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _normalize_username(username: str) -> str:
    """Lower-case all alphabetic characters, preserve the rest."""
    if any(c.isalpha() for c in username):
        return "".join(c.lower() if c.isalpha() else c for c in username)
    return username


def _validate_password(password: str) -> tuple[bool, str]:
    """
    Enforce: ≥8 chars, ≥1 digit, ≥1 special char from !@#$%^&*.
    Returns (is_valid, error_message).
    """
    if not password:
        return False, "Password is required."
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(c.isdigit() for c in password):
        errors.append("at least one number")
    if not any(c in "!@#$%^&*" for c in password):
        errors.append("at least one special character (!@#$%^&*)")
    if errors:
        return False, "Password must contain: " + ", ".join(errors) + "."
    return True, ""


def _is_company_admin_or_manager(role: str) -> bool:
    return role in ("company_admin", "company_manager")


def _is_agent_role(role: str) -> bool:
    return role in ("field_agent", "tele_agent", "tele_verifier")


# ---------------------------------------------------------------------------
# change_password
# ---------------------------------------------------------------------------

async def change_password(
    session: AsyncSession,
    payload: UserChangePasswordRequest,
) -> UserChangePasswordResponse:
    """Validate and apply a password change."""
    is_valid, error_msg = _validate_password(payload.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirm password do not match.",
        )

    normalized = _normalize_username(payload.username)
    try:
        user = await user_repo.get_user_by_username(session, normalized)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        await user_repo.update_user_password(session, user["user_id"], payload.new_password)
        await session.commit()
        return UserChangePasswordResponse(
            message="Password changed successfully",
            username=user["username"],
        )
    except HTTPException:
        await session.rollback()
        raise
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error while changing password: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# logout_user
# ---------------------------------------------------------------------------

async def logout_user(
    session: AsyncSession,
    login_id: str,
    login_start_time: int,
) -> UserLogoutResponse:
    """Mark a user_logins session as inactive and return duration."""
    now_ms = _current_epoch_millis()
    duration_ms = now_ms - login_start_time
    hours, rem = divmod(duration_ms, 3_600_000)
    minutes, rem = divmod(rem, 60_000)
    seconds = rem // 1000
    duration_formatted = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    try:
        result = await session.execute(
            text(
                """
                UPDATE user_logins
                SET login_end_time = :now_ms,
                    duration       = :duration_ms,
                    login_status   = 'inactive'
                WHERE login_id     = :login_id
                  AND login_status = 'active'
                  AND login_end_time IS NULL
                RETURNING login_id
                """
            ),
            {"now_ms": now_ms, "duration_ms": duration_ms, "login_id": login_id},
        )
        if not result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Active session not found or already logged out.",
            )
        await session.commit()
        return UserLogoutResponse(
            message="Logout successful",
            login_id=login_id,
            duration_ms=duration_ms,
            duration_formatted=duration_formatted,
        )
    except HTTPException:
        await session.rollback()
        raise
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error during logout: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# select_campaign
# ---------------------------------------------------------------------------

async def select_campaign(
    session: AsyncSession,
    payload: SelectCampaignRequest,
    temporary_token: str,
) -> SelectCampaignResponse:
    """
    Validate campaign access, mint an access token with campaign context,
    and update the user_logins session.
    """
    import jwt as pyjwt

    try:
        claims = decode_temporary_token(temporary_token)
    except pyjwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Temporary token has expired.",
        ) from exc
    except pyjwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid temporary token: {exc}",
        ) from exc

    user_id: str = claims.get("user_id", "")
    login_id: str = claims.get("login_id", "")
    user_role: str = (claims.get("role") or "").strip().lower().replace(" ", "_")
    campaign_id: str = payload.campaign_id

    if not user_id or not login_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Temporary token is missing required claims.",
        )

    try:
        # 1. Validate campaign exists
        r = await session.execute(
            text(
                """
                SELECT campaign_id, campaign_name, tenant_id, status
                FROM campaign
                WHERE campaign_id = :campaign_id
                  AND (del_flg = false OR del_flg IS NULL)
                """
            ),
            {"campaign_id": campaign_id},
        )
        campaign = r.mappings().fetchone()
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Campaign '{campaign_id}' not found.",
            )

        # 2. Validate user has access to the campaign
        if _is_company_admin_or_manager(user_role):
            r2 = await session.execute(
                text("SELECT company_id FROM users WHERE user_id = :uid"),
                {"uid": user_id},
            )
            user_row = r2.mappings().fetchone()
            if not user_row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
            company_id_val = user_row["company_id"]
            r3 = await session.execute(
                text(
                    """
                    SELECT campaign_company_id
                    FROM campaign_company
                    WHERE campaign_id = :cid AND company_id = :co_id
                    """
                ),
                {"cid": campaign_id, "co_id": company_id_val},
            )
            if not r3.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Your company is not assigned to campaign '{campaign_id}'.",
                )
        elif _is_agent_role(user_role):
            r4 = await session.execute(
                text(
                    """
                    WITH latest AS (
                        SELECT assignment_status,
                               ROW_NUMBER() OVER (
                                   PARTITION BY agent_id, campaign_id
                                   ORDER BY assignment_datetime DESC NULLS LAST
                               ) AS rn
                        FROM campaign_agent
                        WHERE agent_id = :uid AND campaign_id = :cid
                    )
                    SELECT assignment_status FROM latest WHERE rn = 1
                    """
                ),
                {"uid": user_id, "cid": campaign_id},
            )
            assignment = r4.mappings().fetchone()
            if not assignment or assignment["assignment_status"] != "active":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"You do not have an active assignment for campaign '{campaign_id}'.",
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role}' is not authorized to select campaigns.",
            )

        # 3. Campaign switching: close existing active session if present
        now_ms = _current_epoch_millis()
        r5 = await session.execute(
            text(
                """
                SELECT login_id, session_token
                FROM user_logins
                WHERE user_id = :uid
                  AND temporary_token = :tmp
                  AND login_status = 'active'
                  AND login_end_time IS NULL
                """
            ),
            {"uid": user_id, "tmp": temporary_token},
        )
        existing = r5.mappings().fetchone()

        if existing and existing.get("session_token"):
            current_login_id = existing["login_id"]
            await session.execute(
                text(
                    """
                    UPDATE user_logins
                    SET login_end_time = :now_ms,
                        duration       = :now_ms - login_start_time,
                        login_status   = 'inactive'
                    WHERE login_id = :lid
                      AND login_status = 'active'
                      AND login_end_time IS NULL
                    """
                ),
                {"now_ms": now_ms, "lid": current_login_id},
            )
            r6 = await session.execute(
                text(
                    """
                    INSERT INTO user_logins (
                        user_id, role_id, company_id, username, user_role,
                        login_start_time, login_end_time, duration,
                        session_token, temporary_token, ip_address, login_status
                    )
                    SELECT user_id, role_id, company_id, username, user_role,
                           :now_ms, NULL, NULL,
                           NULL, :tmp, ip_address, 'active'
                    FROM user_logins WHERE login_id = :lid
                    RETURNING login_id
                    """
                ),
                {"now_ms": now_ms, "tmp": temporary_token, "lid": current_login_id},
            )
            new_row = r6.mappings().fetchone()
            if not new_row:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create new session for campaign switch.",
                )
            login_id = new_row["login_id"]

        # 4. Fetch full user details
        r7 = await session.execute(
            text(
                """
                SELECT u.user_id, u.username, u.first_name, u.last_name,
                       u.email, u.phone, u.role, u.role_id, u.company_id,
                       u.company, u.tenant_id, u.image, u.status,
                       u.affiliate, u.first_login, u.is_internal,
                       t.tenant_name,
                       co.company_name, co.vendor_lead_code, co.company_logo,
                       co.tenant_id AS company_tenant_id
                FROM users u
                LEFT JOIN tenant t  ON u.tenant_id  = t.tenant_id
                LEFT JOIN company co ON u.company_id = co.company_id
                WHERE u.user_id = :uid AND u.del_flg = false
                """
            ),
            {"uid": user_id},
        )
        user: Any = r7.mappings().fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        company_id_val = user.get("company_id")
        company_name = user.get("company_name") or user.get("company")
        vendor_lead_code = user.get("vendor_lead_code")
        logo = user.get("company_logo")
        tenant_id_for_claims = user.get("company_tenant_id") or user.get("tenant_id")

        # 5. Fetch permissions
        permissions: list[str] = []
        if user.get("role_id"):
            r8 = await session.execute(
                text(
                    """
                    SELECT p.permission_name
                    FROM users u
                    JOIN roles r         ON u.role_id       = r.role_id
                    JOIN role_permissions rp ON rp.role_id  = r.role_id
                    JOIN permissions p   ON p.permission_id = rp.permission_id
                    WHERE u.user_id = :uid
                    ORDER BY p.permission_name
                    """
                ),
                {"uid": user_id},
            )
            permissions = [row["permission_name"] for row in r8.mappings().fetchall()]

        # 6. Build and mint access token
        exp_seconds = 8 * 60 * 60  # 8 hours
        access_token_claims: dict[str, Any] = {
            "sub": user_id,
            "user_id": user_id,
            "user_name": user.get("username"),
            "role": user.get("role"),
            "company_id": company_id_val,
            "company_name": company_name,
            "tenant_id": tenant_id_for_claims,
            "campaign_id": campaign_id,
            "login_id": login_id,
            "is_internal": bool(claims.get("is_internal", False)),
            "iat": now_ms // 1000,
            "exp": now_ms // 1000 + exp_seconds,
            "iss": "saleshub-backend",
            "aud": "saleshub-clients",
        }
        if vendor_lead_code is not None:
            access_token_claims["vendor_lead_code"] = vendor_lead_code

        access_token = create_access_token(access_token_claims)

        # 7. Update session with the new access token and campaign_id
        await session.execute(
            text(
                """
                UPDATE user_logins
                SET session_token = :token, campaign_id = :cid
                WHERE login_id = :lid
                """
            ),
            {"token": access_token, "cid": campaign_id, "lid": login_id},
        )
        await session.commit()

        enforce_campaign = user_role not in ("super_admin", "tenant_admin")

        return SelectCampaignResponse(
            user_id=str(user["user_id"]),
            username=user["username"],
            first_name=user.get("first_name"),
            last_name=user.get("last_name"),
            email=user.get("email"),
            phone=user.get("phone"),
            role=user.get("role"),
            company_id=str(company_id_val) if company_id_val else None,
            company=company_name,
            tenant_id=str(user["tenant_id"]) if user.get("tenant_id") else None,
            tenant_name=user.get("tenant_name"),
            image=user.get("image"),
            status=user["status"],
            vendor_lead_code=vendor_lead_code,
            affiliate=user.get("affiliate"),
            logo=logo,
            permissions=permissions,
            is_internal=bool(claims.get("is_internal", False)),
            first_login=bool(user.get("first_login", False)),
            access_token=access_token,
            temporary_token=temporary_token,
            enforce_campaign=enforce_campaign,
        )

    except HTTPException:
        await session.rollback()
        raise
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error during campaign selection: {exc}",
        ) from exc
