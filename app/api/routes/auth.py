"""Authentication routes.

POST /auth/login            – validate credentials and return user profile
POST /auth/select-campaign  – exchange temporary token for a full JWT with campaign context
POST /auth/change-password  – change a user's password
POST /auth/phone/send-otp   – generate and send a phone OTP via SMS
POST /auth/phone/verify-otp – verify a phone OTP
POST /auth/logout           – end the current session
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from saleshub_core.repositories.user import authenticate_user

from app.api.deps import get_db_session, require_session_for_logout
from app.auth import extract_bearer_token
from app.handlers import phone_otp as phone_otp_handler
from app.handlers import user as user_handler
from app.schemas.phone_otp import SendOTPRequest, SendOTPResponse, VerifyOTPRequest, VerifyOTPResponse
from app.schemas.user import (
    LoginRequest,
    LoginResponse,
    SelectCampaignRequest,
    SelectCampaignResponse,
    UserChangePasswordRequest,
    UserChangePasswordResponse,
    UserLogoutResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse, summary="Login User")
async def login(
    payload: LoginRequest,
    session: AsyncSession = Depends(get_db_session),
) -> LoginResponse:
    """
    Authenticate a user with username + password.

    Password validation is delegated to PostgreSQL's pgcrypto ``crypt()`` function.
    Returns the full user profile on success; raises **401** on bad credentials.

    The ``X-Forwarded-For`` header is preferred for client IP when behind a proxy.
    """
    row = await authenticate_user(session, payload.username, payload.password)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    user_status = (row.get("status") or "").lower().strip()
    if user_status == "inactive":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been inactive. Please contact your administrator.",
        )
    if user_status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Your account is currently {row['status']}. Please contact your administrator.",
        )

    return LoginResponse(
        user_id=str(row["user_id"]),
        username=row["username"],
        first_name=row.get("first_name"),
        last_name=row.get("last_name"),
        email=row.get("email"),
        phone=row.get("phone"),
        role=row.get("role"),
        role_id=str(row["role_id"]) if row.get("role_id") else None,
        company_id=str(row["company_id"]) if row.get("company_id") else None,
        company=row.get("company"),
        tenant_id=str(row["tenant_id"]) if row.get("tenant_id") else None,
        tenant_name=row.get("tenant_name"),
        image=row.get("image"),
        status=row.get("status"),
        affiliate=row.get("affiliate"),
        first_login=row.get("first_login"),
        is_internal=row.get("is_internal"),
    )


# ---------------------------------------------------------------------------
# Select campaign
# ---------------------------------------------------------------------------

@router.post(
    "/select-campaign",
    response_model=SelectCampaignResponse,
    summary="Select Campaign",
    description=(
        "Exchange a temporary token (from login) for a full JWT access token "
        "that includes the selected campaign context. "
        "Validates that the user has access to the requested campaign."
    ),
)
async def select_campaign(
    request: Request,
    payload: SelectCampaignRequest,
    session: AsyncSession = Depends(get_db_session),
) -> SelectCampaignResponse:
    """Select a campaign and receive a full access token."""
    temporary_token = extract_bearer_token(request)
    return await user_handler.select_campaign(session, payload, temporary_token)


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------

@router.post(
    "/change-password",
    response_model=UserChangePasswordResponse,
    summary="Change User Password",
    description="Change a user's password. ``new_password`` and ``confirm_password`` must match.",
)
async def change_password(
    payload: UserChangePasswordRequest,
    session: AsyncSession = Depends(get_db_session),
) -> UserChangePasswordResponse:
    """Change a user's password."""
    return await user_handler.change_password(session, payload)


# ---------------------------------------------------------------------------
# Phone OTP
# ---------------------------------------------------------------------------

@router.post(
    "/phone/send-otp",
    response_model=SendOTPResponse,
    summary="Send Phone OTP",
    description="Generate and send a 6-digit OTP to the user's phone number via SMS. Valid for 90 seconds.",
)
async def send_phone_otp(
    payload: SendOTPRequest,
    session: AsyncSession = Depends(get_db_session),
) -> SendOTPResponse:
    """Send an OTP to the phone number for verification."""
    return await phone_otp_handler.send_phone_otp(session, payload)


@router.post(
    "/phone/verify-otp",
    response_model=VerifyOTPResponse,
    summary="Verify Phone OTP",
    description="Verify the OTP sent to the phone number and mark the phone as verified.",
)
async def verify_phone_otp(
    payload: VerifyOTPRequest,
    session: AsyncSession = Depends(get_db_session),
) -> VerifyOTPResponse:
    """Verify the OTP and mark phone as verified."""
    return await phone_otp_handler.verify_phone_otp(session, payload)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@router.post(
    "/logout",
    response_model=UserLogoutResponse,
    summary="Logout User",
    description=(
        "End the current session. Updates ``login_end_time`` and ``duration`` "
        "in ``user_logins``. Works even if the account is suspended."
    ),
)
async def logout_user(
    session_info: dict[str, Any] = Depends(require_session_for_logout),
    session: AsyncSession = Depends(get_db_session),
) -> UserLogoutResponse:
    """Logout and close the active session."""
    return await user_handler.logout_user(
        session,
        login_id=session_info["login_id"],
        login_start_time=session_info["login_start_time"],
    )
