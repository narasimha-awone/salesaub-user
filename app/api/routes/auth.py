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

from fastapi import APIRouter, Depends, Request

from app.api.deps import get_auth_service, require_session_for_logout
from app.auth import extract_bearer_token
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
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse, summary="Login User")
async def login(
    payload: LoginRequest,
    svc: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    """
    Authenticate a user with username + password.

    Password validation is delegated to PostgreSQL's pgcrypto ``crypt()`` function.
    Returns the full user profile on success; raises **401** on bad credentials.
    """
    return await svc.login(payload.username, payload.password)


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
    svc: AuthService = Depends(get_auth_service),
) -> SelectCampaignResponse:
    """Select a campaign and receive a full access token."""
    temporary_token = extract_bearer_token(request)
    return await svc.select_campaign(payload, temporary_token)


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
    svc: AuthService = Depends(get_auth_service),
) -> UserChangePasswordResponse:
    """Change a user's password."""
    return await svc.change_password(payload)


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
    svc: AuthService = Depends(get_auth_service),
) -> SendOTPResponse:
    """Send an OTP to the phone number for verification."""
    return await svc.send_phone_otp(payload)


@router.post(
    "/phone/verify-otp",
    response_model=VerifyOTPResponse,
    summary="Verify Phone OTP",
    description="Verify the OTP sent to the phone number and mark the phone as verified.",
)
async def verify_phone_otp(
    payload: VerifyOTPRequest,
    svc: AuthService = Depends(get_auth_service),
) -> VerifyOTPResponse:
    """Verify the OTP and mark phone as verified."""
    return await svc.verify_phone_otp(payload)


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
    svc: AuthService = Depends(get_auth_service),
) -> UserLogoutResponse:
    """Logout and close the active session."""
    return await svc.logout_user(
        login_id=session_info["login_id"],
        login_start_time=session_info["login_start_time"],
    )
