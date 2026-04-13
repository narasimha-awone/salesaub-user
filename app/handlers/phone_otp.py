"""
Phone OTP handler.

Adapted from the monolith's app/handler/phone_otp.py.
Uses SQLAlchemy AsyncSession (text() queries) instead of psycopg2.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.phone_otp import (
    SendOTPRequest,
    SendOTPResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from app.settings import settings

# OTP expiry: 90 seconds in milliseconds
_OTP_EXPIRY_MS = 90 * 1000


# ---------------------------------------------------------------------------
# Phone-number helpers
# ---------------------------------------------------------------------------

def _convert_phone_to_e164(phone: str) -> str:
    """Convert (+44)7400326456 → +447400326456."""
    if not phone:
        raise ValueError("Phone number cannot be empty")
    phone = phone.strip()
    match = re.match(r"^\((\+\d+)\)(.+)$", phone)
    if match:
        country_code = match.group(1)
        number = re.sub(r"[\s-]", "", match.group(2))
        return f"{country_code}{number}"
    if phone.startswith("+"):
        return phone
    cleaned = re.sub(r"[^\d+]", "", phone)
    if cleaned.startswith("+"):
        return cleaned
    raise ValueError(f"Invalid phone number format: {phone}")


def _generate_otp() -> str:
    """Return a cryptographically-random 6-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


# ---------------------------------------------------------------------------
# SMS gateway
# ---------------------------------------------------------------------------

async def _send_sms_via_webex(phone_e164: str, otp: str) -> None:
    """Send OTP via the Webex Interact SMS gateway."""
    if not settings.webex_interact_auth_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webex Interact API authentication key is not configured.",
        )
    if not settings.webex_interact_sender_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webex Interact sender ID is not configured.",
        )

    payload = {
        "message_body": "Please use this OTP: ${otpvalue} to continue on SalesHub 2.0",
        "from": settings.webex_interact_sender_id,
        "to": [{"phone": [phone_e164], "merge_fields": {"otpvalue": otp}}],
    }
    headers = {
        "X-AUTH-KEY": settings.webex_interact_auth_key,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.webex_interact_timeout) as client:
            response = await client.post(
                settings.webex_interact_api_url,
                json=payload,
                headers=headers,
            )
            if response.status_code >= 400:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to send SMS. Please try again later.",
                )
            try:
                data: Any = response.json()
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Invalid response from SMS service.",
                ) from exc

            if data.get("errors"):
                error = data["errors"][0]
                code = error.get("code")
                msg = error.get("message", "Unknown error")
                if code == 10005:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="SMS service temporarily unavailable. Please try again later.",
                    )
                if code == 1002:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid phone number format.",
                    )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Failed to send SMS: {msg}",
                )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach SMS service. Please try again later.",
        ) from exc


# ---------------------------------------------------------------------------
# Public handler functions
# ---------------------------------------------------------------------------

async def send_phone_otp(session: AsyncSession, payload: SendOTPRequest) -> SendOTPResponse:
    """Generate and send a phone OTP, storing it in the users table."""
    try:
        phone_e164 = _convert_phone_to_e164(payload.phone)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid phone number format: {exc}",
        ) from exc

    try:
        result = await session.execute(
            text(
                """
                SELECT user_id, phone
                FROM users
                WHERE (phone = :phone OR phone = :phone_e164) AND del_flg = false
                LIMIT 1
                """
            ),
            {"phone": payload.phone, "phone_e164": phone_e164},
        )
        user = result.mappings().fetchone()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Phone number not found.",
            )

        otp = _generate_otp()
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        await session.execute(
            text(
                """
                UPDATE users
                SET phone_otp = :otp,
                    otp_created_at = :now_ms
                WHERE user_id = :user_id AND del_flg = false
                """
            ),
            {"otp": otp, "now_ms": now_ms, "user_id": user["user_id"]},
        )
        await session.flush()

        await _send_sms_via_webex(phone_e164, otp)
        await session.commit()

        return SendOTPResponse(
            message="OTP sent successfully",
            phone=phone_e164,
            expires_in_seconds=90,
        )

    except HTTPException:
        await session.rollback()
        raise
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while processing OTP request.",
        ) from exc


async def verify_phone_otp(session: AsyncSession, payload: VerifyOTPRequest) -> VerifyOTPResponse:
    """Verify the OTP and mark the phone as verified."""
    try:
        phone_e164 = _convert_phone_to_e164(payload.phone)
    except ValueError:
        phone_e164 = payload.phone

    try:
        result = await session.execute(
            text(
                """
                SELECT user_id, phone, phone_otp, otp_created_at,
                       phone_verified, phone_last_verified
                FROM users
                WHERE (phone = :phone OR phone = :phone_e164) AND del_flg = false
                LIMIT 1
                """
            ),
            {"phone": payload.phone, "phone_e164": phone_e164},
        )
        user = result.mappings().fetchone()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Phone number not found.",
            )

        stored_otp = user.get("phone_otp")
        otp_created_at = user.get("otp_created_at")

        if not stored_otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No OTP found. Please request a new OTP.",
            )
        if stored_otp != payload.otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP.",
            )
        if otp_created_at is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP timestamp not found. Please request a new OTP.",
            )

        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        if now_ms - otp_created_at > _OTP_EXPIRY_MS:
            await session.execute(
                text(
                    """
                    UPDATE users
                    SET phone_otp = NULL, otp_created_at = NULL
                    WHERE user_id = :user_id AND del_flg = false
                    """
                ),
                {"user_id": user["user_id"]},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has expired. Please request a new one.",
            )

        await session.execute(
            text(
                """
                UPDATE users
                SET phone_verified = true,
                    phone_last_verified = :now_ms,
                    phone_otp = NULL,
                    otp_created_at = NULL
                WHERE user_id = :user_id AND del_flg = false
                """
            ),
            {"now_ms": now_ms, "user_id": user["user_id"]},
        )
        await session.commit()

        return VerifyOTPResponse(
            message="Phone number verified successfully",
            phone=phone_e164,
            phone_verified=True,
            phone_last_verified=now_ms,
        )

    except HTTPException:
        await session.rollback()
        raise
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while processing OTP verification.",
        ) from exc
