"""
Auth service.

Encapsulates all business logic for authentication:
login, campaign selection, password change, phone OTP, and logout.
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

import saleshub_core.repositories.user as user_repo
from saleshub_core.repositories.user import authenticate_user

from app.auth import create_access_token, decode_temporary_token
from app.schemas.phone_otp import SendOTPRequest, SendOTPResponse, VerifyOTPRequest, VerifyOTPResponse
from app.schemas.user import (
    LoginResponse,
    SelectCampaignRequest,
    SelectCampaignResponse,
    UserChangePasswordRequest,
    UserChangePasswordResponse,
    UserLogoutResponse,
)
from app.settings import settings

_OTP_EXPIRY_MS = 90 * 1000


class AuthService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _current_epoch_millis() -> int:
        return int(datetime.now(timezone.utc).timestamp() * 1000)

    @staticmethod
    def _normalize_username(username: str) -> str:
        if any(c.isalpha() for c in username):
            return "".join(c.lower() if c.isalpha() else c for c in username)
        return username

    @staticmethod
    def _validate_password(password: str) -> tuple[bool, str]:
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

    @staticmethod
    def _is_company_admin_or_manager(role: str) -> bool:
        return role in ("company_admin", "company_manager")

    @staticmethod
    def _is_agent_role(role: str) -> bool:
        return role in ("field_agent", "tele_agent", "tele_verifier")

    @staticmethod
    def _convert_phone_to_e164(phone: str) -> str:
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

    @staticmethod
    def _generate_otp() -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(self, username: str, password: str) -> LoginResponse:
        row = await authenticate_user(self._session, username, password)
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

    # ------------------------------------------------------------------
    # Select campaign
    # ------------------------------------------------------------------

    async def select_campaign(
        self,
        payload: SelectCampaignRequest,
        temporary_token: str,
    ) -> SelectCampaignResponse:
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
            r = await self._session.execute(
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
            if self._is_company_admin_or_manager(user_role):
                r2 = await self._session.execute(
                    text("SELECT company_id FROM users WHERE user_id = :uid"),
                    {"uid": user_id},
                )
                user_row = r2.mappings().fetchone()
                if not user_row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
                r3 = await self._session.execute(
                    text(
                        """
                        SELECT campaign_company_id
                        FROM campaign_company
                        WHERE campaign_id = :cid AND company_id = :co_id
                        """
                    ),
                    {"cid": campaign_id, "co_id": user_row["company_id"]},
                )
                if not r3.fetchone():
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Your company is not assigned to campaign '{campaign_id}'.",
                    )
            elif self._is_agent_role(user_role):
                r4 = await self._session.execute(
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
            now_ms = self._current_epoch_millis()
            r5 = await self._session.execute(
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
                await self._session.execute(
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
                r6 = await self._session.execute(
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
                    await self._session.rollback()
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to create new session for campaign switch.",
                    )
                login_id = new_row["login_id"]

            # 4. Fetch full user details
            r7 = await self._session.execute(
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
                r8 = await self._session.execute(
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

            # 6. Mint access token
            exp_seconds = 8 * 60 * 60
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

            # 7. Update session with new token and campaign_id
            await self._session.execute(
                text(
                    """
                    UPDATE user_logins
                    SET session_token = :token, campaign_id = :cid
                    WHERE login_id = :lid
                    """
                ),
                {"token": access_token, "cid": campaign_id, "lid": login_id},
            )
            await self._session.commit()

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
            await self._session.rollback()
            raise
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error during campaign selection: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Change password (auth flow — validates confirm_password)
    # ------------------------------------------------------------------

    async def change_password(self, payload: UserChangePasswordRequest) -> UserChangePasswordResponse:
        is_valid, error_msg = self._validate_password(payload.new_password)
        if not is_valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

        if payload.new_password != payload.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password and confirm password do not match.",
            )

        normalized = self._normalize_username(payload.username)
        try:
            user = await user_repo.get_user_by_username(self._session, normalized)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found.",
                )
            await user_repo.update_user_password(self._session, user["user_id"], payload.new_password)
            await self._session.commit()
            return UserChangePasswordResponse(
                message="Password changed successfully",
                username=user["username"],
            )
        except HTTPException:
            await self._session.rollback()
            raise
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error while changing password: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    async def logout_user(self, login_id: str, login_start_time: int) -> UserLogoutResponse:
        now_ms = self._current_epoch_millis()
        duration_ms = now_ms - login_start_time
        hours, rem = divmod(duration_ms, 3_600_000)
        minutes, rem = divmod(rem, 60_000)
        seconds = rem // 1000
        duration_formatted = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        try:
            result = await self._session.execute(
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
            await self._session.commit()
            return UserLogoutResponse(
                message="Logout successful",
                login_id=login_id,
                duration_ms=duration_ms,
                duration_formatted=duration_formatted,
            )
        except HTTPException:
            await self._session.rollback()
            raise
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error during logout: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Phone OTP
    # ------------------------------------------------------------------

    async def send_phone_otp(self, payload: SendOTPRequest) -> SendOTPResponse:
        try:
            phone_e164 = self._convert_phone_to_e164(payload.phone)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid phone number format: {exc}",
            ) from exc

        try:
            result = await self._session.execute(
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

            otp = self._generate_otp()
            now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

            await self._session.execute(
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
            await self._session.flush()

            await self._send_sms_via_webex(phone_e164, otp)
            await self._session.commit()

            return SendOTPResponse(
                message="OTP sent successfully",
                phone=phone_e164,
                expires_in_seconds=90,
            )

        except HTTPException:
            await self._session.rollback()
            raise
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error while processing OTP request.",
            ) from exc

    async def verify_phone_otp(self, payload: VerifyOTPRequest) -> VerifyOTPResponse:
        try:
            phone_e164 = self._convert_phone_to_e164(payload.phone)
        except ValueError:
            phone_e164 = payload.phone

        try:
            result = await self._session.execute(
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
                await self._session.execute(
                    text(
                        """
                        UPDATE users
                        SET phone_otp = NULL, otp_created_at = NULL
                        WHERE user_id = :user_id AND del_flg = false
                        """
                    ),
                    {"user_id": user["user_id"]},
                )
                await self._session.commit()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="OTP has expired. Please request a new one.",
                )

            await self._session.execute(
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
            await self._session.commit()

            return VerifyOTPResponse(
                message="Phone number verified successfully",
                phone=phone_e164,
                phone_verified=True,
                phone_last_verified=now_ms,
            )

        except HTTPException:
            await self._session.rollback()
            raise
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error while processing OTP verification.",
            ) from exc

    # ------------------------------------------------------------------
    # SMS gateway (private)
    # ------------------------------------------------------------------

    @staticmethod
    async def _send_sms_via_webex(phone_e164: str, otp: str) -> None:
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
