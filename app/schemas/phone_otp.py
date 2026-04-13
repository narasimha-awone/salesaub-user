from __future__ import annotations

from pydantic import BaseModel, Field


class SendOTPRequest(BaseModel):
    phone: str = Field(..., min_length=1, max_length=20, description="Phone number e.g. (+44)7400326456")


class SendOTPResponse(BaseModel):
    message: str
    phone: str = Field(..., description="Phone number in E.164 format")
    expires_in_seconds: int = 90


class VerifyOTPRequest(BaseModel):
    phone: str = Field(..., min_length=1, max_length=20, description="Phone number e.g. (+44)7400326456")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")


class VerifyOTPResponse(BaseModel):
    message: str
    phone: str = Field(..., description="Phone number in E.164 format")
    phone_verified: bool
    phone_last_verified: int = Field(..., description="Verification timestamp in milliseconds")
