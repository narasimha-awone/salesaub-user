from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# User response
# ---------------------------------------------------------------------------

class UserResponse(BaseModel):
    user_id: str
    user_num: int | None = None
    username: str
    first_name: str | None = None
    last_name: str | None = None
    created_time: int | None = None
    status: str | None = None
    company: str | None = None
    company_id: str | None = None
    tenant_id: str | None = None
    tenant_name: str | None = None
    image: str | None = None
    role_id: str | None = None
    role: str | None = None
    email: str | None = None
    phone: str | None = None
    email_verified: bool | None = None
    phone_verified: bool | None = None
    email_last_verified: int | None = None
    phone_last_verified: int | None = None
    affiliate: str | None = None

    model_config = {"from_attributes": True}


class UserBasicResponse(BaseModel):
    user_id: str
    role: str | None = None
    company_id: str | None = None
    tenant_id: str | None = None


class UserPermissionsResponse(BaseModel):
    user_id: str
    permissions: list[str]


# ---------------------------------------------------------------------------
# Create user
# ---------------------------------------------------------------------------

class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    first_name: str | None = None
    last_name: str | None = None
    status: str | None = "active"
    company: str | None = None
    company_id: str | None = None
    tenant_id: str | None = None
    image: str | None = None
    role_id: str | None = None
    role: str = Field(..., description="User role, e.g. company_admin, tele_agent")
    email: str | None = None
    phone: str | None = None
    email_verified: bool | None = False
    phone_verified: bool | None = False
    affiliate: str | None = None


# ---------------------------------------------------------------------------
# Update user
# ---------------------------------------------------------------------------

class UserUpdateRequest(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    phone: str | None = None
    image: str | None = None
    role_id: str | None = None
    role: str | None = None
    company: str | None = None
    company_id: str | None = None
    tenant_id: str | None = None
    status: str | None = None
    email_verified: bool | None = None
    phone_verified: bool | None = None
    affiliate: str | None = None
    username: str | None = None


# ---------------------------------------------------------------------------
# Status toggle
# ---------------------------------------------------------------------------

class UserStatusRequest(BaseModel):
    status: str = Field(..., description="New status: active | suspended | inactive")


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------

class ChangePasswordRequest(BaseModel):
    username: str
    new_password: str = Field(..., min_length=6)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    user_id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    phone: str | None = None
    role: str | None = None
    role_id: str | None = None
    company_id: str | None = None
    company: str | None = None
    tenant_id: str | None = None
    tenant_name: str | None = None
    image: str | None = None
    status: str | None = None
    affiliate: str | None = None
    first_login: bool | None = None
    is_internal: bool | None = None


# ---------------------------------------------------------------------------
# Select campaign
# ---------------------------------------------------------------------------

class SimplifiedLoginResponse(BaseModel):
    """Returned by login for roles that must select a campaign before full access."""

    user_id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    temporary_token: str
    enforce_campaign: bool
    first_login: bool = False


class SelectCampaignRequest(BaseModel):
    campaign_id: str = Field(..., min_length=1)


class SelectCampaignResponse(BaseModel):
    user_id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    phone: str | None = None
    role: str | None = None
    company_id: str | None = None
    company: str | None = None
    tenant_id: str | None = None
    tenant_name: str | None = None
    image: str | None = None
    status: str
    vendor_lead_code: str | None = None
    affiliate: str | None = None
    logo: str | None = None
    permissions: list[str] = Field(default_factory=list)
    is_internal: bool | None = None
    first_login: bool = False
    message: str = "Campaign selected successfully"
    access_token: str
    temporary_token: str | None = None
    enforce_campaign: bool
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------

class UserChangePasswordRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    new_password: str = Field(..., min_length=1)
    confirm_password: str = Field(..., min_length=1)


class UserChangePasswordResponse(BaseModel):
    message: str
    username: str | None = None


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class UserLogoutResponse(BaseModel):
    message: str = "Logout successful"
    login_id: str | None = None
    duration_ms: int | None = None
    duration_formatted: str | None = None


# ---------------------------------------------------------------------------
# List / pagination
# ---------------------------------------------------------------------------

class UserListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[UserResponse]
