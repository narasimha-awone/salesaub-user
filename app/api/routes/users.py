"""
User management routes.

All write endpoints require a valid JWT (Depends(require_auth)).
Role-restricted endpoints use require_roles().
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import TokenPayload, get_user_service, require_auth, require_roles
from app.schemas.user import (
    ChangePasswordRequest,
    UserCreateRequest,
    UserListResponse,
    UserPermissionsResponse,
    UserResponse,
    UserStatusRequest,
    UserUpdateRequest,
)
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])

_ADMIN_ROLES = ("company_admin", "super_admin")


# ---------------------------------------------------------------------------
# GET /users/{user_id}
# ---------------------------------------------------------------------------

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_auth),
) -> UserResponse:
    """Return a full user profile joined with tenant."""
    return await svc.get_user(user_id)


# ---------------------------------------------------------------------------
# GET /users
# ---------------------------------------------------------------------------

@router.get("", response_model=UserListResponse)
async def list_users(
    company_id: str | None = Query(None),
    role: str | None = Query(None),
    search: str | None = Query(None, description="Search by username, first_name, last_name, email, or phone"),
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_auth),
) -> UserListResponse:
    """
    List users with optional filters.

    - **company_id**: filter by company
    - **role**: filter by role (case-insensitive)
    - **search**: partial match on username / name / email / phone
    - **status**: filter by status (active, suspended, inactive)
    """
    return await svc.list_users(
        company_id=company_id,
        role=role,
        search=search,
        status_filter=status_filter,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# POST /users
# ---------------------------------------------------------------------------

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_roles(*_ADMIN_ROLES)),
) -> UserResponse:
    """
    Create a new user.

    - Validates username, email, and phone uniqueness before inserting.
    - Password is stored as a pgcrypto hash via ``crypt(:password, gen_salt('bf'))``.
    - Requires **company_admin** or **super_admin** role.
    """
    return await svc.create_user(body)


# ---------------------------------------------------------------------------
# PATCH /users/{user_id}
# ---------------------------------------------------------------------------

@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_auth),
) -> UserResponse:
    """
    Partially update a user's profile fields.

    Only non-None fields in the request body are applied.
    Uniqueness is re-checked for username, email, and phone when provided.
    """
    return await svc.update_user(user_id, body)


# ---------------------------------------------------------------------------
# POST /users/{user_id}/suspend  &  POST /users/{user_id}/unsuspend
# ---------------------------------------------------------------------------

@router.post("/{user_id}/suspend", response_model=UserResponse)
async def suspend_user(
    user_id: str,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_roles(*_ADMIN_ROLES)),
) -> UserResponse:
    """Suspend a user account. Requires admin role."""
    return await svc.suspend_user(user_id)


@router.post("/{user_id}/unsuspend", response_model=UserResponse)
async def unsuspend_user(
    user_id: str,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_roles(*_ADMIN_ROLES)),
) -> UserResponse:
    """Restore a suspended user account. Requires admin role."""
    return await svc.unsuspend_user(user_id)


# ---------------------------------------------------------------------------
# PATCH /users/{user_id}/status  (generic status update)
# ---------------------------------------------------------------------------

@router.patch("/{user_id}/status", response_model=UserResponse)
async def set_user_status(
    user_id: str,
    body: UserStatusRequest,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_roles(*_ADMIN_ROLES)),
) -> UserResponse:
    """Set an arbitrary status on a user (active, suspended, inactive)."""
    return await svc.set_user_status(user_id, body.status)


# ---------------------------------------------------------------------------
# PATCH /users/{user_id}/password
# ---------------------------------------------------------------------------

@router.patch("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    user_id: str,
    body: ChangePasswordRequest,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_auth),
) -> None:
    """
    Change a user's password.

    Looks up the user by username to verify it belongs to the given user_id,
    then stores the new password hash via pgcrypto.
    """
    await svc.change_password(user_id, body)


# ---------------------------------------------------------------------------
# DELETE /users/{user_id}
# ---------------------------------------------------------------------------

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_roles(*_ADMIN_ROLES)),
) -> None:
    """
    Soft-delete a user (sets ``del_flg = true``).

    Prevents deleting the last company admin.
    Requires **company_admin** or **super_admin** role.
    """
    await svc.delete_user(user_id)


# ---------------------------------------------------------------------------
# GET /users/{user_id}/permissions
# ---------------------------------------------------------------------------

@router.get("/{user_id}/permissions", response_model=UserPermissionsResponse)
async def get_permissions(
    user_id: str,
    svc: UserService = Depends(get_user_service),
    _: TokenPayload = Depends(require_auth),
) -> UserPermissionsResponse:
    """Return all permission names for a user via their assigned role."""
    return await svc.get_permissions(user_id)
