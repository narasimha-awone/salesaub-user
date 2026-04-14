"""
User service.

Encapsulates all business logic for user management.
Routes delegate to this class instead of calling repositories directly.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from saleshub_core.repositories.user import (
    check_email_exists,
    check_email_exists_excluding,
    check_phone_exists,
    check_phone_variations_excluding,
    check_username_exists,
    check_username_exists_excluding,
    count_other_company_admins,
    execute_count_users,
    execute_list_users,
    get_user_by_id,
    get_user_by_username,
    get_user_for_delete,
    get_user_for_suspend,
    get_user_permissions,
    insert_user,
    soft_delete_user,
    update_user_fields,
    update_user_password,
    update_user_status,
)

from app.schemas.user import (
    ChangePasswordRequest,
    UserCreateRequest,
    UserListResponse,
    UserPermissionsResponse,
    UserResponse,
    UserUpdateRequest,
)


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_user(row: Any) -> UserResponse:
        return UserResponse(
            user_id=str(row["user_id"]),
            user_num=row.get("user_num"),
            username=row["username"],
            first_name=row.get("first_name"),
            last_name=row.get("last_name"),
            created_time=row.get("created_time"),
            status=row.get("status"),
            company=row.get("company"),
            company_id=str(row["company_id"]) if row.get("company_id") else None,
            tenant_id=str(row["tenant_id"]) if row.get("tenant_id") else None,
            tenant_name=row.get("tenant_name"),
            image=row.get("image"),
            role_id=str(row["role_id"]) if row.get("role_id") else None,
            role=row.get("role"),
            email=row.get("email"),
            phone=row.get("phone"),
            email_verified=row.get("email_verified"),
            phone_verified=row.get("phone_verified"),
            email_last_verified=row.get("email_last_verified"),
            phone_last_verified=row.get("phone_last_verified"),
            affiliate=row.get("affiliate"),
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    async def get_user(self, user_id: str) -> UserResponse:
        row = await get_user_by_id(self._session, user_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        return self._row_to_user(row)

    async def list_users(
        self,
        company_id: str | None,
        role: str | None,
        search: str | None,
        status_filter: str | None,
        page: int,
        page_size: int,
    ) -> UserListResponse:
        conditions = ["u.del_flg = false"]
        params: dict[str, Any] = {}

        if company_id:
            conditions.append("u.company_id = :company_id")
            params["company_id"] = company_id

        if role:
            conditions.append("LOWER(u.role) = LOWER(:role)")
            params["role"] = role

        if status_filter:
            conditions.append("u.status = :status")
            params["status"] = status_filter

        if search:
            conditions.append(
                "(u.username ILIKE :search OR u.first_name ILIKE :search "
                "OR u.last_name ILIKE :search OR u.email ILIKE :search "
                "OR u.phone ILIKE :search)"
            )
            params["search"] = f"%{search}%"

        where_clause = " AND ".join(conditions)
        offset = (page - 1) * page_size

        select_query = f"""
            SELECT
                u.user_id, u.user_num, u.username, u.first_name, u.last_name,
                u.created_time, u.status, u.company, u.company_id, u.tenant_id,
                t.tenant_name, u.image, u.role_id, u.role, u.email, u.phone,
                u.email_verified, u.phone_verified, u.email_last_verified,
                u.phone_last_verified, u.affiliate
            FROM users u
            LEFT JOIN tenant t ON u.tenant_id = t.tenant_id
            WHERE {where_clause}
            ORDER BY u.user_num
            LIMIT :limit OFFSET :offset
        """
        count_query = f"SELECT COUNT(*) AS total FROM users u WHERE {where_clause}"

        params["limit"] = page_size
        params["offset"] = offset
        count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}

        rows = await execute_list_users(self._session, select_query, params)
        count_row = await execute_count_users(self._session, count_query, count_params)

        return UserListResponse(
            total=count_row["total"],
            page=page,
            page_size=page_size,
            items=[self._row_to_user(r) for r in rows],
        )

    async def get_permissions(self, user_id: str) -> UserPermissionsResponse:
        rows = await get_user_permissions(self._session, user_id)
        return UserPermissionsResponse(
            user_id=user_id,
            permissions=[r["permission_name"] for r in rows],
        )

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    async def create_user(self, body: UserCreateRequest) -> UserResponse:
        normalized_username = body.username.lower().strip()

        if await check_username_exists(self._session, normalized_username):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{body.username}' is already taken.",
            )
        if body.email and await check_email_exists(self._session, body.email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email '{body.email}' is already registered.",
            )
        if body.phone and await check_phone_exists(self._session, body.phone):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Phone '{body.phone}' is already registered.",
            )

        row = await insert_user(
            self._session,
            username=normalized_username,
            password=f"crypt('{body.password}', gen_salt('bf'))",
            first_name=body.first_name,
            last_name=body.last_name,
            created_time=int(time.time()),
            status=body.status,
            company=body.company,
            company_id=body.company_id,
            tenant_id=body.tenant_id,
            image=body.image,
            role_id=body.role_id,
            role=body.role,
            email=body.email,
            phone=body.phone,
            email_verified=body.email_verified,
            phone_verified=body.phone_verified,
            email_last_verified=None,
            phone_last_verified=None,
            affiliate=body.affiliate,
        )
        await self._session.commit()
        return self._row_to_user(row)

    async def update_user(self, user_id: str, body: UserUpdateRequest) -> UserResponse:
        update_data = body.model_dump(exclude_none=True)
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No fields provided to update.",
            )

        if "username" in update_data:
            if await check_username_exists_excluding(self._session, update_data["username"], user_id):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Username '{update_data['username']}' is already taken.",
                )
        if "email" in update_data:
            if await check_email_exists_excluding(self._session, update_data["email"], user_id):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Email '{update_data['email']}' is already registered.",
                )
        if "phone" in update_data:
            if await check_phone_variations_excluding(self._session, [update_data["phone"]], user_id):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Phone '{update_data['phone']}' is already registered.",
                )

        update_fields = [f"{col} = :{col}" for col in update_data]
        params = {**update_data, "user_id": user_id}
        await update_user_fields(self._session, update_fields, params)
        await self._session.commit()

        row = await get_user_by_id(self._session, user_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        return self._row_to_user(row)

    async def suspend_user(self, user_id: str) -> UserResponse:
        row = await get_user_for_suspend(self._session, user_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        if row["status"] == "suspended":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already suspended.",
            )
        if row["role"].lower() in ("company_admin", "company admin"):
            count_row = await count_other_company_admins(self._session, row["company_id"], user_id)
            if count_row and count_row["remaining_count"] == 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot suspend the last company admin.",
                )

        await update_user_status(self._session, user_id, "suspended")
        await self._session.commit()

        updated = await get_user_by_id(self._session, user_id)
        return self._row_to_user(updated)

    async def unsuspend_user(self, user_id: str) -> UserResponse:
        row = await get_user_for_suspend(self._session, user_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        if row["status"] != "suspended":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is not suspended.",
            )

        await update_user_status(self._session, user_id, "active")
        await self._session.commit()

        updated = await get_user_by_id(self._session, user_id)
        return self._row_to_user(updated)

    async def set_user_status(self, user_id: str, new_status: str) -> UserResponse:
        row = await get_user_for_suspend(self._session, user_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        await update_user_status(self._session, user_id, new_status)
        await self._session.commit()

        updated = await get_user_by_id(self._session, user_id)
        return self._row_to_user(updated)

    async def change_password(self, user_id: str, body: ChangePasswordRequest) -> None:
        row = await get_user_by_username(self._session, body.username)
        if row is None or str(row["user_id"]) != user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        await update_user_password(self._session, user_id, f"crypt('{body.new_password}', gen_salt('bf'))")
        await self._session.commit()

    async def delete_user(self, user_id: str) -> None:
        row = await get_user_for_delete(self._session, user_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        if row["role"].lower() in ("company_admin", "company admin"):
            count_row = await count_other_company_admins(self._session, row["company_id"], user_id)
            if count_row and count_row["remaining_count"] == 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot delete the last company admin.",
                )

        await soft_delete_user(self._session, user_id)
        await self._session.commit()
