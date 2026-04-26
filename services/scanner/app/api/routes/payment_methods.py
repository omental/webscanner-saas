from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db_session,
    require_authenticated_user,
    require_super_admin,
)
from app.core.encryption import EncryptionKeyMissingError
from app.models.payment_method import PaymentMethod
from app.models.user import User
from app.schemas.payment_method import PaymentMethodRead, PaymentMethodUpdate
from app.services.payment_method_service import (
    list_payment_methods,
    update_payment_method,
)

router = APIRouter(prefix="/payment-methods", tags=["payment-methods"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]
SuperAdmin = Annotated[User, Depends(require_super_admin)]


def _serialize_payment_method(payment_method: PaymentMethod) -> PaymentMethodRead:
    return PaymentMethodRead.model_validate(payment_method)


@router.get("", response_model=list[PaymentMethodRead])
async def list_payment_methods_endpoint(
    session: DbSession, current_user: CurrentUser
) -> list[PaymentMethodRead]:
    payment_methods = await list_payment_methods(session, current_user)
    return [_serialize_payment_method(payment_method) for payment_method in payment_methods]


@router.patch("/{payment_method_id}", response_model=PaymentMethodRead)
async def update_payment_method_endpoint(
    payment_method_id: int,
    payload: PaymentMethodUpdate,
    session: DbSession,
    _super_admin: SuperAdmin,
) -> PaymentMethodRead:
    try:
        payment_method = await update_payment_method(session, payment_method_id, payload)
    except EncryptionKeyMissingError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if payment_method is None:
        raise HTTPException(status_code=404, detail="Payment method not found")
    return _serialize_payment_method(payment_method)
