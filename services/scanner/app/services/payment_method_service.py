from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import encrypt_secret
from app.models.payment_method import PaymentMethod
from app.models.user import User
from app.schemas.payment_method import PaymentMethodUpdate

DEFAULT_PAYMENT_METHODS = (
    ("Stripe", "stripe"),
    ("PayPal", "paypal"),
    ("Bank Transfer", "bank_transfer"),
)


async def ensure_default_payment_methods(session: AsyncSession) -> None:
    for name, slug in DEFAULT_PAYMENT_METHODS:
        result = await session.execute(
            select(PaymentMethod).where(PaymentMethod.slug == slug)
        )
        if result.scalar_one_or_none() is None:
            session.add(
                PaymentMethod(
                    name=name,
                    slug=slug,
                    is_active=False,
                    mode="test",
                    webhook_url=(
                        f"/api/v1/webhooks/{slug}"
                        if slug in {"stripe", "paypal"}
                        else None
                    ),
                )
            )
    await session.commit()


async def list_payment_methods(
    session: AsyncSession, current_user: User
) -> list[PaymentMethod]:
    await ensure_default_payment_methods(session)
    query = select(PaymentMethod).order_by(PaymentMethod.id.asc())
    if current_user.role != "super_admin":
        query = query.where(PaymentMethod.is_active.is_(True))
    result = await session.execute(query)
    return list(result.scalars().all())


async def update_payment_method(
    session: AsyncSession, payment_method_id: int, payload: PaymentMethodUpdate
) -> PaymentMethod | None:
    result = await session.execute(
        select(PaymentMethod).where(PaymentMethod.id == payment_method_id)
    )
    payment_method = result.scalar_one_or_none()
    if payment_method is None:
        return None
    updates = payload.model_dump(exclude_unset=True)
    if "is_active" in updates:
        payment_method.is_active = updates["is_active"]
    if "mode" in updates:
        payment_method.mode = updates["mode"]
    if "description" in updates:
        payment_method.description = updates["description"]
    if "config_json" in updates:
        payment_method.config_json = updates["config_json"]
    if "public_key" in updates:
        payment_method.public_key = updates["public_key"]
    if "webhook_enabled" in updates:
        payment_method.webhook_enabled = updates["webhook_enabled"]

    if payment_method.slug in {"stripe", "paypal"}:
        payment_method.webhook_url = f"/api/v1/webhooks/{payment_method.slug}"

    if updates.get("clear_secret_key"):
        payment_method.encrypted_secret_key = None
    elif updates.get("secret_key"):
        payment_method.encrypted_secret_key = encrypt_secret(updates["secret_key"])

    if updates.get("clear_webhook_secret"):
        payment_method.encrypted_webhook_secret = None
    elif updates.get("webhook_secret"):
        payment_method.encrypted_webhook_secret = encrypt_secret(
            updates["webhook_secret"]
        )

    await session.commit()
    await session.refresh(payment_method)
    return payment_method


async def get_enabled_webhook_method(
    session: AsyncSession, slug: str
) -> PaymentMethod | None:
    result = await session.execute(
        select(PaymentMethod).where(PaymentMethod.slug == slug)
    )
    payment_method = result.scalar_one_or_none()
    if (
        payment_method is None
        or not payment_method.is_active
        or not payment_method.webhook_enabled
    ):
        return None
    return payment_method
