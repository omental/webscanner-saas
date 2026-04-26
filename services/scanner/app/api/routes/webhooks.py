import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.services.payment_method_service import get_enabled_webhook_method

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
logger = logging.getLogger(__name__)


async def _handle_webhook(
    gateway: str, request: Request, session: DbSession
) -> dict[str, str]:
    payment_method = await get_enabled_webhook_method(session, gateway)
    if payment_method is None:
        raise HTTPException(status_code=400, detail="Webhook is not enabled")

    try:
        payload: Any = await request.json()
    except ValueError:
        payload = {}

    event_type = "unknown"
    if isinstance(payload, dict):
        raw_event_type = payload.get("type") or payload.get("event_type")
        if isinstance(raw_event_type, str):
            event_type = raw_event_type

    logger.info("%s webhook placeholder received event type: %s", gateway, event_type)
    return {"status": "success", "message": "Webhook placeholder accepted"}


@router.post("/stripe")
async def stripe_webhook(request: Request, session: DbSession) -> dict[str, str]:
    return await _handle_webhook("stripe", request, session)


@router.post("/paypal")
async def paypal_webhook(request: Request, session: DbSession) -> dict[str, str]:
    return await _handle_webhook("paypal", request, session)
