from fastapi import APIRouter

from app.api.routes import (
    auth_router,
    billing_router,
    health_router,
    invoices_router,
    organizations_router,
    packages_router,
    payment_methods_router,
    scan_reports_router,
    scans_router,
    targets_router,
    usage_router,
    users_router,
    webhooks_router,
)
from app.core.config import get_settings

settings = get_settings()

api_router = APIRouter(prefix=settings.api_v1_prefix)
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(billing_router)
api_router.include_router(organizations_router)
api_router.include_router(invoices_router)
api_router.include_router(packages_router)
api_router.include_router(payment_methods_router)
api_router.include_router(users_router)
api_router.include_router(targets_router)
api_router.include_router(scans_router)
api_router.include_router(scan_reports_router)
api_router.include_router(usage_router)
api_router.include_router(webhooks_router)
