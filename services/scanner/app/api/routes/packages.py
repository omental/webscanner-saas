from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, require_super_admin
from app.models.package import Package
from app.models.user import User
from app.schemas.package import PackageRead, PackageUpdate
from app.services.package_service import list_packages, update_package

router = APIRouter(prefix="/packages", tags=["packages"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
SuperAdmin = Annotated[User, Depends(require_super_admin)]


def _serialize_package(package: Package) -> PackageRead:
    return PackageRead.model_validate(package)


@router.get("", response_model=list[PackageRead])
async def list_packages_endpoint(session: DbSession) -> list[PackageRead]:
    packages = await list_packages(session)
    return [_serialize_package(package) for package in packages]


@router.patch("/{package_id}", response_model=PackageRead)
async def update_package_endpoint(
    package_id: int,
    payload: PackageUpdate,
    session: DbSession,
    _super_admin: SuperAdmin,
) -> PackageRead:
    package = await update_package(session, package_id, payload)
    return _serialize_package(package)
