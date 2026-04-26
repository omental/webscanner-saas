from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class VulnAffectedProduct(Base):
    __tablename__ = "vuln_affected_products"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    vuln_record_id: Mapped[int] = mapped_column(
        ForeignKey("vuln_records.id"), nullable=False
    )
    product_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(100), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version_exact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version_start: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version_end: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    vuln_record = relationship("VulnRecord", back_populates="affected_products")
