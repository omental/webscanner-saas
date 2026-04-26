from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class VulnAlias(Base):
    __tablename__ = "vuln_aliases"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    vuln_record_id: Mapped[int] = mapped_column(
        ForeignKey("vuln_records.id"), nullable=False
    )
    alias_type: Mapped[str] = mapped_column(String(50), nullable=False)
    alias_value: Mapped[str] = mapped_column(String(255), nullable=False)

    vuln_record = relationship("VulnRecord", back_populates="aliases")
