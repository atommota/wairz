import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Column, ForeignKey, Integer, String, Table, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# Association table linking findings to the firmware version(s) they affect.
# A finding may apply to multiple versions (e.g. a vuln still present after an
# update), and a version may have many findings — hence many-to-many.
finding_firmware = Table(
    "finding_firmware",
    Base.metadata,
    Column(
        "finding_id",
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "firmware_id",
        ForeignKey("firmware.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String(512))
    line_number: Mapped[int | None] = mapped_column(Integer)
    cve_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    status: Mapped[str] = mapped_column(String(20), default="open", server_default="open")
    source: Mapped[str] = mapped_column(String(50), default="manual", server_default="manual")
    component_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    project: Mapped["Project"] = relationship(back_populates="findings")  # noqa: F821
    firmware_versions: Mapped[list["Firmware"]] = relationship(  # noqa: F821
        secondary=finding_firmware,
        lazy="selectin",
        order_by="Firmware.created_at",
    )
