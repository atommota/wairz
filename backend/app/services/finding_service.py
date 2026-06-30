import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.schemas.finding import FindingCreate, FindingUpdate


class FindingService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _resolve_firmware(
        self,
        project_id: uuid.UUID,
        firmware_ids: list[uuid.UUID] | None,
    ) -> list[Firmware]:
        """Resolve firmware ids to Firmware rows within the project.

        When ``firmware_ids`` is empty/None, defaults to the project's
        latest-uploaded firmware (so every finding gets at least one version
        tag). Ids that don't belong to the project are silently ignored.
        """
        if firmware_ids:
            result = await self.db.execute(
                select(Firmware).where(
                    Firmware.project_id == project_id,
                    Firmware.id.in_(firmware_ids),
                )
            )
            return list(result.scalars().all())

        # Default: latest firmware in the project, if any exists.
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at.desc())
            .limit(1)
        )
        latest = result.scalar_one_or_none()
        return [latest] if latest is not None else []

    async def create(
        self,
        project_id: uuid.UUID,
        data: FindingCreate,
    ) -> Finding:
        finding = Finding(
            project_id=project_id,
            conversation_id=data.conversation_id,
            title=data.title,
            severity=data.severity.value,
            description=data.description,
            evidence=data.evidence,
            file_path=data.file_path,
            line_number=data.line_number,
            cve_ids=data.cve_ids,
            cwe_ids=data.cwe_ids,
            source=data.source,
            component_id=data.component_id,
        )
        finding.firmware_versions = await self._resolve_firmware(
            project_id, data.firmware_ids
        )
        self.db.add(finding)
        await self.db.flush()
        return finding

    async def list_by_project(
        self,
        project_id: uuid.UUID,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        firmware_id: uuid.UUID | None = None,
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.project_id == project_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if source:
            stmt = stmt.where(Finding.source == source)
        if firmware_id:
            stmt = stmt.where(
                Finding.firmware_versions.any(Firmware.id == firmware_id)
            )
        stmt = stmt.order_by(Finding.created_at.desc())
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def update(self, finding_id: uuid.UUID, data: FindingUpdate) -> Finding | None:
        finding = await self.get(finding_id)
        if finding is None:
            return None
        update_data = data.model_dump(exclude_unset=True)
        # firmware_ids is handled separately as an association, not a column.
        firmware_ids = update_data.pop("firmware_ids", None)
        if "firmware_ids" in data.model_fields_set:
            finding.firmware_versions = await self._resolve_firmware(
                finding.project_id, firmware_ids
            )
        # Convert enum values to strings
        for key, value in update_data.items():
            if hasattr(value, "value"):
                value = value.value
            setattr(finding, key, value)
        await self.db.flush()
        # Re-load through a fresh query so the selectin relationship
        # (firmware_versions) is eagerly populated for serialization.
        self.db.expire(finding)
        return await self.get(finding_id)

    async def delete(self, finding_id: uuid.UUID) -> bool:
        finding = await self.get(finding_id)
        if finding is None:
            return False
        await self.db.delete(finding)
        await self.db.flush()
        return True
