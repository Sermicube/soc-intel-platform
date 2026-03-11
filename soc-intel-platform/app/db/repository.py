"""
app/db/repository.py
─────────────────────────────────────────────────────────────
Patrón Repository: abstrae todas las operaciones de DB.

Ventajas:
  - La lógica de negocio no conoce SQL
  - Fácil de testear (mockear el repository)
  - Un solo lugar para cambiar queries
"""

import json
from uuid import UUID

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.database import Investigation, IOCResult, Report
from app.models.schemas import (
    InvestigationRequest, IOCEnrichmentResult, InvestigationStatus
)
from app.utils.logger import logger


class InvestigationRepository:
    """Repository para operaciones CRUD de investigaciones."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, request: InvestigationRequest) -> Investigation:
        """Crea una nueva investigación en estado PENDING."""
        investigation = Investigation(
            title=request.title,
            analyst_name=request.analyst_name,
            notes=request.notes,
            status=InvestigationStatus.PENDING,
        )
        self.db.add(investigation)
        await self.db.flush()  # Obtiene el ID sin commit
        logger.info(f"Investigación creada: {investigation.id}")
        return investigation

    async def get_by_id(self, investigation_id: str) -> Investigation | None:
        """Obtiene una investigación con todos sus IOCs y reportes."""
        result = await self.db.execute(
            select(Investigation)
            .options(
                selectinload(Investigation.iocs),
                selectinload(Investigation.reports),
            )
            .where(Investigation.id == str(investigation_id))
        )
        return result.scalar_one_or_none()

    async def list_all(self, limit: int = 50, offset: int = 0) -> list[Investigation]:
        """Lista investigaciones ordenadas por fecha (más recientes primero)."""
        result = await self.db.execute(
            select(Investigation)
            .options(selectinload(Investigation.iocs))
            .order_by(desc(Investigation.created_at))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def update_status(
        self,
        investigation: Investigation,
        status: InvestigationStatus,
        risk_score: int = 0,
        risk_level: str = "info",
    ) -> Investigation:
        """Actualiza el estado y score de riesgo de una investigación."""
        investigation.status = status
        investigation.overall_risk_score = risk_score
        investigation.overall_risk_level = risk_level
        await self.db.flush()
        return investigation

    async def delete(self, investigation_id: str) -> bool:
        """Elimina una investigación y todos sus datos relacionados."""
        investigation = await self.get_by_id(investigation_id)
        if not investigation:
            return False
        await self.db.delete(investigation)
        logger.info(f"Investigación eliminada: {investigation_id}")
        return True


class IOCResultRepository:
    """Repository para resultados de enriquecimiento de IOCs."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def save_enrichment_result(
        self,
        investigation_id: str,
        result: IOCEnrichmentResult,
    ) -> IOCResult:
        """Guarda el resultado de enriquecimiento de un IOC."""
        ioc_result = IOCResult(
            investigation_id=investigation_id,
            ioc_value=result.ioc_value,
            ioc_type=result.ioc_type.value,
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            summary=result.summary,
            tags=result.tags,
            virustotal_data=result.virustotal.model_dump() if result.virustotal else None,
            abuseipdb_data=result.abuseipdb.model_dump() if result.abuseipdb else None,
            shodan_data=result.shodan.model_dump() if result.shodan else None,
        )
        self.db.add(ioc_result)
        await self.db.flush()
        return ioc_result


class ReportRepository:
    """Repository para reportes generados."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        investigation_id: str,
        format: str,
        file_path: str,
        executive_summary: str = "",
        technical_description: str = "",
        risk_assessment: str = "",
        recommendations: str = "",
        client_name: str | None = None,
    ) -> Report:
        """Guarda metadata de un reporte generado."""
        report = Report(
            investigation_id=investigation_id,
            format=format,
            file_path=file_path,
            executive_summary=executive_summary,
            technical_description=technical_description,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            client_name=client_name,
        )
        self.db.add(report)
        await self.db.flush()
        logger.info(f"Reporte guardado: {report.id} [{format}]")
        return report

    async def get_by_id(self, report_id: str) -> Report | None:
        result = await self.db.execute(
            select(Report).where(Report.id == str(report_id))
        )
        return result.scalar_one_or_none()
