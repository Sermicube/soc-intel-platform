"""
app/api/v1/investigations.py
─────────────────────────────────────────────────────────────
Endpoints para la gestión de investigaciones de IOCs.

Endpoints:
  POST /api/v1/investigations       → Crear y ejecutar investigación
  GET  /api/v1/investigations       → Listar investigaciones
  GET  /api/v1/investigations/{id}  → Detalle de investigación
  DELETE /api/v1/investigations/{id} → Eliminar investigación
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enrichment_engine import EnrichmentEngine
from app.core.risk_scorer import RiskScorer
from app.db.session import get_db
from app.db.repository import InvestigationRepository, IOCResultRepository
from app.models.schemas import (
    InvestigationRequest, InvestigationResponse, InvestigationSummary,
    InvestigationStatus, IOCEnrichmentResult, RiskLevel
)
from app.utils.logger import logger

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.post(
    "/",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear nueva investigación",
    description="Inicia una investigación de uno o más IOCs consultando múltiples fuentes de inteligencia.",
)
async def create_investigation(
    request: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Flujo completo:
    1. Crea registro en DB con estado PENDING
    2. Enriquece todos los IOCs en paralelo
    3. Calcula score global
    4. Actualiza estado a COMPLETED
    5. Retorna resultado completo
    """
    inv_repo = InvestigationRepository(db)
    ioc_repo = IOCResultRepository(db)
    engine = EnrichmentEngine()

    # ─── 1. Crear investigación ────────────────────────────────
    investigation = await inv_repo.create(request)
    await inv_repo.update_status(investigation, InvestigationStatus.IN_PROGRESS)
    await db.flush()

    try:
        # ─── 2. Enriquecer IOCs ────────────────────────────────
        ioc_values = [ioc.value for ioc in request.iocs]
        logger.info(f"Iniciando análisis de {len(ioc_values)} IOCs")

        enriched_results = await engine.enrich_batch(ioc_values)

        # ─── 3. Guardar resultados en DB ───────────────────────
        for result in enriched_results:
            await ioc_repo.save_enrichment_result(
                investigation_id=investigation.id,
                result=result,
            )

        # ─── 4. Calcular score global ──────────────────────────
        individual_scores = [r.risk_score for r in enriched_results]
        overall_score, overall_level = RiskScorer.calculate_overall(individual_scores)

        # ─── 5. Actualizar investigación ───────────────────────
        await inv_repo.update_status(
            investigation,
            InvestigationStatus.COMPLETED,
            risk_score=overall_score,
            risk_level=overall_level.value,
        )
        await db.commit()

        # ─── 6. Refrescar y retornar ───────────────────────────
        await db.refresh(investigation)
        investigation_fresh = await inv_repo.get_by_id(investigation.id)

        return _build_response(investigation_fresh, enriched_results)

    except Exception as e:
        logger.error(f"Error en investigación {investigation.id}: {e}")
        await inv_repo.update_status(investigation, InvestigationStatus.ERROR)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error durante el análisis: {str(e)}",
        )


@router.get(
    "/",
    response_model=list[InvestigationSummary],
    summary="Listar investigaciones",
)
async def list_investigations(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Lista todas las investigaciones ordenadas por fecha (más recientes primero)."""
    repo = InvestigationRepository(db)
    investigations = await repo.list_all(limit=limit, offset=offset)

    return [
        InvestigationSummary(
            id=inv.id,
            title=inv.title,
            analyst_name=inv.analyst_name,
            status=inv.status,
            overall_risk_level=inv.overall_risk_level or "info",
            ioc_count=len(inv.iocs),
            created_at=inv.created_at,
        )
        for inv in investigations
    ]


@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
    summary="Detalle de investigación",
)
async def get_investigation(
    investigation_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Obtiene el detalle completo de una investigación con todos sus IOCs."""
    repo = InvestigationRepository(db)
    investigation = await repo.get_by_id(str(investigation_id))

    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigación {investigation_id} no encontrada",
        )

    # Reconstruir resultados desde DB
    enriched_results = _db_iocs_to_results(investigation.iocs)
    return _build_response(investigation, enriched_results)


@router.delete(
    "/{investigation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar investigación",
)
async def delete_investigation(
    investigation_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Elimina una investigación y todos sus datos asociados."""
    repo = InvestigationRepository(db)
    deleted = await repo.delete(str(investigation_id))

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigación {investigation_id} no encontrada",
        )


# ─── Helpers ──────────────────────────────────────────────────

def _build_response(investigation, enriched_results: list[IOCEnrichmentResult]) -> InvestigationResponse:
    """Construye el InvestigationResponse desde el modelo ORM."""
    return InvestigationResponse(
        id=investigation.id,
        title=investigation.title,
        analyst_name=investigation.analyst_name,
        status=investigation.status,
        overall_risk_score=investigation.overall_risk_score or 0,
        overall_risk_level=investigation.overall_risk_level or "info",
        ioc_results=enriched_results,
        notes=investigation.notes or "",
        created_at=investigation.created_at,
        updated_at=investigation.updated_at or investigation.created_at,
    )


def _db_iocs_to_results(db_iocs) -> list[IOCEnrichmentResult]:
    """Reconstruye IOCEnrichmentResult desde modelos ORM de DB."""
    from app.models.schemas import (
        IOCType, RiskLevel, VirusTotalResult, AbuseIPDBResult, ShodanResult
    )
    from datetime import datetime

    results = []
    for ioc in db_iocs:
        vt = None
        if ioc.virustotal_data:
            try:
                vt = VirusTotalResult(**ioc.virustotal_data)
            except Exception:
                pass

        abuse = None
        if ioc.abuseipdb_data:
            try:
                abuse = AbuseIPDBResult(**ioc.abuseipdb_data)
            except Exception:
                pass

        shodan = None
        if ioc.shodan_data:
            try:
                shodan = ShodanResult(**ioc.shodan_data)
            except Exception:
                pass

        try:
            ioc_type = IOCType(ioc.ioc_type)
        except ValueError:
            ioc_type = IOCType.UNKNOWN

        try:
            risk_level = RiskLevel(ioc.risk_level)
        except ValueError:
            risk_level = RiskLevel.INFO

        results.append(IOCEnrichmentResult(
            ioc_value=ioc.ioc_value,
            ioc_type=ioc_type,
            risk_score=ioc.risk_score or 0,
            risk_level=risk_level,
            virustotal=vt,
            abuseipdb=abuse,
            shodan=shodan,
            summary=ioc.summary or "",
            tags=ioc.tags or [],
            enriched_at=ioc.created_at or datetime.utcnow(),
        ))

    return results
