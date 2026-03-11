"""
app/api/v1/reports.py
─────────────────────────────────────────────────────────────
Endpoints para generación y descarga de reportes.

Endpoints:
  POST /api/v1/reports              → Generar reporte
  GET  /api/v1/reports/{id}/download → Descargar reporte
"""

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.investigations import _db_iocs_to_results
from app.db.session import get_db
from app.db.repository import InvestigationRepository, ReportRepository
from app.models.schemas import ReportRequest, ReportResponse
from app.reports.builder import ReportBuilder
from app.utils.logger import logger

router = APIRouter(prefix="/reports", tags=["Reports"])

CONTENT_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "json": "application/json",
    "csv": "text/csv",
}


@router.post(
    "/",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generar reporte de incidente",
)
async def generate_report(
    request: ReportRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Genera un reporte de incidente a partir de una investigación existente.
    Formatos disponibles: pdf, docx, json, csv
    """
    inv_repo = InvestigationRepository(db)
    report_repo = ReportRepository(db)

    # ─── Verificar que la investigación existe ─────────────────
    investigation = await inv_repo.get_by_id(str(request.investigation_id))
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigación {request.investigation_id} no encontrada",
        )

    # ─── Reconstruir resultados de IOCs ────────────────────────
    ioc_results = _db_iocs_to_results(investigation.iocs)

    if not ioc_results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La investigación no tiene IOCs procesados",
        )

    # ─── Generar el reporte ────────────────────────────────────
    builder = ReportBuilder()
    try:
        file_path = await builder.build(
            investigation_id=investigation.id,
            title=request.custom_title or investigation.title,
            analyst_name=investigation.analyst_name,
            ioc_results=ioc_results,
            overall_risk_level=investigation.overall_risk_level or "info",
            overall_risk_score=investigation.overall_risk_score or 0,
            format=request.format,
            notes=investigation.notes or "",
            client_name=request.client_name,
            include_raw_data=request.include_raw_data,
        )
    except Exception as e:
        logger.error(f"Error generando reporte: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generando reporte: {str(e)}",
        )

    # ─── Guardar metadata del reporte en DB ───────────────────
    report = await report_repo.create(
        investigation_id=investigation.id,
        format=request.format,
        file_path=file_path,
        client_name=request.client_name,
    )
    await db.commit()

    filename = Path(file_path).name
    download_url = f"/api/v1/reports/{report.id}/download"

    return ReportResponse(
        id=report.id,
        investigation_id=report.investigation_id,
        format=report.format,
        file_path=file_path,
        download_url=download_url,
        created_at=report.created_at,
    )


@router.get(
    "/{report_id}/download",
    summary="Descargar reporte generado",
)
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Descarga un reporte previamente generado."""
    repo = ReportRepository(db)
    report = await repo.get_by_id(str(report_id))

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte {report_id} no encontrado",
        )

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Archivo de reporte no encontrado en disco",
        )

    content_type = CONTENT_TYPES.get(report.format, "application/octet-stream")

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=file_path.name,
    )
