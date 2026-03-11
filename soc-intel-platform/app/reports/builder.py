"""
app/reports/builder.py
─────────────────────────────────────────────────────────────
Orquestador del sistema de generación de reportes.

Decide qué generador usar según el formato solicitado
y gestiona el guardado en la base de datos.
"""

from app.models.schemas import IOCEnrichmentResult, ReportRequest
from app.reports.pdf_generator import PDFReportGenerator
from app.reports.word_generator import WordReportGenerator
from app.reports.json_exporter import DataExporter
from app.utils.logger import logger


class ReportBuilder:
    """Orquesta la generación de reportes en cualquier formato."""

    def __init__(self):
        self.pdf_gen = PDFReportGenerator()
        self.word_gen = WordReportGenerator()
        self.exporter = DataExporter()

    async def build(
        self,
        investigation_id: str,
        title: str,
        analyst_name: str,
        ioc_results: list[IOCEnrichmentResult],
        overall_risk_level: str,
        overall_risk_score: int,
        format: str = "pdf",
        notes: str = "",
        client_name: str | None = None,
        include_raw_data: bool = False,
    ) -> str:
        """
        Genera un reporte en el formato especificado.
        
        Args:
            format: "pdf", "docx", "json", or "csv"
            
        Returns:
            Path absoluto del archivo generado
        """
        logger.info(f"Generando reporte [{format.upper()}] para investigación {investigation_id[:8]}")

        kwargs = {
            "investigation_id": investigation_id,
            "title": title,
            "analyst_name": analyst_name,
            "ioc_results": ioc_results,
            "overall_risk_level": overall_risk_level,
            "overall_risk_score": overall_risk_score,
        }

        if format == "pdf":
            return await self.pdf_gen.generate(
                **kwargs, notes=notes, client_name=client_name
            )
        elif format == "docx":
            return await self.word_gen.generate(
                **kwargs, notes=notes, client_name=client_name
            )
        elif format == "json":
            return await self.exporter.export_json(
                **kwargs, include_raw_data=include_raw_data
            )
        elif format == "csv":
            return await self.exporter.export_csv(
                investigation_id=investigation_id,
                ioc_results=ioc_results,
            )
        else:
            raise ValueError(f"Formato no soportado: {format}")
