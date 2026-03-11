"""
app/reports/pdf_generator.py
─────────────────────────────────────────────────────────────
Generador de reportes PDF usando ReportLab.

Genera un PDF profesional con:
  - Portada con logo y metadata
  - Resumen ejecutivo
  - Descripción técnica
  - Tabla de IOCs con color por nivel de riesgo
  - Evaluación de riesgo
  - Acciones recomendadas
"""

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak,
)
from reportlab.platypus.flowables import HRFlowable

from app.config import get_settings
from app.models.schemas import IOCEnrichmentResult, RiskLevel
from app.utils.logger import logger

# ─── Colores corporativos ─────────────────────────────────────
COLOR_DARK = colors.HexColor("#0D1117")
COLOR_PRIMARY = colors.HexColor("#00D4AA")
COLOR_SECONDARY = colors.HexColor("#1E3A5F")
COLOR_CRITICAL = colors.HexColor("#FF4444")
COLOR_HIGH = colors.HexColor("#FF8800")
COLOR_MEDIUM = colors.HexColor("#FFCC00")
COLOR_LOW = colors.HexColor("#44BB44")
COLOR_INFO = colors.HexColor("#4488FF")
COLOR_LIGHT_GRAY = colors.HexColor("#F5F5F5")
COLOR_BORDER = colors.HexColor("#E0E0E0")

RISK_COLORS = {
    RiskLevel.CRITICAL: COLOR_CRITICAL,
    RiskLevel.HIGH: COLOR_HIGH,
    RiskLevel.MEDIUM: COLOR_MEDIUM,
    RiskLevel.LOW: COLOR_LOW,
    RiskLevel.INFO: COLOR_INFO,
}


def get_risk_color(level: str) -> colors.Color:
    try:
        return RISK_COLORS.get(RiskLevel(level), COLOR_INFO)
    except ValueError:
        return COLOR_INFO


class PDFReportGenerator:
    """Genera reportes de incidentes en formato PDF."""

    def __init__(self):
        self.settings = get_settings()
        self.styles = self._build_styles()

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()
        return {
            "title": ParagraphStyle(
                "ReportTitle",
                parent=base["Title"],
                fontSize=24,
                textColor=COLOR_DARK,
                spaceAfter=6,
                fontName="Helvetica-Bold",
            ),
            "subtitle": ParagraphStyle(
                "ReportSubtitle",
                parent=base["Normal"],
                fontSize=11,
                textColor=colors.HexColor("#666666"),
                spaceAfter=4,
                fontName="Helvetica",
            ),
            "section_header": ParagraphStyle(
                "SectionHeader",
                parent=base["Heading1"],
                fontSize=14,
                textColor=COLOR_SECONDARY,
                spaceBefore=16,
                spaceAfter=8,
                fontName="Helvetica-Bold",
                borderPad=4,
            ),
            "body": ParagraphStyle(
                "BodyText",
                parent=base["Normal"],
                fontSize=10,
                leading=16,
                textColor=COLOR_DARK,
                spaceAfter=6,
                fontName="Helvetica",
                alignment=TA_JUSTIFY,
            ),
            "code": ParagraphStyle(
                "CodeText",
                parent=base["Code"],
                fontSize=9,
                fontName="Courier",
                textColor=COLOR_SECONDARY,
                backColor=COLOR_LIGHT_GRAY,
                leftIndent=8,
                rightIndent=8,
            ),
            "caption": ParagraphStyle(
                "Caption",
                parent=base["Normal"],
                fontSize=8,
                textColor=colors.HexColor("#888888"),
                fontName="Helvetica-Oblique",
            ),
        }

    async def generate(
        self,
        investigation_id: str,
        title: str,
        analyst_name: str,
        ioc_results: list[IOCEnrichmentResult],
        overall_risk_level: str,
        overall_risk_score: int,
        notes: str = "",
        client_name: str | None = None,
    ) -> str:
        """
        Genera el PDF y lo guarda en disco.
        
        Returns:
            Path absoluto del archivo PDF generado
        """
        output_dir = self.settings.reports_path
        filename = f"incident_report_{investigation_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = output_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=2.5 * cm,
            leftMargin=2.5 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm,
        )

        story = []

        # ─── Construcción del documento ────────────────────────
        self._add_header(story, title, analyst_name, overall_risk_level, overall_risk_score, client_name)
        self._add_executive_summary(story, ioc_results, overall_risk_level, overall_risk_score)
        self._add_ioc_table(story, ioc_results)
        self._add_technical_details(story, ioc_results)
        self._add_risk_assessment(story, ioc_results, overall_risk_level)
        self._add_recommendations(story, ioc_results, overall_risk_level)

        if notes:
            self._add_notes(story, notes)

        self._add_footer_info(story, analyst_name)

        doc.build(story)
        logger.info(f"PDF generado: {filepath}")
        return str(filepath)

    def _add_header(self, story, title, analyst_name, risk_level, risk_score, client_name):
        """Portada del reporte."""
        story.append(Spacer(1, 1 * cm))

        # Badge de clasificación
        classification_text = "🔒 CONFIDENCIAL — USO INTERNO SOC"
        story.append(Paragraph(classification_text, self.styles["caption"]))
        story.append(Spacer(1, 0.5 * cm))

        # Título principal
        story.append(Paragraph("REPORTE DE INCIDENTE DE SEGURIDAD", self.styles["title"]))
        story.append(Paragraph(title, self.styles["subtitle"]))
        story.append(Spacer(1, 0.3 * cm))

        # Línea decorativa con color de riesgo
        risk_color = get_risk_color(risk_level)
        story.append(HRFlowable(width="100%", thickness=3, color=risk_color))
        story.append(Spacer(1, 0.5 * cm))

        # Metadata del reporte
        now = datetime.now().strftime("%d/%m/%Y %H:%M UTC")
        meta_data = [
            ["Fecha:", now, "Analista:", analyst_name],
            ["Nivel de Riesgo:", risk_level.upper(), "Score:", f"{risk_score}/100"],
        ]
        if client_name:
            meta_data.append(["Cliente:", client_name, "", ""])

        meta_table = Table(meta_data, colWidths=[3.5*cm, 6*cm, 3.5*cm, 4.5*cm])
        meta_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (-1, -1), COLOR_DARK),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_LIGHT_GRAY, colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 1 * cm))

    def _add_executive_summary(self, story, ioc_results, risk_level, risk_score):
        """Sección de resumen ejecutivo."""
        story.append(Paragraph("1. RESUMEN EJECUTIVO", self.styles["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        total = len(ioc_results)
        malicious = sum(1 for r in ioc_results if r.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH))
        suspicious = sum(1 for r in ioc_results if r.risk_level == RiskLevel.MEDIUM)
        clean = total - malicious - suspicious

        summary_text = (
            f"Se analizaron <b>{total} indicadores de compromiso (IOCs)</b> utilizando múltiples "
            f"fuentes de inteligencia de amenazas (VirusTotal, AbuseIPDB, Shodan). "
            f"El análisis reveló <b>{malicious} IOC(s) maliciosos o de alto riesgo</b>, "
            f"{suspicious} IOC(s) sospechosos, y {clean} IOC(s) sin amenazas identificadas. "
            f"El nivel de riesgo global de esta investigación es <b>{risk_level.upper()} "
            f"(Score: {risk_score}/100)</b>."
        )

        if malicious > 0:
            summary_text += (
                " Se recomienda tomar acción inmediata para contener y remediar los IOCs "
                "identificados como maliciosos."
            )

        story.append(Paragraph(summary_text, self.styles["body"]))
        story.append(Spacer(1, 0.5 * cm))

    def _add_ioc_table(self, story, ioc_results):
        """Tabla resumen de todos los IOCs analizados."""
        story.append(Paragraph("2. INDICADORES DE COMPROMISO ANALIZADOS", self.styles["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        headers = ["IOC", "Tipo", "Riesgo", "Score", "VT Detecciones"]
        rows = [headers]

        for r in ioc_results:
            vt_det = "N/A"
            if r.virustotal and not r.virustotal.error:
                vt_det = r.virustotal.detection_ratio

            rows.append([
                r.ioc_value[:45] + ("..." if len(r.ioc_value) > 45 else ""),
                r.ioc_type.value.upper(),
                r.risk_level.value.upper(),
                f"{r.risk_score}/100",
                vt_det,
            ])

        col_widths = [7*cm, 2.5*cm, 2.5*cm, 2*cm, 3.5*cm]
        table = Table(rows, colWidths=col_widths, repeatRows=1)

        style_commands = [
            # Header
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_GRAY]),
        ]

        # Colorear celdas de riesgo
        for i, r in enumerate(ioc_results, start=1):
            risk_bg = get_risk_color(r.risk_level.value)
            style_commands.append(("BACKGROUND", (2, i), (2, i), risk_bg))
            style_commands.append(("TEXTCOLOR", (2, i), (2, i), colors.white))
            style_commands.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))

        table.setStyle(TableStyle(style_commands))
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))

    def _add_technical_details(self, story, ioc_results):
        """Descripción técnica detallada por IOC."""
        story.append(Paragraph("3. DESCRIPCIÓN TÉCNICA", self.styles["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        for i, r in enumerate(ioc_results, 1):
            risk_color = get_risk_color(r.risk_level.value)

            story.append(Paragraph(
                f"<b>IOC #{i}: {r.ioc_value}</b>  [{r.ioc_type.value.upper()}]",
                self.styles["body"]
            ))

            if r.summary:
                story.append(Paragraph(r.summary, self.styles["body"]))

            # Detalles de VirusTotal
            if r.virustotal and not r.virustotal.error:
                vt = r.virustotal
                vt_text = (
                    f"<b>VirusTotal:</b> {vt.detection_ratio} motores detectaron amenaza. "
                )
                if vt.categories:
                    vt_text += f"Categorías: {', '.join(vt.categories[:3])}. "
                if vt.last_analysis_date:
                    vt_text += f"Último análisis: {vt.last_analysis_date[:10]}."
                story.append(Paragraph(vt_text, self.styles["body"]))

            # Detalles de AbuseIPDB
            if r.abuseipdb and not r.abuseipdb.error:
                ab = r.abuseipdb
                ab_text = (
                    f"<b>AbuseIPDB:</b> Confianza de abuso: {ab.abuse_confidence_score}%. "
                    f"Reportes totales: {ab.total_reports}. "
                    f"País: {ab.country_code or 'Desconocido'}. "
                    f"ISP: {ab.isp or 'Desconocido'}."
                )
                story.append(Paragraph(ab_text, self.styles["body"]))

            # Detalles de Shodan
            if r.shodan and not r.shodan.error and r.shodan.ip_str:
                sh = r.shodan
                if sh.open_ports or sh.vulnerabilities:
                    sh_text = f"<b>Shodan:</b> "
                    if sh.open_ports:
                        sh_text += f"Puertos abiertos: {', '.join(map(str, sh.open_ports[:10]))}. "
                    if sh.org:
                        sh_text += f"Organización: {sh.org}. "
                    if sh.vulnerabilities:
                        sh_text += f"CVEs: {', '.join(sh.vulnerabilities[:5])}."
                    story.append(Paragraph(sh_text, self.styles["body"]))

            story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
            story.append(Spacer(1, 0.2 * cm))

    def _add_risk_assessment(self, story, ioc_results, risk_level):
        """Evaluación de riesgo global."""
        story.append(Paragraph("4. EVALUACIÓN DE RIESGO", self.styles["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        risk_descriptions = {
            "critical": (
                "El riesgo es CRÍTICO. Se han identificado IOCs altamente maliciosos con "
                "múltiples confirmaciones de diversas fuentes de inteligencia. La probabilidad "
                "de compromiso activo es elevada. Se requiere respuesta inmediata."
            ),
            "high": (
                "El riesgo es ALTO. Se han identificado IOCs con indicios claros de actividad "
                "maliciosa. La situación requiere atención urgente y contención inmediata."
            ),
            "medium": (
                "El riesgo es MEDIO. Se han identificado IOCs sospechosos que requieren "
                "monitorización activa y mayor investigación para confirmar su naturaleza."
            ),
            "low": (
                "El riesgo es BAJO. Los IOCs analizados presentan indicios mínimos de actividad "
                "maliciosa. Se recomienda monitorización estándar."
            ),
            "info": (
                "Los IOCs analizados no presentan indicios de actividad maliciosa en las "
                "fuentes consultadas. Sin embargo, se recomienda mantener la vigilancia."
            ),
        }

        description = risk_descriptions.get(risk_level.lower(), risk_descriptions["info"])
        story.append(Paragraph(description, self.styles["body"]))
        story.append(Spacer(1, 0.5 * cm))

    def _add_recommendations(self, story, ioc_results, risk_level):
        """Acciones recomendadas basadas en el nivel de riesgo."""
        story.append(Paragraph("5. ACCIONES RECOMENDADAS", self.styles["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        all_recommendations = {
            "critical": [
                "🚨 INMEDIATO: Aislar los sistemas afectados de la red corporativa.",
                "🚨 INMEDIATO: Bloquear los IOCs maliciosos en todos los controles de seguridad (firewall, proxy, EDR).",
                "🔍 Iniciar proceso formal de respuesta a incidentes (IR).",
                "🔍 Preservar evidencia forense antes de cualquier remediación.",
                "📋 Notificar a la dirección y equipos legales/de cumplimiento.",
                "🔒 Resetear credenciales de sistemas potencialmente comprometidos.",
                "📊 Revisar logs de los últimos 90 días buscando actividad relacionada.",
            ],
            "high": [
                "⚠️ URGENTE: Bloquear los IOCs en firewall, proxy y herramientas EDR.",
                "🔍 Escalar al equipo de IR para investigación detallada.",
                "🔍 Analizar logs de sistemas para detectar actividad relacionada.",
                "🔒 Revisar y fortalecer controles de acceso afectados.",
                "📊 Implementar reglas de detección específicas en SIEM.",
            ],
            "medium": [
                "🟡 Bloquear o monitorizar los IOCs en controles de seguridad.",
                "📊 Añadir IOCs al SIEM para correlación y alertas.",
                "🔍 Investigar el origen y contexto de los IOCs.",
                "📋 Documentar hallazgos para referencia futura.",
            ],
            "low": [
                "📊 Monitorizar los IOCs de forma pasiva.",
                "📋 Registrar en el sistema de ticketing para seguimiento.",
                "🔍 Re-evaluar en 30 días si el contexto cambia.",
            ],
            "info": [
                "📋 Registrar los IOCs para referencia futura.",
                "📊 Añadir a listas de observación en sistemas de monitorización.",
            ],
        }

        recommendations = all_recommendations.get(risk_level.lower(), all_recommendations["info"])
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles["body"]))

        story.append(Spacer(1, 0.5 * cm))

    def _add_notes(self, story, notes):
        """Notas adicionales del analista."""
        story.append(Paragraph("6. NOTAS DEL ANALISTA", self.styles["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(notes, self.styles["body"]))

    def _add_footer_info(self, story, analyst_name):
        """Información de cierre del reporte."""
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY))
        story.append(Spacer(1, 0.2 * cm))
        footer_text = (
            f"Reporte generado automáticamente por SOC Intel Platform | "
            f"Analista: {analyst_name} | "
            f"{datetime.now().strftime('%d/%m/%Y %H:%M UTC')}"
        )
        story.append(Paragraph(footer_text, self.styles["caption"]))
