"""
app/reports/json_exporter.py
─────────────────────────────────────────────────────────────
Exportador de resultados en JSON y CSV.

Útil para:
  - Integración con otros sistemas (SIEM, SOAR)
  - Importar en Excel para análisis adicional
  - Pipelines automatizados
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from app.config import get_settings
from app.models.schemas import IOCEnrichmentResult
from app.utils.logger import logger


class DataExporter:
    """Exporta resultados de enriquecimiento en distintos formatos."""

    def __init__(self):
        self.settings = get_settings()

    async def export_json(
        self,
        investigation_id: str,
        title: str,
        analyst_name: str,
        ioc_results: list[IOCEnrichmentResult],
        overall_risk_level: str,
        overall_risk_score: int,
        include_raw_data: bool = False,
    ) -> str:
        """
        Exporta resultados como JSON estructurado.
        
        Returns:
            Path del archivo JSON generado
        """
        output = {
            "metadata": {
                "investigation_id": investigation_id,
                "title": title,
                "analyst_name": analyst_name,
                "overall_risk_level": overall_risk_level,
                "overall_risk_score": overall_risk_score,
                "ioc_count": len(ioc_results),
                "exported_at": datetime.utcnow().isoformat(),
                "platform": "SOC Intel Platform v1.0",
            },
            "iocs": [],
        }

        for result in ioc_results:
            ioc_data = {
                "value": result.ioc_value,
                "type": result.ioc_type.value,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "summary": result.summary,
                "tags": result.tags,
                "enriched_at": result.enriched_at.isoformat(),
                "sources": {},
            }

            # VirusTotal
            if result.virustotal:
                vt = result.virustotal
                ioc_data["sources"]["virustotal"] = {
                    "detected": vt.detected,
                    "malicious_count": vt.malicious_count,
                    "suspicious_count": vt.suspicious_count,
                    "total_engines": vt.total_engines,
                    "detection_ratio": vt.detection_ratio,
                    "reputation": vt.reputation,
                    "categories": vt.categories,
                    "tags": vt.tags,
                    "last_analysis_date": vt.last_analysis_date,
                    "error": vt.error,
                }
                if include_raw_data:
                    ioc_data["sources"]["virustotal"]["raw_data"] = vt.raw_data

            # AbuseIPDB
            if result.abuseipdb:
                ab = result.abuseipdb
                ioc_data["sources"]["abuseipdb"] = {
                    "abuse_confidence_score": ab.abuse_confidence_score,
                    "total_reports": ab.total_reports,
                    "num_distinct_users": ab.num_distinct_users,
                    "country_code": ab.country_code,
                    "isp": ab.isp,
                    "domain": ab.domain,
                    "usage_type": ab.usage_type,
                    "is_whitelisted": ab.is_whitelisted,
                    "last_reported_at": ab.last_reported_at,
                    "error": ab.error,
                }
                if include_raw_data:
                    ioc_data["sources"]["abuseipdb"]["raw_data"] = ab.raw_data

            # Shodan
            if result.shodan:
                sh = result.shodan
                ioc_data["sources"]["shodan"] = {
                    "org": sh.org,
                    "isp": sh.isp,
                    "country_name": sh.country_name,
                    "city": sh.city,
                    "open_ports": sh.open_ports,
                    "hostnames": sh.hostnames,
                    "os": sh.os,
                    "tags": sh.tags,
                    "vulnerabilities": sh.vulnerabilities,
                    "last_update": sh.last_update,
                    "error": sh.error,
                }
                if include_raw_data:
                    ioc_data["sources"]["shodan"]["raw_data"] = sh.raw_data

            output["iocs"].append(ioc_data)

        # Guardar archivo
        output_dir = self.settings.reports_path
        filename = f"investigation_{investigation_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"JSON exportado: {filepath}")
        return str(filepath)

    async def export_csv(
        self,
        investigation_id: str,
        ioc_results: list[IOCEnrichmentResult],
    ) -> str:
        """
        Exporta resultados como CSV plano para Excel/análisis.
        
        Cada IOC es una fila con columnas de todas las fuentes.
        
        Returns:
            Path del archivo CSV generado
        """
        output_dir = self.settings.reports_path
        filename = f"iocs_{investigation_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = output_dir / filename

        fieldnames = [
            "ioc_value", "ioc_type", "risk_score", "risk_level", "tags",
            # VirusTotal
            "vt_detected", "vt_malicious", "vt_suspicious", "vt_total_engines",
            "vt_detection_ratio", "vt_reputation", "vt_categories",
            # AbuseIPDB
            "abuse_confidence_score", "abuse_total_reports", "abuse_distinct_users",
            "abuse_country", "abuse_isp", "abuse_usage_type",
            # Shodan
            "shodan_org", "shodan_country", "shodan_open_ports",
            "shodan_cves", "shodan_os",
            # Meta
            "summary", "enriched_at",
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for r in ioc_results:
                row = {
                    "ioc_value": r.ioc_value,
                    "ioc_type": r.ioc_type.value,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level.value,
                    "tags": "|".join(r.tags),
                    "summary": r.summary,
                    "enriched_at": r.enriched_at.isoformat(),
                }

                # VirusTotal
                if r.virustotal:
                    vt = r.virustotal
                    row.update({
                        "vt_detected": vt.detected,
                        "vt_malicious": vt.malicious_count,
                        "vt_suspicious": vt.suspicious_count,
                        "vt_total_engines": vt.total_engines,
                        "vt_detection_ratio": vt.detection_ratio,
                        "vt_reputation": vt.reputation,
                        "vt_categories": "|".join(vt.categories),
                    })

                # AbuseIPDB
                if r.abuseipdb:
                    ab = r.abuseipdb
                    row.update({
                        "abuse_confidence_score": ab.abuse_confidence_score,
                        "abuse_total_reports": ab.total_reports,
                        "abuse_distinct_users": ab.num_distinct_users,
                        "abuse_country": ab.country_code or "",
                        "abuse_isp": ab.isp or "",
                        "abuse_usage_type": ab.usage_type or "",
                    })

                # Shodan
                if r.shodan:
                    sh = r.shodan
                    row.update({
                        "shodan_org": sh.org or "",
                        "shodan_country": sh.country_name or "",
                        "shodan_open_ports": "|".join(map(str, sh.open_ports)),
                        "shodan_cves": "|".join(sh.vulnerabilities),
                        "shodan_os": sh.os or "",
                    })

                writer.writerow(row)

        logger.info(f"CSV exportado: {filepath}")
        return str(filepath)
