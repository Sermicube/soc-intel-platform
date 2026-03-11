"""
app/integrations/virustotal.py
─────────────────────────────────────────────────────────────
Adaptador para la API v3 de VirusTotal.

VirusTotal agrega resultados de 70+ motores antivirus y
es la fuente más importante para clasificar amenazas.

Endpoints usados:
  - IPs:    GET /api/v3/ip_addresses/{ip}
  - Domins: GET /api/v3/domains/{domain}
  - URLs:   GET /api/v3/urls/{url_id}   (requiere encode base64)
  - Hashes: GET /api/v3/files/{hash}

Rate limits (cuenta gratuita):
  - 4 requests / minuto
  - 500 requests / día
"""

import base64
import hashlib
from datetime import datetime

from app.integrations.base import BaseThreatIntelAdapter
from app.models.schemas import VirusTotalResult
from app.utils.logger import logger


class VirusTotalAdapter(BaseThreatIntelAdapter):
    """Adaptador para VirusTotal API v3."""

    SOURCE_NAME = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    @property
    def _headers(self) -> dict:
        return {"x-apikey": self.api_key}

    async def enrich(self, ioc_value: str, ioc_type: str) -> VirusTotalResult:
        """
        Consulta VirusTotal según el tipo de IOC.
        
        Returns:
            VirusTotalResult con datos normalizados
        """
        if not self.is_configured:
            return VirusTotalResult(error="API key de VirusTotal no configurada")

        # ─── Seleccionar endpoint según tipo ──────────────────
        endpoint_map = {
            "ip": f"{self.BASE_URL}/ip_addresses/{ioc_value}",
            "domain": f"{self.BASE_URL}/domains/{ioc_value}",
            "hash_md5": f"{self.BASE_URL}/files/{ioc_value}",
            "hash_sha1": f"{self.BASE_URL}/files/{ioc_value}",
            "hash_sha256": f"{self.BASE_URL}/files/{ioc_value}",
            "url": self._build_url_endpoint(ioc_value),
        }

        url = endpoint_map.get(ioc_type)
        if not url:
            return VirusTotalResult(error=f"Tipo de IOC '{ioc_type}' no soportado por VirusTotal")

        logger.info(f"[VirusTotal] Consultando: {ioc_value[:50]} [{ioc_type}]")
        raw = await self._get(url, headers=self._headers)

        if "error" in raw:
            return VirusTotalResult(error=raw["error"])

        return self._parse_response(raw, ioc_type)

    def _build_url_endpoint(self, url: str) -> str:
        """
        VirusTotal identifica URLs por un ID en base64 URL-safe.
        El ID es: base64(url).rstrip("=")
        """
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return f"{self.BASE_URL}/urls/{url_id}"

    def _parse_response(self, raw: dict, ioc_type: str) -> VirusTotalResult:
        """
        Normaliza la respuesta de VirusTotal al schema estándar.
        
        La API v3 usa una estructura data.attributes para todos
        los tipos de recursos.
        """
        try:
            data = raw.get("data", {})
            attrs = data.get("attributes", {})

            # ─── Estadísticas de análisis ─────────────────────
            last_analysis_stats = attrs.get("last_analysis_stats", {})
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            harmless = last_analysis_stats.get("harmless", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            # ─── Fecha del último análisis ────────────────────
            last_analysis_date = None
            raw_date = attrs.get("last_analysis_date")
            if raw_date:
                try:
                    last_analysis_date = datetime.fromtimestamp(raw_date).isoformat()
                except (ValueError, TypeError, OSError):
                    pass

            # ─── Categorías y tags ────────────────────────────
            categories = []
            raw_categories = attrs.get("categories", {})
            if isinstance(raw_categories, dict):
                categories = list(set(raw_categories.values()))

            tags = attrs.get("tags", [])
            if not isinstance(tags, list):
                tags = []

            return VirusTotalResult(
                detected=malicious > 0 or suspicious > 0,
                malicious_count=malicious,
                suspicious_count=suspicious,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                categories=categories[:10],
                last_analysis_date=last_analysis_date,
                reputation=attrs.get("reputation", 0),
                tags=tags[:10],
                raw_data={
                    "id": data.get("id", ""),
                    "type": data.get("type", ""),
                    "last_analysis_stats": last_analysis_stats,
                },
            )

        except Exception as e:
            logger.error(f"[VirusTotal] Error parseando respuesta: {e}")
            return VirusTotalResult(error=f"Error al procesar respuesta: {str(e)}")
