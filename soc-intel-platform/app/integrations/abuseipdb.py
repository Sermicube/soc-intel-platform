"""
app/integrations/abuseipdb.py
─────────────────────────────────────────────────────────────
Adaptador para la API v2 de AbuseIPDB.

AbuseIPDB es una base de datos colaborativa de IPs maliciosas.
Miles de administradores de red reportan IPs que les atacan,
creando un score de confianza de abuso muy fiable para IPs.

Solo aplica para IPs (no para dominios, hashes o URLs).

Endpoints usados:
  - GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90

Rate limits (cuenta gratuita):
  - 1000 requests / día
"""

from app.integrations.base import BaseThreatIntelAdapter
from app.models.schemas import AbuseIPDBResult
from app.utils.logger import logger


class AbuseIPDBAdapter(BaseThreatIntelAdapter):
    """Adaptador para AbuseIPDB API v2."""

    SOURCE_NAME = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    @property
    def _headers(self) -> dict:
        return {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    async def enrich(self, ioc_value: str, ioc_type: str) -> AbuseIPDBResult:
        """
        Consulta AbuseIPDB para una dirección IP.
        
        Solo funciona con IPs. Para otros tipos retorna resultado
        vacío sin error (no es un fallo, simplemente no aplica).
        """
        if not self.is_configured:
            return AbuseIPDBResult(error="API key de AbuseIPDB no configurada")

        # AbuseIPDB solo analiza IPs
        if ioc_type not in ("ip",):
            return AbuseIPDBResult(
                error=f"AbuseIPDB no analiza IOCs de tipo '{ioc_type}' (solo IPs)"
            )

        logger.info(f"[AbuseIPDB] Consultando IP: {ioc_value}")

        raw = await self._get(
            url=f"{self.BASE_URL}/check",
            headers=self._headers,
            params={
                "ipAddress": ioc_value,
                "maxAgeInDays": "90",    # Reportes de los últimos 90 días
                "verbose": "",            # Incluye ISP y país
            },
        )

        if "error" in raw and not raw.get("data"):
            return AbuseIPDBResult(error=raw["error"])

        return self._parse_response(raw)

    def _parse_response(self, raw: dict) -> AbuseIPDBResult:
        """Normaliza la respuesta de AbuseIPDB."""
        try:
            data = raw.get("data", {})

            if not data:
                return AbuseIPDBResult(error="Respuesta vacía de AbuseIPDB")

            return AbuseIPDBResult(
                is_public=data.get("isPublic", True),
                abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                country_code=data.get("countryCode"),
                isp=data.get("isp"),
                domain=data.get("domain"),
                total_reports=data.get("totalReports", 0),
                num_distinct_users=data.get("numDistinctUsers", 0),
                last_reported_at=data.get("lastReportedAt"),
                is_whitelisted=data.get("isWhitelisted", False),
                usage_type=data.get("usageType"),
                raw_data={
                    "ipAddress": data.get("ipAddress"),
                    "isPublic": data.get("isPublic"),
                    "ipVersion": data.get("ipVersion"),
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "countryCode": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "usageType": data.get("usageType"),
                    "totalReports": data.get("totalReports"),
                    "numDistinctUsers": data.get("numDistinctUsers"),
                },
            )

        except Exception as e:
            logger.error(f"[AbuseIPDB] Error parseando respuesta: {e}")
            return AbuseIPDBResult(error=f"Error al procesar respuesta: {str(e)}")
