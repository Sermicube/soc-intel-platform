"""
app/integrations/shodan.py
─────────────────────────────────────────────────────────────
Adaptador para la API de Shodan.

Shodan es un motor de búsqueda de dispositivos conectados a Internet.
Para IPs, nos dice:
  - Qué puertos tiene abiertos
  - Qué servicios están corriendo
  - Sistema operativo
  - Vulnerabilidades conocidas (CVEs)
  - Geolocalización e ISP

Solo aplica para IPs (al igual que AbuseIPDB).

Endpoints usados:
  - GET /shodan/host/{ip}

Rate limits (cuenta gratuita):
  - 1 request / segundo
  - Historial limitado
"""

from app.integrations.base import BaseThreatIntelAdapter
from app.models.schemas import ShodanResult
from app.utils.logger import logger


class ShodanAdapter(BaseThreatIntelAdapter):
    """Adaptador para Shodan API."""

    SOURCE_NAME = "shodan"
    BASE_URL = "https://api.shodan.io"

    async def enrich(self, ioc_value: str, ioc_type: str) -> ShodanResult:
        """
        Consulta Shodan para obtener información de infraestructura de una IP.
        """
        if not self.is_configured:
            return ShodanResult(error="API key de Shodan no configurada")

        # Shodan solo analiza IPs
        if ioc_type not in ("ip",):
            return ShodanResult(
                error=f"Shodan no analiza IOCs de tipo '{ioc_type}' (solo IPs)"
            )

        logger.info(f"[Shodan] Consultando IP: {ioc_value}")

        raw = await self._get(
            url=f"{self.BASE_URL}/shodan/host/{ioc_value}",
            params={"key": self.api_key},
        )

        # Shodan retorna 404 para IPs sin datos (no es un error crítico)
        if "error" in raw:
            error_msg = raw["error"]
            if "404" in str(error_msg) or "No information available" in str(error_msg):
                logger.info(f"[Shodan] Sin datos para {ioc_value}")
                return ShodanResult(
                    ip_str=ioc_value,
                    error=None,  # No es un error, simplemente sin datos
                )
            return ShodanResult(error=error_msg)

        return self._parse_response(raw, ioc_value)

    def _parse_response(self, raw: dict, ioc_value: str) -> ShodanResult:
        """Normaliza la respuesta de Shodan."""
        try:
            # ─── Puertos abiertos ──────────────────────────────
            open_ports = raw.get("ports", [])
            if not isinstance(open_ports, list):
                open_ports = []

            # ─── Hostnames y dominios ──────────────────────────
            hostnames = raw.get("hostnames", [])
            domains = raw.get("domains", [])

            # ─── Tags de Shodan ────────────────────────────────
            tags = raw.get("tags", [])

            # ─── Vulnerabilidades (CVEs) ───────────────────────
            vulns_raw = raw.get("vulns", {})
            if isinstance(vulns_raw, dict):
                vulnerabilities = list(vulns_raw.keys())  # Keys son CVE IDs
            elif isinstance(vulns_raw, list):
                vulnerabilities = vulns_raw
            else:
                vulnerabilities = []

            # ─── Sistema operativo ─────────────────────────────
            os = raw.get("os")

            return ShodanResult(
                ip_str=raw.get("ip_str", ioc_value),
                org=raw.get("org"),
                isp=raw.get("isp"),
                country_name=raw.get("country_name"),
                city=raw.get("city"),
                open_ports=sorted(open_ports)[:50],  # Max 50 puertos
                hostnames=hostnames[:10],
                domains=domains[:10],
                os=os,
                tags=tags[:10],
                vulnerabilities=vulnerabilities[:20],  # Max 20 CVEs
                last_update=raw.get("last_update"),
                raw_data={
                    "ip_str": raw.get("ip_str"),
                    "org": raw.get("org"),
                    "isp": raw.get("isp"),
                    "country_name": raw.get("country_name"),
                    "asn": raw.get("asn"),
                    "ports": open_ports[:20],
                    "vulns": list(vulnerabilities)[:10],
                },
            )

        except Exception as e:
            logger.error(f"[Shodan] Error parseando respuesta: {e}")
            return ShodanResult(error=f"Error al procesar respuesta: {str(e)}")
