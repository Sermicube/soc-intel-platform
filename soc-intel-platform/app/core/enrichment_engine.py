"""
app/core/enrichment_engine.py
─────────────────────────────────────────────────────────────
Motor de enriquecimiento: orquesta todas las consultas a APIs.

El punto clave de diseño es que las 3 APIs se consultan
EN PARALELO usando asyncio.gather(). Esto reduce el tiempo
de respuesta de ~9s (secuencial) a ~3s (paralelo).

Flujo por IOC:
  1. Detectar tipo (IP/domain/hash/URL)
  2. Determinar qué fuentes aplican para ese tipo
  3. Consultar todas las fuentes aplicables en paralelo
  4. Consolidar resultados
  5. Calcular score de riesgo
  6. Generar resumen textual
"""

import asyncio
from typing import Optional

from app.config import get_settings
from app.core.ioc_detector import IOCDetector, detect_ioc_type
from app.core.risk_scorer import RiskScorer
from app.integrations.virustotal import VirusTotalAdapter
from app.integrations.abuseipdb import AbuseIPDBAdapter
from app.integrations.shodan import ShodanAdapter
from app.models.schemas import (
    IOCEnrichmentResult, IOCType,
    VirusTotalResult, AbuseIPDBResult, ShodanResult
)
from app.utils.cache import get_cache
from app.utils.logger import logger


class EnrichmentEngine:
    """
    Orquestador principal del proceso de enriquecimiento de IOCs.
    
    Patrón de uso:
        engine = EnrichmentEngine()
        result = await engine.enrich("8.8.8.8")
    """

    def __init__(self):
        self.settings = get_settings()
        self.cache = get_cache()

        # Inicializar adaptadores con sus API keys
        self.vt_adapter = VirusTotalAdapter(self.settings.virustotal_api_key)
        self.abuse_adapter = AbuseIPDBAdapter(self.settings.abuseipdb_api_key)
        self.shodan_adapter = ShodanAdapter(self.settings.shodan_api_key)

    async def enrich(self, ioc_value: str) -> IOCEnrichmentResult:
        """
        Proceso completo de enriquecimiento para un único IOC.
        
        Args:
            ioc_value: El IOC a analizar (IP, dominio, hash, URL)
            
        Returns:
            IOCEnrichmentResult con todos los datos consolidados
        """
        logger.info(f"Iniciando enriquecimiento: {ioc_value[:50]}")

        # ─── 1. Detectar tipo ──────────────────────────────────
        ioc_type = detect_ioc_type(ioc_value)
        applicable_sources = IOCDetector.get_applicable_sources(ioc_type)

        if ioc_type == IOCType.UNKNOWN:
            logger.warning(f"IOC de tipo desconocido: {ioc_value}")
            return IOCEnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                risk_score=0,
                risk_level="info",
                summary=f"No se pudo identificar el tipo del IOC: {ioc_value}",
            )

        logger.info(f"IOC tipo: {ioc_type.value} | Fuentes: {applicable_sources}")

        # ─── 2. Consultar APIs en paralelo ─────────────────────
        vt_result, abuse_result, shodan_result = await self._query_all_sources(
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            applicable_sources=applicable_sources,
        )

        # ─── 3. Construir resultado parcial ───────────────────
        result = IOCEnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            risk_score=0,
            risk_level="info",
            virustotal=vt_result,
            abuseipdb=abuse_result,
            shodan=shodan_result,
        )

        # ─── 4. Calcular score de riesgo ──────────────────────
        risk_score, risk_level = RiskScorer.calculate(result)
        result.risk_score = risk_score
        result.risk_level = risk_level

        # ─── 5. Generar resumen textual ───────────────────────
        result.summary = RiskScorer.generate_summary(result)
        result.tags = self._extract_tags(result)

        logger.info(
            f"Enriquecimiento completo: {ioc_value[:30]} → "
            f"Score={risk_score}, Level={risk_level.value}"
        )

        return result

    async def enrich_batch(self, ioc_values: list[str]) -> list[IOCEnrichmentResult]:
        """
        Enriquece múltiples IOCs de forma concurrente.
        
        Limitamos la concurrencia a 5 para respetar rate limits.
        Con más de 5 IOCs simultáneos, VirusTotal (4 req/min) fallaría.
        """
        semaphore = asyncio.Semaphore(5)

        async def enrich_with_semaphore(ioc: str) -> IOCEnrichmentResult:
            async with semaphore:
                return await self.enrich(ioc)

        tasks = [enrich_with_semaphore(ioc) for ioc in ioc_values]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Manejar excepciones en tareas individuales
        processed = []
        for ioc, result in zip(ioc_values, results):
            if isinstance(result, Exception):
                logger.error(f"Error enriqueciendo {ioc}: {result}")
                processed.append(IOCEnrichmentResult(
                    ioc_value=ioc,
                    ioc_type=IOCType.UNKNOWN,
                    risk_score=0,
                    risk_level="info",
                    summary=f"Error durante el análisis: {str(result)}",
                ))
            else:
                processed.append(result)

        return processed

    async def _query_all_sources(
        self,
        ioc_value: str,
        ioc_type: str,
        applicable_sources: list[str],
    ) -> tuple[Optional[VirusTotalResult], Optional[AbuseIPDBResult], Optional[ShodanResult]]:
        """
        Consulta todas las fuentes en paralelo con asyncio.gather().
        
        Cada fuente que no aplique al tipo de IOC retorna None directamente
        sin hacer ninguna petición HTTP.
        """

        async def query_virustotal():
            if "virustotal" not in applicable_sources:
                return None
            cached = self.cache.get(ioc_value, "virustotal")
            if cached:
                return VirusTotalResult(**cached)
            async with self.vt_adapter as adapter:
                result = await adapter.enrich(ioc_value, ioc_type)
            if not result.error:
                self.cache.set(ioc_value, "virustotal", result.model_dump())
            return result

        async def query_abuseipdb():
            if "abuseipdb" not in applicable_sources:
                return None
            cached = self.cache.get(ioc_value, "abuseipdb")
            if cached:
                return AbuseIPDBResult(**cached)
            async with self.abuse_adapter as adapter:
                result = await adapter.enrich(ioc_value, ioc_type)
            if not result.error:
                self.cache.set(ioc_value, "abuseipdb", result.model_dump())
            return result

        async def query_shodan():
            if "shodan" not in applicable_sources:
                return None
            cached = self.cache.get(ioc_value, "shodan")
            if cached:
                return ShodanResult(**cached)
            async with self.shodan_adapter as adapter:
                result = await adapter.enrich(ioc_value, ioc_type)
            if not result.error:
                self.cache.set(ioc_value, "shodan", result.model_dump())
            return result

        # ─── Ejecución en paralelo ────────────────────────────
        vt_result, abuse_result, shodan_result = await asyncio.gather(
            query_virustotal(),
            query_abuseipdb(),
            query_shodan(),
            return_exceptions=False,
        )

        return vt_result, abuse_result, shodan_result

    @staticmethod
    def _extract_tags(result: IOCEnrichmentResult) -> list[str]:
        """Extrae tags relevantes de todos los resultados para visualización."""
        tags = set()

        if result.virustotal:
            tags.update(result.virustotal.tags[:5])
            tags.update(result.virustotal.categories[:3])
            if result.virustotal.detected:
                tags.add("malicious")

        if result.abuseipdb:
            if result.abuseipdb.abuse_confidence_score > 50:
                tags.add("abusive-ip")
            if result.abuseipdb.country_code:
                tags.add(f"country:{result.abuseipdb.country_code}")

        if result.shodan:
            tags.update(result.shodan.tags[:3])
            if result.shodan.vulnerabilities:
                tags.add("has-cves")
            if result.shodan.open_ports:
                tags.add("exposed-ports")

        return sorted(list(tags))[:15]
