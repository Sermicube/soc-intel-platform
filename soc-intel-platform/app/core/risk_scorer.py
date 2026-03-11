"""
app/core/risk_scorer.py
─────────────────────────────────────────────────────────────
Módulo de cálculo de puntuación de riesgo.

Consolida los resultados de múltiples fuentes en un único
score de 0-100 con nivel de riesgo (CRITICAL/HIGH/MEDIUM/LOW/INFO).

Metodología de scoring:
  - Cada fuente contribuye con un peso diferente según relevancia
  - Los resultados se normalizan a 0-100
  - El score final es el máximo ponderado entre fuentes
  - En ciberseguridad, el principio es: si UNA fuente dice
    que es malicioso, hay que investigar (conservative approach)
"""

from app.models.schemas import (
    IOCEnrichmentResult, RiskLevel,
    VirusTotalResult, AbuseIPDBResult, ShodanResult
)
from app.utils.logger import logger


# ─── Pesos de cada fuente ─────────────────────────────────────
# VirusTotal tiene más peso porque agrega 70+ motores AV
WEIGHTS = {
    "virustotal": 0.60,
    "abuseipdb": 0.30,
    "shodan": 0.10,  # Shodan es informativo, no de amenazas
}

# ─── Umbrales de nivel de riesgo ─────────────────────────────
RISK_THRESHOLDS = [
    (80, RiskLevel.CRITICAL),
    (60, RiskLevel.HIGH),
    (40, RiskLevel.MEDIUM),
    (20, RiskLevel.LOW),
    (0,  RiskLevel.INFO),
]


class RiskScorer:
    """Calcula el score de riesgo consolidado de un IOC."""

    @staticmethod
    def calculate(result: IOCEnrichmentResult) -> tuple[int, RiskLevel]:
        """
        Calcula el score de riesgo basándose en todos los resultados.
        
        Returns:
            Tuple de (score_0_100, nivel_de_riesgo)
        """
        scores = []

        # ─── Score de VirusTotal ───────────────────────────────
        if result.virustotal and not result.virustotal.error:
            vt_score = RiskScorer._score_virustotal(result.virustotal)
            scores.append(("virustotal", vt_score))

        # ─── Score de AbuseIPDB ────────────────────────────────
        if result.abuseipdb and not result.abuseipdb.error:
            abuse_score = RiskScorer._score_abuseipdb(result.abuseipdb)
            scores.append(("abuseipdb", abuse_score))

        # ─── Score de Shodan ───────────────────────────────────
        if result.shodan and not result.shodan.error:
            shodan_score = RiskScorer._score_shodan(result.shodan)
            scores.append(("shodan", shodan_score))

        if not scores:
            return 0, RiskLevel.INFO

        # ─── Score final: promedio ponderado ───────────────────
        # Si VirusTotal dice 90 y AbuseIPDB dice 10:
        # final = (90*0.6 + 10*0.3) / (0.6 + 0.3) = (54+3)/0.9 = 63.3 → HIGH
        total_weight = sum(WEIGHTS.get(src, 0.1) for src, _ in scores)
        weighted_sum = sum(
            score * WEIGHTS.get(src, 0.1)
            for src, score in scores
        )
        final_score = int(weighted_sum / total_weight) if total_weight > 0 else 0
        final_score = max(0, min(100, final_score))

        risk_level = RiskScorer._score_to_level(final_score)

        logger.debug(
            f"Risk scores: {scores} → final={final_score} ({risk_level})"
        )
        return final_score, risk_level

    @staticmethod
    def _score_virustotal(vt: VirusTotalResult) -> int:
        """
        Score basado en el ratio de detección de VirusTotal.
        
        Lógica:
          - 0 detecciones → 0
          - 1-2 detecciones → score bajo (puede ser falso positivo)
          - Más detecciones → escala linealmente hasta 100
        """
        if vt.total_engines == 0:
            return 0

        ratio = vt.malicious_count / vt.total_engines
        suspicious_bonus = (vt.suspicious_count / vt.total_engines) * 0.3

        # Score no lineal: penaliza más cuando hay muchas detecciones
        raw_score = (ratio + suspicious_bonus) * 100

        # Bonus por reputación negativa de VirusTotal
        if vt.reputation < -50:
            raw_score = min(100, raw_score + 10)

        return int(min(100, max(0, raw_score)))

    @staticmethod
    def _score_abuseipdb(abuse: AbuseIPDBResult) -> int:
        """
        Score directo del confidence score de AbuseIPDB.
        AbuseIPDB ya provee un score de 0-100 de confianza de abuso.
        """
        score = abuse.abuse_confidence_score

        # Penalización adicional por muchos reportes únicos
        if abuse.num_distinct_users > 10:
            score = min(100, score + 10)
        elif abuse.num_distinct_users > 5:
            score = min(100, score + 5)

        return int(score)

    @staticmethod
    def _score_shodan(shodan: ShodanResult) -> int:
        """
        Shodan es informativo pero puede indicar exposición.
        Un servidor con muchos puertos abiertos o CVEs es más riesgoso.
        """
        score = 0

        # Puertos peligrosos expuestos
        dangerous_ports = {23, 445, 3389, 1433, 3306, 5432, 6379, 27017}
        exposed_dangerous = set(shodan.open_ports) & dangerous_ports
        score += len(exposed_dangerous) * 10

        # Vulnerabilidades conocidas (CVEs)
        score += len(shodan.vulnerabilities) * 15

        return int(min(100, score))

    @staticmethod
    def _score_to_level(score: int) -> RiskLevel:
        """Convierte un score numérico en nivel de riesgo."""
        for threshold, level in RISK_THRESHOLDS:
            if score >= threshold:
                return level
        return RiskLevel.INFO

    @staticmethod
    def calculate_overall(individual_scores: list[int]) -> tuple[int, RiskLevel]:
        """
        Calcula el score global de una investigación completa
        a partir de los scores individuales de sus IOCs.
        
        Usa el máximo para ser conservador: si un IOC es CRITICAL,
        toda la investigación es CRITICAL.
        """
        if not individual_scores:
            return 0, RiskLevel.INFO

        overall = max(individual_scores)
        level = RiskScorer._score_to_level(overall)
        return overall, level

    @staticmethod
    def generate_summary(result: IOCEnrichmentResult) -> str:
        """Genera un resumen textual del análisis de riesgo."""
        parts = []

        if result.risk_level == RiskLevel.CRITICAL:
            parts.append(f"⚠️ IOC de ALTO RIESGO: {result.ioc_value}")
        elif result.risk_level == RiskLevel.HIGH:
            parts.append(f"🔴 IOC de riesgo elevado: {result.ioc_value}")
        elif result.risk_level == RiskLevel.MEDIUM:
            parts.append(f"🟡 IOC sospechoso: {result.ioc_value}")
        elif result.risk_level == RiskLevel.LOW:
            parts.append(f"🟢 IOC de bajo riesgo: {result.ioc_value}")
        else:
            parts.append(f"ℹ️ IOC informativo: {result.ioc_value}")

        if result.virustotal and not result.virustotal.error:
            vt = result.virustotal
            parts.append(
                f"VirusTotal: {vt.malicious_count}/{vt.total_engines} motores detectaron amenaza"
            )

        if result.abuseipdb and not result.abuseipdb.error:
            abuse = result.abuseipdb
            parts.append(
                f"AbuseIPDB: Confianza de abuso {abuse.abuse_confidence_score}% "
                f"({abuse.total_reports} reportes)"
            )

        if result.shodan and not result.shodan.error:
            shodan = result.shodan
            if shodan.open_ports:
                parts.append(f"Shodan: {len(shodan.open_ports)} puertos abiertos detectados")
            if shodan.vulnerabilities:
                parts.append(f"Vulnerabilidades conocidas: {', '.join(shodan.vulnerabilities[:3])}")

        return " | ".join(parts)
