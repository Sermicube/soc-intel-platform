"""
app/core/ioc_detector.py
─────────────────────────────────────────────────────────────
Módulo de detección automática del tipo de IOC.

Estrategia de detección (en orden de especificidad):
  1. Hash MD5/SHA1/SHA256: solo caracteres hex, longitud fija
  2. IP: formato numérico con puntos (IPv4) o dos puntos (IPv6)
  3. URL: comienza con http:// o https://
  4. Dominio: estructura de etiquetas separadas por puntos

El orden importa: una URL contiene un dominio, pero se detecta
primero porque es más específica.
"""

import re
from app.models.schemas import IOCType
from app.utils.logger import logger


# ─── Patrones de expresiones regulares ───────────────────────

# Hashes criptográficos
HASH_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
HASH_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# IPv4: 4 octetos 0-255
IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv6: grupos hexadecimales separados por ':'
IPV6_RE = re.compile(
    r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?$"
)

# URL: esquema + host + path opcional
URL_RE = re.compile(
    r"^https?://"                    # Esquema obligatorio
    r"([\w\-]+\.)+[\w\-]+"          # Host
    r"(:\d+)?"                       # Puerto opcional
    r"(/[\w\-._~:/?#\[\]@!$&'()*+,;=%]*)?$",  # Path opcional
    re.IGNORECASE,
)

# Dominio: letras, números, guiones, múltiples etiquetas
DOMAIN_RE = re.compile(
    r"^(?!-)"                        # No empieza con guión
    r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"  # Etiquetas
    r"[a-zA-Z]{2,}$"                 # TLD de al menos 2 chars
)

# TLDs válidos conocidos (muestra representativa)
KNOWN_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "io", "co", "uk", "de", "fr", "es", "br", "ru",
    "cn", "jp", "au", "ca", "mx", "ar", "cl", "pe",
    "info", "biz", "name", "mobi", "coop", "aero",
    "museum", "travel", "tel", "jobs", "cat", "pro",
    "onion",  # Dark web
}


class IOCDetector:
    """
    Detecta el tipo de un Indicador de Compromiso.
    
    Diseñado para ser stateless: todos los métodos son estáticos
    o de clase, no necesita instancia con estado.
    """

    @staticmethod
    def detect(value: str) -> IOCType:
        """
        Detecta el tipo de IOC a partir de su valor.
        
        Args:
            value: El string del IOC a clasificar
            
        Returns:
            IOCType enum con el tipo detectado
        """
        if not value or not isinstance(value, str):
            return IOCType.UNKNOWN

        value = value.strip()

        # ─── 1. Hashes (más específicos) ──────────────────────
        if HASH_SHA256_RE.match(value):
            logger.debug(f"IOC detectado: SHA256 → {value[:16]}...")
            return IOCType.HASH_SHA256

        if HASH_SHA1_RE.match(value):
            logger.debug(f"IOC detectado: SHA1 → {value[:16]}...")
            return IOCType.HASH_SHA1

        if HASH_MD5_RE.match(value):
            logger.debug(f"IOC detectado: MD5 → {value}")
            return IOCType.HASH_MD5

        # ─── 2. IP addresses ──────────────────────────────────
        if IPV4_RE.match(value):
            logger.debug(f"IOC detectado: IPv4 → {value}")
            return IOCType.IP

        if IPV6_RE.match(value):
            logger.debug(f"IOC detectado: IPv6 → {value}")
            return IOCType.IP

        # ─── 3. URL (antes que dominio, es más específica) ─────
        if URL_RE.match(value):
            logger.debug(f"IOC detectado: URL → {value[:50]}")
            return IOCType.URL

        # ─── 4. Dominio ────────────────────────────────────────
        if IOCDetector._is_domain(value):
            logger.debug(f"IOC detectado: Dominio → {value}")
            return IOCType.DOMAIN

        logger.warning(f"IOC no reconocido: {value[:50]}")
        return IOCType.UNKNOWN

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Validación adicional de dominio.
        Comprueba formato regex + que el TLD sea válido.
        """
        if not DOMAIN_RE.match(value):
            return False

        # Verificar que el TLD sea reconocible
        parts = value.lower().split(".")
        if len(parts) < 2:
            return False

        tld = parts[-1]
        # Aceptar TLDs conocidos o cualquiera de 2-6 chars (para nuevos gTLDs)
        return tld in KNOWN_TLDS or (2 <= len(tld) <= 6 and tld.isalpha())

    @staticmethod
    def get_applicable_sources(ioc_type: IOCType) -> list[str]:
        """
        Retorna qué fuentes de inteligencia aplican a cada tipo de IOC.
        
        No tiene sentido consultar Shodan para un hash de malware,
        ni AbuseIPDB para un dominio.
        
        Returns:
            Lista de nombres de fuentes aplicables
        """
        source_map = {
            IOCType.IP: ["virustotal", "abuseipdb", "shodan"],
            IOCType.DOMAIN: ["virustotal"],
            IOCType.URL: ["virustotal"],
            IOCType.HASH_MD5: ["virustotal"],
            IOCType.HASH_SHA1: ["virustotal"],
            IOCType.HASH_SHA256: ["virustotal"],
            IOCType.UNKNOWN: [],
        }
        return source_map.get(ioc_type, [])

    @staticmethod
    def describe(ioc_type: IOCType) -> str:
        """Descripción legible del tipo de IOC para reportes."""
        descriptions = {
            IOCType.IP: "Dirección IP",
            IOCType.DOMAIN: "Nombre de dominio",
            IOCType.URL: "URL completa",
            IOCType.HASH_MD5: "Hash MD5 de archivo",
            IOCType.HASH_SHA1: "Hash SHA-1 de archivo",
            IOCType.HASH_SHA256: "Hash SHA-256 de archivo",
            IOCType.UNKNOWN: "Tipo desconocido",
        }
        return descriptions.get(ioc_type, "Desconocido")


# ─── Función de conveniencia ──────────────────────────────────

def detect_ioc_type(value: str) -> IOCType:
    """Función de nivel de módulo para uso directo."""
    return IOCDetector.detect(value)
