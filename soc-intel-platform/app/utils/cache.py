"""
app/utils/cache.py
─────────────────────────────────────────────────────────────
Sistema de caché con TTL (Time-To-Live) usando cachetools.

Por qué es importante en un SOC:
  - Las APIs de inteligencia de amenazas tienen límites de rate
  - VirusTotal free: 4 requests/minuto
  - AbuseIPDB free: 1000 requests/día
  - Un mismo IOC puede aparecer en múltiples alertas
  - Cachear evita costes y mejora la velocidad de respuesta
"""

import hashlib
import json
from typing import Any

from cachetools import TTLCache
from app.utils.logger import logger


class IOCCache:
    """
    Caché especializado para resultados de enriquecimiento de IOCs.
    
    La clave es un hash del IOC + fuente para evitar colisiones.
    Ejemplo: MD5("1.1.1.1:virustotal") → clave única
    """

    def __init__(self, maxsize: int = 500, ttl: int = 3600):
        """
        Args:
            maxsize: Número máximo de entradas en caché
            ttl: Tiempo de vida en segundos (default: 1 hora)
        """
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._hits = 0
        self._misses = 0

    def _make_key(self, ioc_value: str, source: str) -> str:
        """Genera una clave única y consistente para el caché."""
        raw = f"{ioc_value.lower().strip()}:{source.lower()}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get(self, ioc_value: str, source: str) -> Any | None:
        """
        Recupera un resultado del caché.
        
        Returns:
            El resultado cacheado o None si no existe / expiró
        """
        key = self._make_key(ioc_value, source)
        result = self._cache.get(key)

        if result is not None:
            self._hits += 1
            logger.debug(f"Cache HIT: {ioc_value} [{source}]")
        else:
            self._misses += 1
            logger.debug(f"Cache MISS: {ioc_value} [{source}]")

        return result

    def set(self, ioc_value: str, source: str, data: Any) -> None:
        """Almacena un resultado en caché."""
        key = self._make_key(ioc_value, source)
        self._cache[key] = data
        logger.debug(f"Cache SET: {ioc_value} [{source}]")

    def invalidate(self, ioc_value: str, source: str) -> None:
        """Elimina una entrada específica del caché."""
        key = self._make_key(ioc_value, source)
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Limpia todo el caché."""
        self._cache.clear()
        logger.info("Caché limpiado completamente")

    @property
    def stats(self) -> dict:
        """Estadísticas de uso del caché."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_percent": round(hit_rate, 2),
            "current_size": len(self._cache),
            "max_size": self._cache.maxsize,
        }


# ─── Instancia global del caché ───────────────────────────────
# Se inicializa con los valores de config al arrancar la app
_cache_instance: IOCCache | None = None


def get_cache() -> IOCCache:
    """Retorna la instancia global del caché (singleton)."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = IOCCache()
    return _cache_instance


def init_cache(maxsize: int, ttl: int) -> None:
    """Inicializa el caché con la configuración de la app."""
    global _cache_instance
    _cache_instance = IOCCache(maxsize=maxsize, ttl=ttl)
    logger.info(f"Caché inicializado: maxsize={maxsize}, ttl={ttl}s")
