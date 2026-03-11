"""
app/integrations/base.py
─────────────────────────────────────────────────────────────
Clase base abstracta para todos los adaptadores de APIs.

Patrón Adaptador (Adapter Pattern):
  - Define la interfaz que TODOS los adaptadores deben cumplir
  - El EnrichmentEngine solo conoce esta interfaz, nunca las
    implementaciones concretas
  - Para añadir una nueva fuente (ej: AlienVault OTX), solo
    hay que crear una nueva clase que herede de BaseThreatIntelAdapter
"""

from abc import ABC, abstractmethod
from typing import Any

import httpx
from app.utils.logger import logger


class BaseThreatIntelAdapter(ABC):
    """
    Interfaz que deben implementar todos los adaptadores.
    
    Cada adaptador recibe un IOC y devuelve un resultado
    normalizado en un schema Pydantic específico de su fuente.
    """

    # Nombre de la fuente (se usa como clave en el cache)
    SOURCE_NAME: str = "base"

    def __init__(self, api_key: str, timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @property
    def is_configured(self) -> bool:
        """Verifica si el adaptador tiene API key configurada."""
        return bool(self.api_key)

    @abstractmethod
    async def enrich(self, ioc_value: str, ioc_type: str) -> Any:
        """
        Enriquece un IOC consultando la API correspondiente.
        
        Args:
            ioc_value: El valor del IOC (ej: "1.1.1.1")
            ioc_type: El tipo detectado (ej: "ip")
            
        Returns:
            Schema Pydantic con resultado normalizado
        """
        pass

    async def _get(self, url: str, headers: dict = None, params: dict = None) -> dict:
        """
        Helper para hacer GET requests con manejo de errores.
        
        Returns:
            JSON de respuesta como dict, o dict con error
        """
        if not self._client:
            self._client = httpx.AsyncClient(timeout=self.timeout)

        try:
            response = await self._client.get(
                url,
                headers=headers or {},
                params=params or {},
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.warning(
                f"[{self.SOURCE_NAME}] HTTP {e.response.status_code} para {url}"
            )
            return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}

        except httpx.TimeoutException:
            logger.warning(f"[{self.SOURCE_NAME}] Timeout al consultar {url}")
            return {"error": "Timeout al conectar con la API"}

        except httpx.RequestError as e:
            logger.error(f"[{self.SOURCE_NAME}] Error de red: {e}")
            return {"error": f"Error de red: {str(e)}"}

        except Exception as e:
            logger.error(f"[{self.SOURCE_NAME}] Error inesperado: {e}")
            return {"error": f"Error inesperado: {str(e)}"}
