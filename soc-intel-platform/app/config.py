"""
app/config.py
─────────────────────────────────────────────────────────────
Configuración centralizada usando pydantic-settings.
Todas las variables de entorno se validan aquí al arrancar.
Si falta una variable crítica, la app falla rápido con un
mensaje claro (fail-fast principle).
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuración de la aplicación.
    Los valores se cargan en este orden de prioridad:
      1. Variables de entorno del sistema
      2. Archivo .env
      3. Valores por defecto definidos aquí
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ─── App ──────────────────────────────────────────────────
    app_name: str = "SOC Intel Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # ─── Database ─────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./data/soc_platform.db"

    # ─── API Keys (opcionales para permitir modo demo) ─────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""

    # ─── Cache ────────────────────────────────────────────────
    cache_ttl: int = 3600       # segundos
    cache_max_size: int = 500   # entradas máximas en cache

    # ─── Reports ──────────────────────────────────────────────
    reports_output_dir: str = "./data/reports"

    @property
    def reports_path(self) -> Path:
        path = Path(self.reports_output_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def available_integrations(self) -> list[str]:
        """Retorna qué integraciones están configuradas con API key."""
        integrations = []
        if self.virustotal_api_key:
            integrations.append("virustotal")
        if self.abuseipdb_api_key:
            integrations.append("abuseipdb")
        if self.shodan_api_key:
            integrations.append("shodan")
        return integrations


@lru_cache
def get_settings() -> Settings:
    """
    Singleton de configuración.
    @lru_cache garantiza que el archivo .env se lee una sola vez.
    Usar como dependencia en FastAPI: Depends(get_settings)
    """
    return Settings()
