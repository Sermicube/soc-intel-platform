"""
app/utils/logger.py
─────────────────────────────────────────────────────────────
Configuración de logging con loguru.
Loguru es superior al logging estándar porque:
  - Formato automático con colores en consola
  - Rotación automática de archivos de log
  - Contexto estructurado con bind()
  - Sin boilerplate de handlers/formatters
"""

import sys
from loguru import logger


def setup_logger(debug: bool = False) -> None:
    """
    Configura el logger global de la aplicación.
    Se llama una sola vez al arrancar en main.py
    """
    # Eliminar el handler por defecto de loguru
    logger.remove()

    # ─── Consola: formato legible para desarrollo ──────────────
    log_level = "DEBUG" if debug else "INFO"
    logger.add(
        sys.stdout,
        level=log_level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # ─── Archivo: rotación diaria, retención 7 días ────────────
    logger.add(
        "data/logs/soc_platform_{time:YYYY-MM-DD}.log",
        level="INFO",
        rotation="00:00",      # Nuevo archivo cada medianoche
        retention="7 days",    # Borra logs de más de 7 días
        compression="zip",     # Comprime logs rotados
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
    )

    logger.info("Logger configurado correctamente")


# Re-exportar logger para uso en toda la app
__all__ = ["logger", "setup_logger"]
