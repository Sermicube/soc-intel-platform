"""
app/main.py
─────────────────────────────────────────────────────────────
Entry point de la aplicación FastAPI.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api.router import api_router
from app.config import get_settings
from app.db.session import init_db
from app.utils.cache import init_cache
from app.utils.logger import logger, setup_logger


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────
    setup_logger(debug=settings.debug)
    logger.info(f"Arrancando {settings.app_name} v{settings.app_version}")

    Path("data/logs").mkdir(parents=True, exist_ok=True)
    Path("data/reports").mkdir(parents=True, exist_ok=True)

    await init_db()

    init_cache(
        maxsize=settings.cache_max_size,
        ttl=settings.cache_ttl,
    )

    integrations = settings.available_integrations
    if integrations:
        logger.info(f"Integraciones activas: {', '.join(integrations)}")
    else:
        logger.warning(
            "No hay API keys configuradas. "
            "Configura las keys en el archivo .env"
        )

    logger.info(f"Servidor listo en http://{settings.host}:{settings.port}")

    yield

    # ── Shutdown ──────────────────────────────────────────────
    logger.info("Cerrando aplicación...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
## SOC Intelligence Platform

Plataforma de automatización para analistas de Centros de Operaciones de Seguridad (SOC).

### Funcionalidades:
* **Enriquecimiento automático de IOCs** (IP, dominio, hash, URL)
* **Consulta paralela** a VirusTotal, AbuseIPDB y Shodan
* **Generación automática de reportes** (PDF, Word, JSON, CSV)
* **Almacenamiento de investigaciones** en base de datos
    """,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["System"])
async def health_check():
    from app.utils.cache import get_cache
    cache = get_cache()
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
        "integrations": settings.available_integrations,
        "cache_stats": cache.stats,
    }


# ─── Frontend estático ────────────────────────────────────────
# Sirve index.html en / y archivos estáticos solo si el
# directorio existe Y contiene archivos (evita crash en Codespaces)

frontend_path = Path(__file__).parent.parent / "frontend"
static_path   = frontend_path / "static"


def _has_files(path: Path) -> bool:
    """Comprueba si un directorio existe y tiene al menos un archivo."""
    try:
        return path.is_dir() and any(path.iterdir())
    except Exception:
        return False


if _has_files(static_path):
    app.mount(
        "/static",
        StaticFiles(directory=str(static_path)),
        name="static",
    )


@app.get("/", include_in_schema=False)
async def serve_frontend():
    """Sirve el frontend SPA o redirige a la documentación."""
    index = frontend_path / "index.html"
    if index.exists():
        return FileResponse(str(index))
    # Fallback: si no hay frontend, redirige a los docs
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/api/docs")


# ─── Entry point ──────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
