"""
app/db/session.py
─────────────────────────────────────────────────────────────
Gestión de sesiones de base de datos con SQLAlchemy async.

Usamos el motor asíncrono con aiosqlite para no bloquear
el event loop de FastAPI durante operaciones de DB.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.models.database import Base
from app.utils.logger import logger

settings = get_settings()

# ─── Engine asíncrono ─────────────────────────────────────────
# StaticPool es necesario para SQLite en tests (misma conexión)
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,       # Log SQL queries en modo debug
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

# ─── Session Factory ──────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,    # Importante: evita lazy loading issues
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """
    Crea todas las tablas en la base de datos.
    Se llama al arrancar la aplicación.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Base de datos inicializada correctamente")


async def get_db() -> AsyncSession:
    """
    Generador de sesiones de DB para inyección de dependencias.
    
    Garantiza que la sesión se cierra siempre, incluso si hay error.
    Uso en FastAPI: db: AsyncSession = Depends(get_db)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
