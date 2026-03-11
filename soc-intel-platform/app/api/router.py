"""
app/api/router.py
─────────────────────────────────────────────────────────────
Router principal que agrupa todos los endpoints de la API.
"""

from fastapi import APIRouter
from app.api.v1 import investigations, reports

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(investigations.router)
api_router.include_router(reports.router)
