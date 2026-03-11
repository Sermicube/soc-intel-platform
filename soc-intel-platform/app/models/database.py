"""
app/models/database.py
─────────────────────────────────────────────────────────────
Modelos ORM de SQLAlchemy para la base de datos.

SQLAlchemy 2.0 usa el nuevo estilo declarativo con type hints,
lo que hace el código más limpio y con mejor soporte de IDEs.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, JSON
)
from sqlalchemy.orm import DeclarativeBase, relationship


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Clase base para todos los modelos."""
    pass


class Investigation(Base):
    """
    Representa una sesión de investigación completa.
    Un analista puede investigar múltiples IOCs en una sola investigación.
    """
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(200), nullable=False, default="Investigación sin título")
    analyst_name = Column(String(100), nullable=False, default="Analista SOC")
    status = Column(String(20), nullable=False, default="pending")
    overall_risk_score = Column(Integer, default=0)
    overall_risk_level = Column(String(20), default="info")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relaciones
    iocs = relationship("IOCResult", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="investigation", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Investigation(id={self.id[:8]}..., title={self.title})>"


class IOCResult(Base):
    """
    Resultado del enriquecimiento de un IOC individual.
    Almacena los datos de todas las fuentes en columnas JSON
    para flexibilidad (cada API devuelve datos distintos).
    """
    __tablename__ = "ioc_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    # ─── IOC Info ─────────────────────────────────────────────
    ioc_value = Column(String(2048), nullable=False)
    ioc_type = Column(String(20), nullable=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="info")
    summary = Column(Text, default="")
    tags = Column(JSON, default=list)

    # ─── Resultados por fuente (JSON para flexibilidad) ────────
    virustotal_data = Column(JSON, nullable=True)
    abuseipdb_data = Column(JSON, nullable=True)
    shodan_data = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relaciones
    investigation = relationship("Investigation", back_populates="iocs")

    def __repr__(self):
        return f"<IOCResult(value={self.ioc_value}, type={self.ioc_type}, risk={self.risk_level})>"


class Report(Base):
    """
    Reporte de incidente generado a partir de una investigación.
    """
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    # ─── Contenido del reporte ────────────────────────────────
    format = Column(String(10), nullable=False)  # pdf, docx, json, csv
    file_path = Column(String(500), nullable=True)
    executive_summary = Column(Text, default="")
    technical_description = Column(Text, default="")
    risk_assessment = Column(Text, default="")
    recommendations = Column(Text, default="")
    client_name = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relaciones
    investigation = relationship("Investigation", back_populates="reports")

    def __repr__(self):
        return f"<Report(id={self.id[:8]}..., format={self.format})>"
