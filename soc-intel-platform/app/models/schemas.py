"""
app/models/schemas.py
─────────────────────────────────────────────────────────────
Schemas Pydantic para validación de datos de entrada/salida.

Pydantic v2 valida automáticamente tipos, formatos y rangos.
FastAPI usa estos schemas para:
  - Validar el body de las requests
  - Generar documentación OpenAPI automáticamente
  - Serializar respuestas JSON
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


# ─── Enums ────────────────────────────────────────────────────

class IOCType(str, Enum):
    """Tipos de Indicadores de Compromiso soportados."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Niveles de riesgo."""
    CRITICAL = "critical"   # Score 80-100
    HIGH = "high"           # Score 60-79
    MEDIUM = "medium"       # Score 40-59
    LOW = "low"             # Score 20-39
    INFO = "info"           # Score 0-19


class InvestigationStatus(str, Enum):
    """Estado de una investigación."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ERROR = "error"


# ─── IOC Schemas ──────────────────────────────────────────────

class IOCInput(BaseModel):
    """Un IOC individual para analizar."""
    value: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Valor del IOC: IP, dominio, hash o URL",
        examples=["8.8.8.8", "malware.example.com", "d41d8cd98f00b204e9800998ecf8427e"]
    )

    @field_validator("value")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class InvestigationRequest(BaseModel):
    """Request para iniciar una investigación de uno o más IOCs."""
    title: str = Field(
        default="Investigación sin título",
        max_length=200,
        description="Título descriptivo de la investigación"
    )
    analyst_name: str = Field(
        default="Analista SOC",
        max_length=100,
        description="Nombre del analista responsable"
    )
    iocs: list[IOCInput] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Lista de IOCs a investigar (máx. 50)"
    )
    notes: str = Field(
        default="",
        max_length=2000,
        description="Notas adicionales del analista"
    )


# ─── Enrichment Result Schemas ────────────────────────────────

class VirusTotalResult(BaseModel):
    """Resultado normalizado de VirusTotal."""
    source: str = "virustotal"
    detected: bool = False
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    detection_ratio: str = "0/0"
    categories: list[str] = []
    last_analysis_date: str | None = None
    reputation: int = 0
    tags: list[str] = []
    raw_data: dict[str, Any] = {}
    error: str | None = None


class AbuseIPDBResult(BaseModel):
    """Resultado normalizado de AbuseIPDB."""
    source: str = "abuseipdb"
    is_public: bool = True
    abuse_confidence_score: int = 0
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: str | None = None
    is_whitelisted: bool = False
    usage_type: str | None = None
    raw_data: dict[str, Any] = {}
    error: str | None = None


class ShodanResult(BaseModel):
    """Resultado normalizado de Shodan."""
    source: str = "shodan"
    ip_str: str | None = None
    org: str | None = None
    isp: str | None = None
    country_name: str | None = None
    city: str | None = None
    open_ports: list[int] = []
    hostnames: list[str] = []
    domains: list[str] = []
    os: str | None = None
    tags: list[str] = []
    vulnerabilities: list[str] = []
    last_update: str | None = None
    raw_data: dict[str, Any] = {}
    error: str | None = None


class IOCEnrichmentResult(BaseModel):
    """Resultado completo del enriquecimiento de un IOC."""
    ioc_value: str
    ioc_type: IOCType
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    virustotal: VirusTotalResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    summary: str = ""
    tags: list[str] = []
    enriched_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Investigation Schemas ────────────────────────────────────

class InvestigationResponse(BaseModel):
    """Respuesta completa de una investigación."""
    id: UUID
    title: str
    analyst_name: str
    status: InvestigationStatus
    overall_risk_score: int
    overall_risk_level: RiskLevel
    ioc_results: list[IOCEnrichmentResult] = []
    notes: str = ""
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class InvestigationSummary(BaseModel):
    """Resumen ligero para listados."""
    id: UUID
    title: str
    analyst_name: str
    status: InvestigationStatus
    overall_risk_level: RiskLevel
    ioc_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Report Schemas ───────────────────────────────────────────

class ReportRequest(BaseModel):
    """Request para generar un reporte."""
    investigation_id: UUID
    format: str = Field(
        default="pdf",
        pattern="^(pdf|docx|json|csv)$",
        description="Formato de exportación: pdf, docx, json, csv"
    )
    include_raw_data: bool = Field(
        default=False,
        description="Si incluir datos crudos de las APIs en el reporte"
    )
    custom_title: str | None = Field(
        default=None,
        max_length=200
    )
    client_name: str | None = Field(
        default=None,
        max_length=100,
        description="Nombre del cliente para reportes externos"
    )


class ReportResponse(BaseModel):
    """Respuesta tras generar un reporte."""
    id: UUID
    investigation_id: UUID
    format: str
    file_path: str
    download_url: str
    created_at: datetime

    model_config = {"from_attributes": True}
