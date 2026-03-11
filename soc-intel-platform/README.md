# 🛡 SOC Intelligence Platform

Plataforma de automatización para analistas de Centros de Operaciones de Seguridad (SOC).
Enriquece automáticamente IOCs consultando múltiples fuentes de inteligencia de amenazas
y genera reportes de incidentes profesionales.

---

## ✨ Funcionalidades

- **Detección automática** del tipo de IOC (IP, dominio, hash MD5/SHA1/SHA256, URL)
- **Consulta paralela** a VirusTotal, AbuseIPDB y Shodan (3x más rápido que secuencial)
- **Score de riesgo consolidado** (0–100) con niveles CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Generación de reportes** en PDF, Word (.docx), JSON y CSV
- **Almacenamiento** de investigaciones en base de datos SQLite
- **Interfaz web** para analistas SOC
- **API REST documentada** con OpenAPI / Swagger

---

## 🚀 Inicio Rápido

### 1. Clonar y configurar entorno

```bash
git clone <repo>
cd soc-intel-platform

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Configurar API keys

```bash
cp .env.example .env
# Editar .env con tus API keys
nano .env
```

Obtener API keys gratuitas:
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **AbuseIPDB**: https://www.abuseipdb.com/account/api
- **Shodan**: https://account.shodan.io/

### 3. Arrancar el servidor

```bash
python -m app.main
# O con uvicorn directamente:
uvicorn app.main:app --reload --port 8000
```

### 4. Abrir la aplicación

- **Interfaz web**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/api/docs
- **API Docs (ReDoc)**: http://localhost:8000/api/redoc

---

## 📁 Estructura del Proyecto

```
soc-intel-platform/
├── app/
│   ├── main.py                 # Entry point FastAPI
│   ├── config.py               # Configuración centralizada
│   ├── api/v1/
│   │   ├── investigations.py   # Endpoints de investigación
│   │   └── reports.py          # Endpoints de reportes
│   ├── core/
│   │   ├── ioc_detector.py     # Detección automática de tipo IOC
│   │   ├── enrichment_engine.py # Motor de enriquecimiento async
│   │   └── risk_scorer.py      # Cálculo de score de riesgo
│   ├── integrations/
│   │   ├── base.py             # Clase base abstracta (Adapter Pattern)
│   │   ├── virustotal.py       # Integración VirusTotal API v3
│   │   ├── abuseipdb.py        # Integración AbuseIPDB API v2
│   │   └── shodan.py           # Integración Shodan API
│   ├── reports/
│   │   ├── pdf_generator.py    # Generación PDF (ReportLab)
│   │   ├── word_generator.py   # Generación Word (python-docx)
│   │   └── json_exporter.py    # Exportación JSON/CSV
│   ├── models/
│   │   ├── schemas.py          # Schemas Pydantic (validación)
│   │   └── database.py         # Modelos ORM SQLAlchemy
│   └── db/
│       ├── session.py          # Gestión de sesiones async
│       └── repository.py       # Patrón Repository
├── frontend/
│   └── index.html              # SPA del analista SOC
├── tests/
│   └── unit/
│       └── test_ioc_detector.py
└── data/                       # DB y reportes generados
```

---

## 🔌 API Reference

### Crear investigación

```bash
POST /api/v1/investigations/
Content-Type: application/json

{
  "title": "Análisis phishing campaña Q1",
  "analyst_name": "Ana García",
  "iocs": [
    {"value": "8.8.8.8"},
    {"value": "malware.example.com"},
    {"value": "d41d8cd98f00b204e9800998ecf8427e"}
  ],
  "notes": "Detectado en honeypot interno"
}
```

### Generar reporte

```bash
POST /api/v1/reports/
Content-Type: application/json

{
  "investigation_id": "uuid-aqui",
  "format": "pdf",
  "client_name": "ACME Corp"
}
```

### Descargar reporte

```bash
GET /api/v1/reports/{report_id}/download
```

---

## 🧪 Tests

```bash
# Instalar dependencias de dev
pip install pytest pytest-asyncio

# Ejecutar tests
pytest tests/ -v

# Solo tests unitarios
pytest tests/unit/ -v
```

---

## 🏗 Arquitectura

El sistema sigue un patrón **API-first** con capas desacopladas:

1. **API Layer** (FastAPI): Validación, routing, serialización
2. **Core Layer**: Lógica de negocio (detector, enrichment engine, risk scorer)
3. **Integration Layer**: Adaptadores para APIs externas (Adapter Pattern)
4. **Data Layer**: SQLAlchemy async + Repository Pattern

Las consultas a APIs externas se ejecutan **en paralelo** con `asyncio.gather()`,
reduciendo el tiempo de respuesta de ~9s a ~3s.

---

## 🔒 Consideraciones de Seguridad

- Las API keys **nunca** se guardan en el código, solo en `.env`
- El archivo `.env` está en `.gitignore`
- Los reportes se guardan en `data/reports/` con nombres únicos (UUID + timestamp)
- La base de datos SQLite está en `data/` (no expuesta por la API)

---

## 📦 Añadir Nuevas Fuentes de Inteligencia

Para integrar una nueva API (ej: AlienVault OTX):

```python
# app/integrations/otx.py
from app.integrations.base import BaseThreatIntelAdapter

class OTXAdapter(BaseThreatIntelAdapter):
    SOURCE_NAME = "otx"
    
    async def enrich(self, ioc_value: str, ioc_type: str):
        # Implementar lógica
        ...
```

Luego añadir al `EnrichmentEngine` en `enrichment_engine.py`.

---

## 📄 Licencia

MIT License — Proyecto de práctica profesional para equipos SOC.
