"""Modelos de datos para Gung12."""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICA"
    HIGH = "ALTA"
    MEDIUM = "MEDIA"
    LOW = "BAJA"
    INFO = "INFO"


class VulnType(Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    XPATH = "xpath"
    CMDI = "cmdi"
    NOSQL = "nosql"
    XXE = "xxe"
    CSRF = "csrf"
    FILE_UPLOAD = "file_upload"
    OPEN_REDIRECT = "redirect"
    HTMLI = "htmli"
    LOGIC = "logic"


# Mapeo de tipo de vulnerabilidad a severidad por defecto
SEVERITY_MAP = {
    VulnType.XSS: Severity.HIGH,
    VulnType.SQLI: Severity.CRITICAL,
    VulnType.SSTI: Severity.CRITICAL,
    VulnType.XPATH: Severity.HIGH,
    VulnType.CMDI: Severity.CRITICAL,
    VulnType.NOSQL: Severity.HIGH,
    VulnType.XXE: Severity.HIGH,
    VulnType.CSRF: Severity.MEDIUM,
    VulnType.FILE_UPLOAD: Severity.HIGH,
    VulnType.OPEN_REDIRECT: Severity.MEDIUM,
    VulnType.HTMLI: Severity.MEDIUM,
    VulnType.LOGIC: Severity.LOW,
}


@dataclass
class FormField:
    """Representa un campo de un formulario HTML."""
    name: str
    field_type: str  # text, password, hidden, submit, etc.
    value: str = ""
    required: bool = False
    options: List[str] = field(default_factory=list)  # Para <select>


@dataclass
class FormData:
    """Representa un formulario HTML parseado."""
    url: str
    action: str
    method: str  # GET o POST
    fields: List[FormField] = field(default_factory=list)
    has_csrf_token: bool = False
    csrf_field: Optional[FormField] = None
    body_type: str = "form"  # "form" = x-www-form-urlencoded, "json" = application/json

    @property
    def injectable_fields(self) -> List[FormField]:
        """Campos donde se pueden inyectar payloads (excluye submit, hidden CSRF, file, etc.)."""
        skip_types = {"submit", "button", "image", "reset", "file"}
        csrf_names = {"csrf_token", "_token", "csrfmiddlewaretoken",
                      "authenticity_token", "__requestverificationtoken",
                      "csrf", "token", "user_token"}
        return [
            f for f in self.fields
            if f.field_type not in skip_types
            and f.name.lower() not in csrf_names
        ]

    @property
    def file_fields(self) -> List[FormField]:
        """Campos de tipo file para pruebas de carga de archivos sin restricciones."""
        return [f for f in self.fields if f.field_type == "file"]

    @property
    def submit_data(self) -> dict:
        """Datos base para enviar el formulario con valores por defecto."""
        data = {}
        for f in self.fields:
            if f.field_type == "submit":
                data[f.name] = f.value if f.value else "Submit"
            else:
                data[f.name] = f.value if f.value else "test"
        return data


@dataclass
class VulnResult:
    """Resultado de una detección de vulnerabilidad."""
    vuln_type: VulnType
    severity: Severity
    field_name: str
    payload: str
    evidence: str
    description: str
    confidence: float = 0.0  # 0.0 - 1.0


@dataclass
class ScanResult:
    """Resultado completo de un escaneo."""
    url: str
    form: FormData
    vulnerabilities: List[VulnResult] = field(default_factory=list)
    scan_mode: str = "quick"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0
    total_requests: int = 0
    ai_analysis: Optional[str] = None

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        """Convierte el resultado a diccionario para JSON."""
        return {
            "url": self.url,
            "scan_mode": self.scan_mode,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "total_requests": self.total_requests,
            "form": {
                "action": self.form.action,
                "method": self.form.method,
                "fields": [
                    {"name": f.name, "type": f.field_type, "value": f.value}
                    for f in self.form.fields
                ],
                "has_csrf_token": self.form.has_csrf_token,
            },
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM),
                "low": sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW),
            },
            "vulnerabilities": [
                {
                    "type": v.vuln_type.value,
                    "severity": v.severity.value,
                    "field": v.field_name,
                    "payload": v.payload,
                    "evidence": v.evidence[:500],
                    "description": v.description,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "ai_analysis": self.ai_analysis,
        }
