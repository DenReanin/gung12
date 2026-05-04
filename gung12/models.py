"""Modelos de datos para Gung12."""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
from datetime import datetime


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
    field_name: str
    payload: str
    evidence: str
    description: str
    confidence: float = 0.0  # 0.0 - 1.0
    reflection_artifact: bool = False  # True si es posible falso positivo por reflexión total


@dataclass
class ScanResult:
    """Resultado completo de un escaneo."""
    url: str
    form: FormData
    vulnerabilities: List[VulnResult] = field(default_factory=list)
    scan_mode: str = "quick"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    ai_analysis: Optional[str] = None

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    def to_dict(self) -> dict:
        """Convierte el resultado a diccionario para JSON."""
        return {
            "url": self.url,
            "scan_mode": self.scan_mode,
            "timestamp": self.timestamp,
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
            },
            "vulnerabilities": [
                {
                    "type": v.vuln_type.value,
                    "field": v.field_name,
                    "payload": v.payload,
                    "evidence": v.evidence[:500],
                    "description": v.description,
                    "confidence": v.confidence,
                    "reflection_artifact": v.reflection_artifact,
                }
                for v in self.vulnerabilities
            ],
            "ai_analysis": self.ai_analysis,
        }
