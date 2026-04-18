"""Módulo 3: Analizador de respuestas.

Compara la respuesta base con las respuestas tras inyección de payloads
para detectar indicios de vulnerabilidades.
"""

import re
import time
from typing import Optional

from formvuln.models import VulnType, VulnResult, Severity, SEVERITY_MAP, FormData
from formvuln.payloads import xss, sqli, ssti, ldap, cmdi, nosql, xxe, lfi, open_redirect


class ResponseAnalyzer:
    """Analiza respuestas HTTP para detectar indicios de vulnerabilidades."""

    def __init__(self, base_response: Optional[str] = None, base_status: int = 200,
                 base_time: float = 0.0):
        self.base_response = base_response or ""
        self.base_status = base_status
        self.base_time = base_time

    def analyze(self, vuln_type: VulnType, payload: str, response_text: str,
                status_code: int, response_time: float, field_name: str,
                form: Optional[FormData] = None) -> Optional[VulnResult]:
        """Analiza una respuesta y retorna VulnResult si detecta vulnerabilidad."""

        analyzers = {
            VulnType.XSS: self._analyze_xss,
            VulnType.SQLI: self._analyze_sqli,
            VulnType.SSTI: self._analyze_ssti,
            VulnType.LDAP: self._analyze_ldap,
            VulnType.CMDI: self._analyze_cmdi,
            VulnType.NOSQL: self._analyze_nosql,
            VulnType.XXE: self._analyze_xxe,
            VulnType.LFI: self._analyze_lfi,
            VulnType.OPEN_REDIRECT: self._analyze_redirect,
            VulnType.IDOR: self._analyze_idor,
            VulnType.LOGIC: self._analyze_logic,
            VulnType.CSRF: self._analyze_csrf,
        }

        analyzer_fn = analyzers.get(vuln_type)
        if not analyzer_fn:
            return None

        if vuln_type == VulnType.CSRF:
            return analyzer_fn(field_name, form)

        return analyzer_fn(payload, response_text, status_code, response_time, field_name)

    def _analyze_xss(self, payload: str, response: str, status: int,
                     resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta XSS reflejado: el payload aparece sin encoding en la respuesta."""
        response_lower = response.lower()

        # Verificar si el payload exacto se refleja
        if payload.lower() in response_lower:
            return VulnResult(
                vuln_type=VulnType.XSS,
                severity=SEVERITY_MAP[VulnType.XSS],
                field_name=field,
                payload=payload,
                evidence=self._extract_context(response, payload, 100),
                description=f"XSS reflejado: el payload se refleja sin sanitizar en el campo '{field}'",
                confidence=0.9,
            )

        # Verificar patrones de detección
        for pattern in xss.DETECTION_PATTERNS:
            if pattern.lower() in response_lower and pattern.lower() not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.XSS,
                    severity=SEVERITY_MAP[VulnType.XSS],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"XSS reflejado: patrón '{pattern}' detectado en respuesta",
                    confidence=0.7,
                )

        return None

    def _analyze_sqli(self, payload: str, response: str, status: int,
                      resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta SQLi: errores SQL o time-based."""
        response_lower = response.lower()

        # Detección por errores SQL
        for pattern in sqli.DETECTION_PATTERNS:
            if re.search(pattern, response_lower) and not re.search(pattern, self.base_response.lower()):
                return VulnResult(
                    vuln_type=VulnType.SQLI,
                    severity=SEVERITY_MAP[VulnType.SQLI],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 150),
                    description=f"SQL Injection: error SQL detectado en campo '{field}'",
                    confidence=0.85,
                )

        # Detección time-based (si SLEEP/WAITFOR está en payload)
        time_payloads = ["sleep", "waitfor", "benchmark", "pg_sleep"]
        if any(tp in payload.lower() for tp in time_payloads):
            if resp_time > self.base_time + 2.5:
                return VulnResult(
                    vuln_type=VulnType.SQLI,
                    severity=SEVERITY_MAP[VulnType.SQLI],
                    field_name=field,
                    payload=payload,
                    evidence=f"Tiempo de respuesta: {resp_time:.1f}s (base: {self.base_time:.1f}s)",
                    description=f"SQL Injection time-based: delay detectado en campo '{field}'",
                    confidence=0.75,
                )

        # Detección por diferencia boolean-based
        boolean_indicators = ["OR '1'='1", "OR 1=1", "OR ''='", "OR 1=1--"]
        if any(ind in payload.upper() for ind in [i.upper() for i in boolean_indicators]):
            if len(self.base_response) > 0 and len(response) > len(self.base_response) * 1.03:
                return VulnResult(
                    vuln_type=VulnType.SQLI,
                    severity=SEVERITY_MAP[VulnType.SQLI],
                    field_name=field,
                    payload=payload,
                    evidence=f"Respuesta mayor con tautología: {len(response)} vs {len(self.base_response)} bytes (+{len(response)-len(self.base_response)})",
                    description=f"SQL Injection boolean-based: el payload tautológico devuelve más datos en '{field}'",
                    confidence=0.7,
                )

        # Detección: payload reflejado en respuesta indica falta de sanitización
        if payload in response and payload not in self.base_response:
            sql_keywords = ["'", "OR", "UNION", "SELECT", "--", ";"]
            if any(kw in payload.upper() for kw in sql_keywords):
                return VulnResult(
                    vuln_type=VulnType.SQLI,
                    severity=SEVERITY_MAP[VulnType.SQLI],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, payload, 150),
                    description=f"SQL Injection: payload SQL reflejado sin sanitizar en '{field}'",
                    confidence=0.65,
                )

        return None

    def _analyze_ssti(self, payload: str, response: str, status: int,
                      resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta SSTI: resultado de expresión matemática en respuesta."""
        # Si el payload es una expresión matemática, buscar el resultado
        math_checks = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
            ("{7*7}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("${{7*7}}", "49"),
            ("{{7*7*7}}", "343"),
            ("${7*7*7}", "343"),
        ]

        for template, expected in math_checks:
            if payload == template and expected in response and expected not in self.base_response:
                return VulnResult(
                    vuln_type=VulnType.SSTI,
                    severity=SEVERITY_MAP[VulnType.SSTI],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, expected, 100),
                    description=f"SSTI: expresión '{payload}' evaluada a '{expected}' en campo '{field}'",
                    confidence=0.95,
                )

        # Buscar patrones genéricos de SSTI
        response_lower = response.lower()
        for pattern in ssti.DETECTION_PATTERNS:
            if pattern in response_lower and pattern not in self.base_response.lower():
                if pattern not in ("49", "343"):  # Evitar falsos positivos con números
                    return VulnResult(
                        vuln_type=VulnType.SSTI,
                        severity=SEVERITY_MAP[VulnType.SSTI],
                        field_name=field,
                        payload=payload,
                        evidence=self._extract_context(response, pattern, 100),
                        description=f"SSTI: patrón '{pattern}' detectado en respuesta",
                        confidence=0.7,
                    )

        return None

    def _analyze_ldap(self, payload: str, response: str, status: int,
                      resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta LDAP Injection."""
        response_lower = response.lower()

        for pattern in ldap.DETECTION_PATTERNS:
            if pattern in response_lower and pattern not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.LDAP,
                    severity=SEVERITY_MAP[VulnType.LDAP],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"LDAP Injection: patrón '{pattern}' detectado en campo '{field}'",
                    confidence=0.7,
                )

        # Si el payload wildcard (*) devuelve más datos que la base
        if payload.strip() == "*" and len(response) > len(self.base_response) * 1.3:
            return VulnResult(
                vuln_type=VulnType.LDAP,
                severity=SEVERITY_MAP[VulnType.LDAP],
                field_name=field,
                payload=payload,
                evidence=f"Wildcard devuelve más datos: {len(response)} vs {len(self.base_response)}",
                description=f"LDAP Injection: wildcard acepta todos los registros en '{field}'",
                confidence=0.6,
            )

        return None

    def _analyze_cmdi(self, payload: str, response: str, status: int,
                      resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta Command Injection."""
        response_lower = response.lower()

        for pattern in cmdi.DETECTION_PATTERNS:
            if pattern.lower() in response_lower and pattern.lower() not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.CMDI,
                    severity=SEVERITY_MAP[VulnType.CMDI],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 150),
                    description=f"Command Injection: salida de comando detectada en campo '{field}'",
                    confidence=0.9,
                )

        # Time-based (sleep)
        if "sleep" in payload.lower() and resp_time > self.base_time + 2.5:
            return VulnResult(
                vuln_type=VulnType.CMDI,
                severity=SEVERITY_MAP[VulnType.CMDI],
                field_name=field,
                payload=payload,
                evidence=f"Delay detectado: {resp_time:.1f}s (base: {self.base_time:.1f}s)",
                description=f"Command Injection time-based en campo '{field}'",
                confidence=0.7,
            )

        return None

    def _analyze_nosql(self, payload: str, response: str, status: int,
                       resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta NoSQL Injection."""
        response_lower = response.lower()

        for pattern in nosql.DETECTION_PATTERNS:
            if pattern in response_lower and pattern not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.NOSQL,
                    severity=SEVERITY_MAP[VulnType.NOSQL],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"NoSQL Injection: patrón '{pattern}' detectado en campo '{field}'",
                    confidence=0.7,
                )

        # Boolean-based: si $ne o $gt devuelve más datos
        if ('$ne' in payload or '$gt' in payload) and len(response) > len(self.base_response) * 1.3:
            return VulnResult(
                vuln_type=VulnType.NOSQL,
                severity=SEVERITY_MAP[VulnType.NOSQL],
                field_name=field,
                payload=payload,
                evidence=f"Respuesta mayor con operador NoSQL: {len(response)} vs {len(self.base_response)}",
                description=f"NoSQL Injection: bypass de lógica detectado en campo '{field}'",
                confidence=0.6,
            )

        return None

    def _analyze_xxe(self, payload: str, response: str, status: int,
                     resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta XXE."""
        response_lower = response.lower()

        for pattern in xxe.DETECTION_PATTERNS:
            if pattern.lower() in response_lower and pattern.lower() not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.XXE,
                    severity=SEVERITY_MAP[VulnType.XXE],
                    field_name=field,
                    payload=payload[:200],
                    evidence=self._extract_context(response, pattern, 150),
                    description=f"XXE: contenido sensible detectado en respuesta del campo '{field}'",
                    confidence=0.85,
                )

        return None

    def _analyze_lfi(self, payload: str, response: str, status: int,
                     resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta Local File Inclusion."""
        response_lower = response.lower()

        for pattern in lfi.DETECTION_PATTERNS:
            if pattern.lower() in response_lower and pattern.lower() not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.LFI,
                    severity=SEVERITY_MAP[VulnType.LFI],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 150),
                    description=f"LFI: contenido de archivo detectado en campo '{field}'",
                    confidence=0.9,
                )

        return None

    def _analyze_redirect(self, payload: str, response: str, status: int,
                          resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta Open Redirect."""
        # Verificar si la respuesta tiene redirección a host externo
        if status in (301, 302, 303, 307, 308):
            return VulnResult(
                vuln_type=VulnType.OPEN_REDIRECT,
                severity=SEVERITY_MAP[VulnType.OPEN_REDIRECT],
                field_name=field,
                payload=payload,
                evidence=f"Redirección HTTP {status} detectada",
                description=f"Open Redirect: el servidor redirige con payload en campo '{field}'",
                confidence=0.7,
            )

        # Verificar meta refresh o javascript redirect en respuesta
        redirect_patterns = [
            "window.location", "document.location", "location.href",
            "location.replace", 'http-equiv="refresh"', "meta http-equiv",
        ]
        response_lower = response.lower()
        for pattern in redirect_patterns:
            if pattern in response_lower and "evil.com" in response_lower:
                return VulnResult(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    severity=SEVERITY_MAP[VulnType.OPEN_REDIRECT],
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"Open Redirect: redirección detectada en campo '{field}'",
                    confidence=0.75,
                )

        return None

    def _analyze_idor(self, payload: str, response: str, status: int,
                      resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta IDOR comparando respuestas con diferentes IDs."""
        # Si cambiamos el ID y obtenemos 200 con contenido diferente
        if status == 200 and response != self.base_response and len(response) > 100:
            # Verificar que la respuesta contiene datos de otro usuario
            response_lower = response.lower()
            for pattern in ["username", "email", "profile", "user"]:
                if pattern in response_lower:
                    return VulnResult(
                        vuln_type=VulnType.IDOR,
                        severity=SEVERITY_MAP[VulnType.IDOR],
                        field_name=field,
                        payload=payload,
                        evidence=f"Acceso con ID={payload} retorna datos ({len(response)} bytes)",
                        description=f"IDOR: acceso a recursos de otros usuarios con ID modificado en '{field}'",
                        confidence=0.5,
                    )

        return None

    def _analyze_logic(self, payload: str, response: str, status: int,
                       resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta errores lógicos: inputs inválidos aceptados."""
        # Si un campo vacío o inválido es aceptado (200 sin error)
        invalid_payloads = ["", " ", "-1", "-999999", "aaa@", "<>"]

        if payload in invalid_payloads and status == 200:
            response_lower = response.lower()
            # Buscar indicios de aceptación
            error_patterns = ["error", "invalid", "required", "failed", "wrong", "incorrect"]
            has_error = any(p in response_lower for p in error_patterns)

            if not has_error and len(response) > 50:
                desc_map = {
                    "": "campo vacío aceptado",
                    " ": "campo con solo espacios aceptado",
                    "-1": "valor negativo aceptado",
                    "-999999": "valor extremadamente negativo aceptado",
                    "aaa@": "email inválido aceptado",
                    "<>": "caracteres especiales aceptados sin sanitizar",
                }
                return VulnResult(
                    vuln_type=VulnType.LOGIC,
                    severity=SEVERITY_MAP[VulnType.LOGIC],
                    field_name=field,
                    payload=payload if payload else "(vacío)",
                    evidence=f"Status {status}, sin mensaje de error, {len(response)} bytes",
                    description=f"Error lógico: {desc_map.get(payload, 'input inválido aceptado')} en '{field}'",
                    confidence=0.5,
                )

        return None

    def _analyze_csrf(self, field: str, form: Optional[FormData] = None) -> Optional[VulnResult]:
        """Detecta ausencia de protección CSRF."""
        if form and not form.has_csrf_token:
            if form.method.upper() == "POST":
                return VulnResult(
                    vuln_type=VulnType.CSRF,
                    severity=SEVERITY_MAP[VulnType.CSRF],
                    field_name="(formulario)",
                    payload="N/A - análisis estático",
                    evidence=f"Formulario POST sin token CSRF. Campos: {[f.name for f in form.fields]}",
                    description="CSRF: formulario POST sin token anti-CSRF detectado",
                    confidence=0.8,
                )
        return None

    def _extract_context(self, text: str, search: str, context_chars: int = 100) -> str:
        """Extrae contexto alrededor de una coincidencia."""
        idx = text.lower().find(search.lower())
        if idx == -1:
            return text[:200]
        start = max(0, idx - context_chars)
        end = min(len(text), idx + len(search) + context_chars)
        excerpt = text[start:end]
        if start > 0:
            excerpt = "..." + excerpt
        if end < len(text):
            excerpt = excerpt + "..."
        return excerpt
