"""Módulo 3: Analizador de respuestas.

Compara la respuesta base con las respuestas tras inyección de payloads
para detectar indicios de vulnerabilidades.
"""

import re
import time
from typing import Optional

from gung12.models import VulnType, VulnResult, FormData
from gung12.payloads import xss, sqli, ssti, xpath, cmdi, nosql, xxe, file_upload, open_redirect, htmli


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
            VulnType.XPATH: self._analyze_xpath,
            VulnType.CMDI: self._analyze_cmdi,
            VulnType.NOSQL: self._analyze_nosql,
            VulnType.XXE: self._analyze_xxe,
            VulnType.FILE_UPLOAD: self._analyze_file_upload,
            VulnType.OPEN_REDIRECT: self._analyze_redirect,
            VulnType.HTMLI: self._analyze_htmli,
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
                        field_name=field,
                        payload=payload,
                        evidence=self._extract_context(response, pattern, 100),
                        description=f"SSTI: patrón '{pattern}' detectado en respuesta",
                        confidence=0.7,
                    )

        return None

    def _analyze_xpath(self, payload: str, response: str, status: int,
                       resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta XPath Injection: errores de motor XPath o comportamiento boolean-based."""
        response_lower = response.lower()

        # Técnica 1: errores específicos del motor XPath
        for pattern in xpath.DETECTION_PATTERNS:
            if re.search(pattern, response_lower) and not re.search(pattern, self.base_response.lower()):
                return VulnResult(
                    vuln_type=VulnType.XPATH,
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"XPath Injection: error de motor XPath detectado en campo '{field}'",
                    confidence=0.85,
                )

        # Técnica 2: boolean-based — payload tautológico devuelve más contenido
        tautological = ["' or '1'='1", "' or 1=1 or 'a'='b", "x' or 'x'='x"]
        if payload in tautological and len(response) > len(self.base_response) * 1.10:
            return VulnResult(
                vuln_type=VulnType.XPATH,
                field_name=field,
                payload=payload,
                evidence=f"Respuesta tautológica: {len(response)} bytes vs base {len(self.base_response)} bytes",
                description=f"XPath Injection boolean-based: payload tautológico devuelve más datos en '{field}'",
                confidence=0.70,
            )

        # Técnica 3: error 500 inesperado al inyectar sintaxis XPath
        if status == 500 and self.base_status != 500:
            return VulnResult(
                vuln_type=VulnType.XPATH,
                field_name=field,
                payload=payload,
                evidence=f"Error HTTP 500 con payload XPath (base: {self.base_status})",
                description=f"XPath Injection: error interno del servidor al procesar sintaxis XPath en '{field}'",
                confidence=0.60,
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
                    field_name=field,
                    payload=payload[:200],
                    evidence=self._extract_context(response, pattern, 150),
                    description=f"XXE: contenido sensible detectado en respuesta del campo '{field}'",
                    confidence=0.85,
                )

        return None

    def _analyze_file_upload(self, payload: str, response: str, status: int,
                             resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta carga de archivos sin restricciones.

        El payload es el nombre del archivo (filename de la tupla). El engine
        envía la petición multipart y aquí se analiza si el servidor aceptó
        el fichero sin rechazar su extensión o tipo MIME.
        """
        response_lower = response.lower()

        # Detección de alta confianza: probe ejecutado remotamente
        if "gung12_probe" in response_lower:
            return VulnResult(
                vuln_type=VulnType.FILE_UPLOAD,
                field_name=field,
                payload=payload,
                evidence=self._extract_context(response, "gung12_probe", 150),
                description=f"Carga de archivos sin restricciones CRÍTICA: el fichero PHP fue ejecutado en el servidor (campo '{field}')",
                confidence=0.95,
            )

        # Detección media: servidor reporta éxito con fichero malicioso
        for pattern in file_upload.DETECTION_PATTERNS:
            if pattern in response_lower and pattern not in self.base_response.lower():
                # Verificar que el payload tiene extensión ejecutable
                exec_exts = [".php", ".phtml", ".php3", ".php5", ".asp", ".aspx", ".shtml", ".htaccess", ".svg"]
                is_exec = any(ext in payload.lower() for ext in exec_exts)
                if is_exec:
                    return VulnResult(
                        vuln_type=VulnType.FILE_UPLOAD,
                        field_name=field,
                        payload=payload,
                        evidence=self._extract_context(response, pattern, 150),
                        description=f"Carga de archivos sin restricciones: fichero con extensión ejecutable aceptado en campo '{field}'",
                        confidence=0.75,
                    )

        return None

    def _analyze_htmli(self, payload: str, response: str, status: int,
                       resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta HTML Injection: etiquetas HTML reflejadas sin escapar.

        Diferencia con XSS: los payloads no contienen atributos de evento JS.
        Si el HTML aparece sin encoding en la respuesta, hay inyección HTML
        aunque no haya ejecución de scripts.
        """
        # Reflexión directa del payload (sin escapar)
        if payload.lower() in response.lower():
            # Asegurar que no está codificado como &lt; o &gt;
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            if escaped not in response:
                return VulnResult(
                    vuln_type=VulnType.HTMLI,
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, payload, 100),
                    description=f"HTML Injection: etiquetas HTML reflejadas sin codificar en campo '{field}'",
                    confidence=0.85,
                )

        # Verificar patrones de detección
        response_lower = response.lower()
        for pattern in htmli.DETECTION_PATTERNS:
            if pattern.lower() in response_lower and pattern.lower() not in self.base_response.lower():
                return VulnResult(
                    vuln_type=VulnType.HTMLI,
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"HTML Injection: patrón HTML detectado sin escapar en campo '{field}'",
                    confidence=0.75,
                )

        return None

    def _analyze_redirect(self, payload: str, response: str, status: int,
                          resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta Open Redirect."""
        # Verificar si la respuesta tiene redirección a host externo
        if status in (301, 302, 303, 307, 308):
            return VulnResult(
                vuln_type=VulnType.OPEN_REDIRECT,
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
                    field_name=field,
                    payload=payload,
                    evidence=self._extract_context(response, pattern, 100),
                    description=f"Open Redirect: redirección detectada en campo '{field}'",
                    confidence=0.75,
                )

        return None

    def _analyze_logic(self, payload: str, response: str, status: int,
                       resp_time: float, field: str) -> Optional[VulnResult]:
        """Detecta errores lógicos: inputs inválidos aceptados.

        Umbral conservador para evitar falsos positivos en APIs REST con
        respuestas JSON cortas pero válidas. Solo reporta cuando:
        - status 200, sin patrones de error
        - respuesta significativamente larga (>200 bytes)
        - respuesta comparable en tamaño a la respuesta base (no es error genérico)
        - aparece al menos un indicio explícito de aceptación
        """
        invalid_payloads = ["", " ", "-1", "-999999", "aaa@", "<>"]

        if payload not in invalid_payloads or status != 200:
            return None

        response_lower = response.lower()

        # Ampliado: cubrir más variantes en EN/ES
        error_patterns = [
            "error", "invalid", "required", "failed", "wrong", "incorrect",
            "not valid", "must be", "cannot be", "no válido", "obligatorio",
            "incorrecto", "no permitido", "rechazad",
        ]
        if any(p in response_lower for p in error_patterns):
            return None

        # Umbral subido: <200 bytes es probablemente respuesta JSON corta
        if len(response) <= 200:
            return None

        # Comparación con respuesta base: si difiere demasiado, no es aceptación silenciosa
        if self.base_response and len(self.base_response) > 0:
            ratio = len(response) / max(len(self.base_response), 1)
            if ratio < 0.5 or ratio > 2.0:
                return None

        # Requerir un indicio EXPLÍCITO de aceptación
        acceptance_patterns = [
            "success", "accepted", "welcome", "created", "updated",
            "submitted", "registered", "saved", "ok", "completed",
            "bienvenido", "guardado", "enviado", "creado",
        ]
        has_acceptance = any(p in response_lower for p in acceptance_patterns)
        if not has_acceptance:
            return None

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
            field_name=field,
            payload=payload if payload else "(vacío)",
            evidence=f"Status {status}, indicio de aceptación detectado, {len(response)} bytes",
            description=f"Error lógico: {desc_map.get(payload, 'input inválido aceptado')} en '{field}'",
            confidence=0.55,
        )

    def _analyze_csrf(self, field: str, form: Optional[FormData] = None) -> Optional[VulnResult]:
        """Detecta ausencia de protección CSRF."""
        if form and not form.has_csrf_token:
            if form.method.upper() == "POST":
                # APIs REST/JSON: probablemente usan JWT/Bearer en headers (stateless).
                # CSRF requiere cookies de sesión para ser explotable; si el cuerpo
                # es JSON, reducir a INFO para evitar falsos positivos en APIs JWT.
                if getattr(form, "body_type", "form") == "json":
                    return VulnResult(
                        vuln_type=VulnType.CSRF,
                        field_name="(formulario)",
                        payload="N/A - análisis estático",
                        evidence=f"API JSON sin token CSRF explícito. Campos: {[f.name for f in form.fields]}",
                        description="CSRF (INFO): API REST/JSON sin token — verificar si usa JWT/Bearer; si usa cookies de sesión, vulnerabilidad real",
                        confidence=0.4,
                    )
                return VulnResult(
                    vuln_type=VulnType.CSRF,
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
