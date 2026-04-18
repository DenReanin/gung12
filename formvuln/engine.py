"""Módulo 2: Motor de pruebas (Payload Engine).

Orquesta el escaneo: para cada tipo de vulnerabilidad y cada campo del formulario,
envía payloads y analiza las respuestas.
"""

import time
import requests
from typing import List, Optional

from formvuln.models import FormData, VulnType, VulnResult, ScanResult
from formvuln.payloads import get_payloads
from formvuln.analyzer import ResponseAnalyzer


class ScanEngine:
    """Motor de pruebas que lanza payloads contra formularios."""

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10,
                 verbose: bool = False):
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.verbose = verbose
        self.total_requests = 0
        self.session.headers.update({
            "User-Agent": "FormVuln/1.0 (Security Scanner - Authorized Testing Only)"
        })

    def scan(self, form: FormData, test_types: List[VulnType],
             full_mode: bool = False, callback=None) -> ScanResult:
        """Ejecuta un escaneo completo contra un formulario."""
        start_time = time.time()
        self.total_requests = 0

        # Obtener respuesta base
        base_response, base_status, base_time = self._send_base_request(form)

        analyzer = ResponseAnalyzer(
            base_response=base_response,
            base_status=base_status,
            base_time=base_time,
        )

        all_vulns: List[VulnResult] = []

        for vuln_type in test_types:
            if callback:
                callback(f"Probando {vuln_type.value}...")

            # CSRF es análisis estático (no necesita payloads)
            if vuln_type == VulnType.CSRF:
                result = analyzer.analyze(
                    vuln_type=VulnType.CSRF,
                    payload="",
                    response_text="",
                    status_code=0,
                    response_time=0,
                    field_name="(formulario)",
                    form=form,
                )
                if result:
                    all_vulns.append(result)
                    if callback:
                        callback(f"  [!] CSRF detectado: sin token anti-CSRF")
                continue

            # Para el resto, obtener payloads e inyectar
            payloads = get_payloads(vuln_type, full_mode)
            injectable = form.injectable_fields

            if not injectable:
                if callback:
                    callback(f"  Sin campos inyectables para {vuln_type.value}")
                continue

            for field in injectable:
                for payload in payloads:
                    response_text, status_code, resp_time = self._send_payload(
                        form, field.name, payload
                    )
                    self.total_requests += 1

                    result = analyzer.analyze(
                        vuln_type=vuln_type,
                        payload=payload,
                        response_text=response_text,
                        status_code=status_code,
                        response_time=resp_time,
                        field_name=field.name,
                        form=form,
                    )

                    if result:
                        # Evitar duplicados del mismo tipo+campo
                        if not any(v.vuln_type == result.vuln_type and v.field_name == result.field_name
                                   for v in all_vulns):
                            all_vulns.append(result)
                            if callback:
                                callback(f"  [!] {vuln_type.value.upper()} detectado en '{field.name}': {payload[:60]}")

        duration = time.time() - start_time

        return ScanResult(
            url=form.url,
            form=form,
            vulnerabilities=all_vulns,
            scan_mode="full" if full_mode else "quick",
            duration_seconds=round(duration, 2),
            total_requests=self.total_requests,
        )

    def _send_base_request(self, form: FormData) -> tuple:
        """Envía una petición base con datos normales."""
        data = form.submit_data
        try:
            start = time.time()
            if form.method == "GET":
                resp = self.session.get(form.action, params=data, timeout=self.timeout)
            else:
                resp = self.session.post(form.action, data=data, timeout=self.timeout)
            elapsed = time.time() - start
            self.total_requests += 1
            return resp.text, resp.status_code, elapsed
        except requests.RequestException:
            return "", 0, 0.0

    def _send_payload(self, form: FormData, field_name: str, payload: str) -> tuple:
        """Envía una petición con un payload en un campo específico."""
        data = form.submit_data
        data[field_name] = payload

        try:
            start = time.time()
            if form.method == "GET":
                resp = self.session.get(
                    form.action, params=data, timeout=self.timeout,
                    allow_redirects=False,
                )
            else:
                resp = self.session.post(
                    form.action, data=data, timeout=self.timeout,
                    allow_redirects=False,
                )
            elapsed = time.time() - start
            return resp.text, resp.status_code, elapsed
        except requests.Timeout:
            return "", 0, self.timeout
        except requests.RequestException:
            return "", 0, 0.0
