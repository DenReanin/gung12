"""Módulo 2: Motor de pruebas (Payload Engine).

Orquesta el escaneo: para cada tipo de vulnerabilidad y cada campo del formulario,
envía payloads y analiza las respuestas.
"""

import time
import requests
from typing import List, Optional

from gung12.models import FormData, VulnType, VulnResult, ScanResult
from gung12.payloads import get_payloads
from gung12.analyzer import ResponseAnalyzer


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
            "User-Agent": "Gung12/1.0 (Security Scanner - Authorized Testing Only)"
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

            # FILE_UPLOAD requiere campos file y envío multipart
            if vuln_type == VulnType.FILE_UPLOAD:
                file_fields = form.file_fields
                if not file_fields:
                    if callback:
                        callback(f"  Sin campos <input type=file> para file_upload")
                    continue
                for field in file_fields:
                    for payload_tuple in payloads:
                        response_text, status_code, resp_time = self._send_file_payload(
                            form, field.name, payload_tuple
                        )
                        self.total_requests += 1

                        filename = payload_tuple[0] if isinstance(payload_tuple, tuple) else payload_tuple
                        result = analyzer.analyze(
                            vuln_type=vuln_type,
                            payload=filename,
                            response_text=response_text,
                            status_code=status_code,
                            response_time=resp_time,
                            field_name=field.name,
                            form=form,
                        )

                        if result:
                            if not any(v.vuln_type == result.vuln_type and v.field_name == result.field_name
                                       for v in all_vulns):
                                all_vulns.append(result)
                                if callback:
                                    callback(f"  [!] FILE_UPLOAD detectado en '{field.name}': {filename[:60]}")
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
            elif form.body_type == "json":
                resp = self.session.post(form.action, json=data, timeout=self.timeout)
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
            elif form.body_type == "json":
                resp = self.session.post(
                    form.action, json=data, timeout=self.timeout,
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

    def _send_file_payload(self, form: FormData, field_name: str, file_tuple: tuple) -> tuple:
        """Envía una petición multipart/form-data con un archivo malicioso."""
        filename, content, mime_type = file_tuple
        # Datos del formulario excluyendo el campo file
        data = {k: v for k, v in form.submit_data.items() if k != field_name}
        files = {field_name: (filename, content.encode("utf-8", errors="replace"), mime_type)}

        try:
            start = time.time()
            resp = self.session.post(
                form.action, data=data, files=files,
                timeout=self.timeout, allow_redirects=False,
            )
            elapsed = time.time() - start
            return resp.text, resp.status_code, elapsed
        except requests.Timeout:
            return "", 0, self.timeout
        except requests.RequestException:
            return "", 0, 0.0
