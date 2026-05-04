"""Módulo 2: Motor de pruebas (Payload Engine).

Orquesta el escaneo: para cada tipo de vulnerabilidad y cada campo del formulario,
envía payloads y analiza las respuestas.
"""

import time
import json as _json
import requests
from typing import List, Optional

from gung12.models import FormData, VulnType, VulnResult, ScanResult
from gung12.payloads import get_payloads
from gung12.analyzer import ResponseAnalyzer


class ScanEngine:
    """Motor de pruebas que lanza payloads contra formularios."""

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10,
                 verbose: bool = False, use_spa: bool = False):
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.verbose = verbose
        self.use_spa = use_spa
        self.session.headers.update({
            "User-Agent": "Gung12/1.0 (Security Scanner - Authorized Testing Only)"
        })

    def scan(self, form: FormData, test_types: List[VulnType],
             full_mode: bool = False, callback=None) -> ScanResult:
        """Ejecuta un escaneo completo contra un formulario."""

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
                file_payloads = get_payloads(vuln_type, full_mode)
                for field in file_fields:
                    for payload_tuple in file_payloads:
                        response_text, status_code, resp_time = self._send_file_payload(
                            form, field.name, payload_tuple
                        )

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


        # DOM XSS pass: solo cuando --spa activo
        if self.use_spa and VulnType.XSS in test_types:
            if callback:
                callback("Probando DOM XSS (Playwright)...")
            dom_results = self._scan_dom_xss(form, get_payloads(VulnType.XSS, full_mode))
            for result in dom_results:
                if not any(v.vuln_type == result.vuln_type and v.field_name == result.field_name
                           for v in all_vulns):
                    all_vulns.append(result)
                    if callback:
                        callback(f"  [!] DOM XSS detectado en '{result.field_name}': {result.payload[:60]}")

        return ScanResult(
            url=form.url,
            form=form,
            vulnerabilities=all_vulns,
            scan_mode="full" if full_mode else "quick",
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
            return resp.text, resp.status_code, elapsed
        except requests.RequestException:
            return "", 0, 0.0

    def _send_payload(self, form: FormData, field_name: str, payload: str) -> tuple:
        """Envía una petición con un payload en un campo específico."""
        data = form.submit_data

        # Fix NoSQL en APIs JSON: los operadores MongoDB deben enviarse como objetos,
        # no como strings. Si el payload es JSON válido y el body es JSON, parsearlo.
        if form.body_type == "json" and payload.strip().startswith("{"):
            try:
                data[field_name] = _json.loads(payload)
            except (_json.JSONDecodeError, ValueError):
                data[field_name] = payload
        else:
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

    def _scan_dom_xss(self, form: FormData, payloads: List[str]) -> List[VulnResult]:
        """Detecta DOM XSS usando Playwright: captura alert() disparados por payloads.

        Sólo activo cuando use_spa=True. Usa page.on('dialog') para interceptar
        alerts JavaScript. Confianza 0.98 — un alert disparado es confirmación directa.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return []

        # Solo payloads que intentan disparar alert() / confirm() / prompt()
        trigger_payloads = [p for p in payloads if "alert" in p.lower() or "confirm" in p.lower()]
        if not trigger_payloads:
            return []

        results: List[VulnResult] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)

                for field in form.injectable_fields:
                    for payload in trigger_payloads:
                        dialog_info = {"fired": False, "message": ""}

                        def _on_dialog(dialog, _info=dialog_info):
                            _info["fired"] = True
                            _info["message"] = dialog.message
                            dialog.dismiss()

                        context = browser.new_context()
                        page = context.new_page()
                        page.on("dialog", _on_dialog)

                        # Pasar cookies de sesión
                        if self.session.cookies:
                            from urllib.parse import urlparse
                            parsed = urlparse(form.url)
                            pw_cookies = [
                                {"name": c.name, "value": c.value,
                                 "domain": parsed.netloc, "path": "/"}
                                for c in self.session.cookies
                            ]
                            if pw_cookies:
                                context.add_cookies(pw_cookies)  # type: ignore[arg-type]

                        try:
                            page.goto(form.url, timeout=self.timeout * 1000)
                            page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)

                            # Rellenar el campo con el payload
                            sel = f"input[name='{field.name}'], textarea[name='{field.name}']"
                            try:
                                page.locator(sel).first.fill(payload, timeout=3000)
                            except Exception:
                                context.close()
                                continue

                            # Enviar el formulario
                            page.keyboard.press("Enter")
                            page.wait_for_timeout(2000)

                        except Exception:
                            context.close()
                            continue
                        finally:
                            context.close()

                        if dialog_info["fired"]:
                            results.append(VulnResult(
                                vuln_type=VulnType.XSS,
                                field_name=field.name,
                                payload=payload,
                                evidence=f"Alert JavaScript ejecutado: '{dialog_info['message']}'",
                                description=f"DOM XSS: alert() disparado por payload en campo '{field.name}'",
                                confidence=0.98,
                            ))
                            # Un resultado por campo es suficiente
                            break

                browser.close()

        except Exception:
            pass

        return results

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
