
import time
import json as _json
import requests
from typing import List, Optional

from gung12.models import FormData, VulnType, VulnResult, ScanResult
from gung12.payloads import get_payloads
from gung12.analyzer import ResponseAnalyzer


_REFLECTION_INDICATORS = {VulnType.XSS, VulnType.HTMLI}
_REFLECTION_SUSCEPTIBLE = {VulnType.SQLI, VulnType.CMDI, VulnType.NOSQL, VulnType.SSTI,
                          VulnType.XXE, VulnType.OPEN_REDIRECT}

_BLOCK_MARKERS = (
    "just a moment", "checking your browser", "cf-mitigated", "_cf_chl",
    "/cdn-cgi/challenge", "attention required", "cloudflare to restrict",
    "access denied", "you have been blocked", "request unsuccessful. incapsula",
    "captcha-delivery", "enable javascript and cookies to continue",
    "ddos protection by", "ray id:",
)
_BLOCK_STATUS = {403, 429, 503}


class ScanEngine:

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10,
                 verbose: bool = False, use_spa: bool = False,
                 waf_bypass: bool = False):
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.verbose = verbose
        self.use_spa = use_spa
        self.waf_bypass = waf_bypass
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        )
        self.session.headers.update({"User-Agent": self.user_agent})

    def scan(self, form: FormData, test_types: List[VulnType],
             full_mode: bool = False, callback=None) -> ScanResult:

        base_response, base_status, base_time = self._send_base_request(form)

        if self._looks_like_block(base_response, base_status):
            if callback:
                callback(f"[BLOQUEO] La respuesta parece un bloqueo de WAF/anti-bot "
                         f"(estado {base_status}). Resultados no fiables; escaneo detenido.")
            return ScanResult(
                url=form.url,
                form=form,
                vulnerabilities=[],
                scan_mode="full" if full_mode else "quick",
                blocked=True,
            )

        analyzer = ResponseAnalyzer(
            base_response=base_response,
            base_status=base_status,
            base_time=base_time,
        )

        all_vulns: List[VulnResult] = []
        reflective_fields: set = set()

        total_types = len(test_types)
        for idx, vuln_type in enumerate(test_types, 1):
            if callback:
                callback(f"[{idx}/{total_types}] Probando {vuln_type.value}...")

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

            payloads = get_payloads(vuln_type, full_mode)
            injectable = form.injectable_fields

            if not injectable:
                if callback:
                    callback(f"  Sin campos inyectables para {vuln_type.value}")
                continue

            for field in injectable:
                for payload in payloads:
                    payload_list = [payload]
                    if self.waf_bypass:
                        from gung12.waf_bypass import generate_bypass_variants
                        payload_list += generate_bypass_variants(payload, vuln_type.value)

                    for actual_payload in payload_list:
                        response_text, status_code, resp_time = self._send_payload(
                            form, field.name, actual_payload
                        )

                        if (len(actual_payload) >= 4
                                and actual_payload in response_text
                                and actual_payload not in base_response):
                            reflective_fields.add(field.name)

                        result = analyzer.analyze(
                            vuln_type=vuln_type,
                            payload=actual_payload,
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
                                    callback(f"  [!] {vuln_type.value.upper()} detectado en '{field.name}': {actual_payload[:60]}")
                            break


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

        self._apply_reflection_filter(all_vulns, reflective_fields)

        return ScanResult(
            url=form.url,
            form=form,
            vulnerabilities=all_vulns,
            scan_mode="full" if full_mode else "quick",
        )

    @staticmethod
    def _looks_like_block(text: str, status: int) -> bool:
        if status in _BLOCK_STATUS:
            return True
        low = (text or "").lower()
        return any(marker in low for marker in _BLOCK_MARKERS)

    def _send_base_request(self, form: FormData) -> tuple:
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
        data = form.submit_data

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

    def _apply_reflection_filter(self, vulns: List[VulnResult],
                                 reflective_fields: Optional[set] = None) -> None:
        reflected_fields = {
            v.field_name for v in vulns
            if v.vuln_type in _REFLECTION_INDICATORS and v.confidence >= 0.80
        }
        if reflective_fields:
            reflected_fields |= reflective_fields
        for v in vulns:
            if v.field_name in reflected_fields and v.vuln_type in _REFLECTION_SUSCEPTIBLE:
                v.confidence = min(v.confidence, 0.55)
                v.reflection_artifact = True
                v.description += " [posible artefacto de reflexión — verificar manualmente]"

    def _scan_dom_xss(self, form: FormData, payloads: List[str]) -> List[VulnResult]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return []

        trigger_payloads = [p for p in payloads if "alert" in p.lower() or "confirm" in p.lower()]
        if not trigger_payloads:
            return []

        results: List[VulnResult] = []

        pw_cookies = []
        if self.session.cookies:
            from urllib.parse import urlparse
            parsed = urlparse(form.url)
            pw_cookies = [
                {"name": c.name, "value": c.value,
                 "domain": parsed.netloc, "path": "/"}
                for c in self.session.cookies
            ]

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)

                for field in form.injectable_fields:
                    context = browser.new_context(user_agent=self.user_agent)
                    if pw_cookies:
                        context.add_cookies(pw_cookies)
                    page = context.new_page()

                    dialog_info = {"fired": False, "message": ""}

                    def _on_dialog(dialog):
                        dialog_info["fired"] = True
                        dialog_info["message"] = dialog.message
                        dialog.dismiss()

                    page.on("dialog", _on_dialog)

                    field_hit = False
                    for payload in trigger_payloads:
                        dialog_info["fired"] = False
                        dialog_info["message"] = ""

                        try:
                            page.goto(form.url, timeout=self.timeout * 1000)
                            page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)
                            sel = f"input[name='{field.name}'], textarea[name='{field.name}']"
                            try:
                                page.locator(sel).first.fill(payload, timeout=3000)
                            except Exception:
                                continue
                            page.keyboard.press("Enter")
                            page.wait_for_timeout(2000)
                        except Exception:
                            continue

                        if dialog_info["fired"]:
                            results.append(VulnResult(
                                vuln_type=VulnType.XSS,
                                field_name=field.name,
                                payload=payload,
                                evidence=f"Alert JavaScript ejecutado: '{dialog_info['message']}'",
                                description=f"DOM XSS: alert() disparado por payload en campo '{field.name}'",
                                confidence=0.98,
                            ))
                            field_hit = True
                            break

                    context.close()
                    if field_hit:
                        continue

                browser.close()

        except Exception:
            pass

        return results

    def _send_file_payload(self, form: FormData, field_name: str, file_tuple: tuple) -> tuple:
        filename, content, mime_type = file_tuple
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
