"""Módulo de parsing de formularios en SPAs (Single Page Applications).

Extiende FormParser usando Playwright para renderizar el JavaScript antes
de extraer los formularios. Permite analizar aplicaciones Angular, React y Vue.

Requisitos:
    pip install playwright
    playwright install chromium

Target recomendado para pruebas: OWASP Juice Shop
    docker run -p 3000:3000 bkimminich/juice-shop
    URL de login: http://localhost:3000/#/login
"""

import sys
from typing import List, Optional

from gung12.parser import FormParser
from gung12.models import FormData, FormField


def _install_chromium() -> bool:
    """Instala el navegador Chromium de Playwright.

    Usa el driver que Playwright trae empaquetado, por lo que funciona tanto
    en una instalación con pip como en el ejecutable generado con PyInstaller
    (donde no existe ``python -m playwright``). Devuelve True si la instalación
    termina correctamente.
    """
    import subprocess
    try:
        from playwright._impl._driver import compute_driver_executable
    except Exception:
        return False
    try:
        from playwright._impl._driver import get_driver_env
        env = get_driver_env()
    except Exception:
        env = None
    try:
        driver = compute_driver_executable()
        cmd = list(driver) if isinstance(driver, (list, tuple)) else [driver]
        cmd += ["install", "chromium"]
        return subprocess.run(cmd, env=env).returncode == 0
    except Exception:
        return False


class SPAFormParser(FormParser):
    """Parser de formularios que usa Playwright para renderizar SPAs.

    Hereda la lógica de extracción de FormParser. Sobreescribe parse_forms()
    para realizar la extracción del HTML y, si es necesario, el descubrimiento
    del endpoint REST en una única sesión de navegador. Esto reduce a la mitad
    el coste de lanzar Chromium.
    """

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10,
                 headless: bool = True, wait_state: str = "networkidle"):
        super().__init__(cookies=cookies, timeout=timeout)
        self.headless = headless
        self.wait_state = wait_state  # "networkidle", "domcontentloaded", "load"

    def parse_forms(self, url: str) -> List[FormData]:
        """Extrae formularios del HTML renderizado. Incluye fallback para SPAs sin <form>.

        Unifica fetch + discovery en una sola sesión Playwright cuando es necesario.
        """
        from bs4 import BeautifulSoup

        # Una sola sesión Playwright para todo: HTML + (opcional) descubrimiento de endpoint
        html, endpoint_info = self._render_and_maybe_discover(url, discover=False)
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        if forms:
            return [self._parse_single_form(form_tag, url) for form_tag in forms]

        # Fallback: Angular Material y similares que renderizan inputs sin <form>
        injectable_types = {"text", "email", "password", "search", "tel", "url", "number"}
        skip_types_fb = {"submit", "button", "image", "reset", "hidden", "checkbox", "radio"}
        fields = []
        for input_tag in soup.find_all("input"):
            name = input_tag.get("name")
            if not name:
                continue
            ftype = (str(input_tag.get("type") or "text")).lower()
            if ftype in skip_types_fb:
                continue
            if ftype in injectable_types:
                fields.append(FormField(
                    name=str(name),
                    field_type=ftype,
                    value=str(input_tag.get("value") or ""),
                    required=input_tag.get("required") is not None,
                ))
        for textarea in soup.find_all("textarea"):
            name = textarea.get("name")
            if name:
                fields.append(FormField(
                    name=str(name),
                    field_type="textarea",
                    value=textarea.string or "",
                ))

        if not fields:
            return []

        # Se necesita descubrir el endpoint real: segunda sesión Playwright pero
        # solo aquí (no en el flujo normal con <form> presente).
        _, endpoint_info = self._render_and_maybe_discover(url, discover=True, fields=fields)

        return [FormData(
            url=url,
            action=endpoint_info["action"],
            method="POST",
            fields=fields,
            has_csrf_token=False,
            csrf_field=None,
            body_type=endpoint_info["body_type"],
        )]

    def _render_and_maybe_discover(self, url: str, discover: bool = False,
                                   fields: Optional[List[FormField]] = None) -> tuple:
        """Abre Chromium una sola vez, obtiene el HTML renderizado y, si
        ``discover`` está activo, intenta capturar el endpoint POST real
        enviando el formulario con valores dummy.

        Devuelve (html, endpoint_info). endpoint_info por defecto apunta a la
        URL original con body_type='form'.
        """
        endpoint_info = {"action": url, "body_type": "form"}
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            if discover:
                return ("", endpoint_info)
            raise ImportError(
                "El modo --spa requiere Playwright. Instálalo con:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            ) from e

        html = ""
        try:
            with sync_playwright() as p:
                try:
                    browser = p.chromium.launch(headless=self.headless)
                except Exception as e:
                    msg = str(e)
                    browser_missing = ("Executable doesn't exist" in msg
                                       or "playwright install" in msg.lower())
                    if discover or not browser_missing:
                        raise
                    # Autoinstalación de Chromium en el primer uso de --spa
                    print("[*] Chromium de Playwright no encontrado. "
                          "Descargando (~280 MB, solo la primera vez)...",
                          file=sys.stderr)
                    if not _install_chromium():
                        raise RuntimeError(
                            "El modo --spa requiere el navegador Chromium de Playwright. "
                            "La descarga automática falló (¿sin conexión o tras un proxy?).\n"
                            "    Instálalo manualmente con:  python -m playwright install chromium"
                        ) from e
                    print("[+] Chromium instalado correctamente.", file=sys.stderr)
                    try:
                        browser = p.chromium.launch(headless=self.headless)
                    except Exception as e2:
                        raise RuntimeError(
                            "No se pudo iniciar Chromium tras instalarlo.\n"
                            "    Inténtalo manualmente con:  python -m playwright install chromium"
                        ) from e2
                context = browser.new_context(user_agent=self.user_agent)

                if self.session.cookies:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    pw_cookies = [
                        {"name": c.name, "value": c.value,
                         "domain": parsed.netloc, "path": "/"}
                        for c in self.session.cookies
                    ]
                    if pw_cookies:
                        context.add_cookies(pw_cookies)  # type: ignore[arg-type]

                page = context.new_page()

                # Captura de petición POST solo si estamos en modo discover
                capture_active = {"value": False}
                if discover:
                    def on_request(request):
                        if not capture_active["value"] or request.method != "POST":
                            return
                        req_url = request.url
                        excluded = ["socket.io", "heartbeat", "telemetry", "analytics", "beacon"]
                        if any(e in req_url for e in excluded):
                            return
                        ct = request.headers.get("content-type", "")
                        auth_kw = ["login", "auth", "signin", "sign-in", "user", "session", "api"]
                        is_auth = any(kw in req_url.lower() for kw in auth_kw)
                        if is_auth or endpoint_info["action"] == url:
                            endpoint_info["action"] = req_url
                            endpoint_info["body_type"] = "json" if "application/json" in ct else "form"

                    page.on("request", on_request)

                page.goto(url, timeout=self.timeout * 1000)
                page.wait_for_load_state(self.wait_state, timeout=self.timeout * 1000)  # type: ignore[arg-type]

                # Esperar a que aparezca un formulario/input (SPAs con hash routing)
                try:
                    page.wait_for_selector(
                        "form, input[type='text'], input[type='email'], input[type='password']",
                        state="visible",
                        timeout=8000,
                    )
                except Exception:
                    pass

                # HTML siempre se captura — es lo principal
                html = page.content()

                if discover and fields:
                    self._submit_with_dummy_data(page, fields, capture_active)

                browser.close()
        except RuntimeError:
            raise
        except Exception:
            pass

        return (html, endpoint_info)

    def _submit_with_dummy_data(self, page, fields: List[FormField], capture_active: dict) -> None:
        """Rellena el formulario con valores dummy y dispara el submit para que
        el listener on_request capture la URL real del endpoint."""
        try:
            specific_selector = ", ".join(f"input[name='{f.name}']" for f in fields)
            page.wait_for_selector(specific_selector, state="visible", timeout=8000)
        except Exception:
            return

        last_input_selector = None
        for f in fields:
            selector = f"input[name='{f.name}']"
            name_l = f.name.lower()
            if f.field_type == "email" or any(k in name_l for k in ("email", "mail", "correo")):
                dummy = "probe@gung12.test"
            elif f.field_type == "password" or any(k in name_l for k in ("pass", "pwd", "clave")):
                dummy = "Gung12Probe!"
            elif f.field_type == "number":
                dummy = "0"
            elif f.field_type == "url":
                dummy = "http://gung12.test"
            elif f.field_type == "tel":
                dummy = "000000000"
            else:
                dummy = "gung12probe"
            try:
                page.locator(selector).first.type(dummy, timeout=2000)
                last_input_selector = selector
            except Exception:
                pass

        # Cerrar overlays que bloqueen el envío
        dismiss_selectors = [
            "button:has-text('Dismiss')",
            "button:has-text('Close')",
            "button:has-text('No thanks')",
            "button:has-text('Skip')",
            "[aria-label='Close']",
            ".cdk-overlay-container button[aria-label*='ismi']",
        ]
        for dsel in dismiss_selectors:
            try:
                dloc = page.locator(dsel)
                if dloc.count() > 0 and dloc.first.is_visible():
                    dloc.first.click(timeout=1500)
                    page.wait_for_timeout(300)
            except Exception:
                pass

        submit_selectors = [
            "#loginButton",
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Login')",
            "button:has-text('LOGIN')",
            "button:has-text('Log in')",
            "button:has-text('Sign in')",
            "button:has-text('Submit')",
            "button:has-text('Iniciar')",
            "button:has-text('Entrar')",
            "[id*='login']",
            "[id*='submit']",
        ]
        capture_active["value"] = True
        clicked = False
        for sel in submit_selectors:
            try:
                locator = page.locator(sel)
                if locator.count() > 0:
                    locator.first.click(timeout=2000, force=True)
                    page.wait_for_timeout(1500)
                    clicked = True
                    break
            except Exception:
                continue

        if not clicked and last_input_selector:
            try:
                page.locator(last_input_selector).first.press("Enter")
                page.wait_for_timeout(1500)
            except Exception:
                pass

    def fetch_page(self, url: str) -> str:
        """Compatibilidad: descarga el HTML tras ejecutar el JavaScript."""
        html, _ = self._render_and_maybe_discover(url, discover=False)
        return html
