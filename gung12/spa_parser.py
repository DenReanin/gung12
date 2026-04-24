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

from typing import List, Optional

from gung12.parser import FormParser
from gung12.models import FormData, FormField


class SPAFormParser(FormParser):
    """Parser de formularios que usa Playwright para renderizar SPAs.

    Hereda la lógica de extracción de FormParser. Sobreescribe fetch_page()
    para obtener el HTML tras la ejecución del JavaScript, y parse_forms()
    para manejar SPAs que renderizan inputs sin etiqueta <form> (Angular Material).
    """

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10,
                 headless: bool = True, wait_state: str = "networkidle"):
        super().__init__(cookies=cookies, timeout=timeout)
        self.headless = headless
        self.wait_state = wait_state  # "networkidle", "domcontentloaded", "load"

    def parse_forms(self, url: str) -> List[FormData]:
        """Extrae formularios del HTML renderizado. Incluye fallback para SPAs sin <form>."""
        from bs4 import BeautifulSoup

        html = self.fetch_page(url)
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
            ftype = (input_tag.get("type") or "text").lower()
            if ftype in skip_types_fb:
                continue
            if ftype in injectable_types:
                fields.append(FormField(
                    name=name,
                    field_type=ftype,
                    value=input_tag.get("value", ""),
                    required=input_tag.get("required") is not None,
                ))
        for textarea in soup.find_all("textarea"):
            name = textarea.get("name")
            if name:
                fields.append(FormField(
                    name=name,
                    field_type="textarea",
                    value=textarea.string or "",
                ))

        if not fields:
            return []

        # Descubrir el endpoint real interceptando la petición POST
        endpoint_info = self._discover_submit_endpoint(url, fields)

        return [FormData(
            url=url,
            action=endpoint_info["action"],
            method="POST",
            fields=fields,
            has_csrf_token=False,
            csrf_field=None,
            body_type=endpoint_info["body_type"],
        )]

    def _discover_submit_endpoint(self, url: str, fields: List[FormField]) -> dict:
        """Intercepta la petición POST real al enviar el formulario SPA.

        Rellena los campos con valores dummy (sin credenciales reales), hace clic
        en el botón de submit y captura la URL y Content-Type de la petición POST.
        Si no puede capturar la petición, devuelve la URL original con body_type=form.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"action": url, "body_type": "form"}

        discovered = {"action": url, "body_type": "form"}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context()

                if self.session.cookies:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    playwright_cookies = [
                        {"name": c.name, "value": c.value,
                         "domain": parsed.netloc, "path": "/"}
                        for c in self.session.cookies
                    ]
                    if playwright_cookies:
                        context.add_cookies(playwright_cookies)

                page = context.new_page()
                page.set_extra_http_headers({
                    "User-Agent": "Gung12/1.0 (Security Scanner - Authorized Testing Only)"
                })

                # Flag: solo capturar peticiones DESPUÉS de hacer clic en submit
                capture_active = {"value": False}

                def on_request(request):
                    if not capture_active["value"] or request.method != "POST":
                        return
                    req_url = request.url
                    # Ignorar Socket.IO, websockets y analytics
                    excluded = ["socket.io", "heartbeat", "telemetry", "analytics", "beacon"]
                    if any(e in req_url for e in excluded):
                        return
                    ct = request.headers.get("content-type", "")
                    # Priorizar endpoints con keywords de autenticación/API
                    auth_kw = ["login", "auth", "signin", "sign-in", "user", "session", "api"]
                    is_auth = any(kw in req_url.lower() for kw in auth_kw)
                    if is_auth or discovered["action"] == url:
                        discovered["action"] = req_url
                        discovered["body_type"] = "json" if "application/json" in ct else "form"

                page.on("request", on_request)

                page.goto(url, timeout=self.timeout * 1000)
                page.wait_for_load_state(self.wait_state, timeout=self.timeout * 1000)

                # Esperar los campos específicos (más fiable que selectores genéricos)
                try:
                    specific_selector = ", ".join(f"input[name='{f.name}']" for f in fields)
                    page.wait_for_selector(specific_selector, state="visible", timeout=8000)
                except Exception:
                    browser.close()
                    return discovered

                # Rellenar con valores dummy (no credenciales reales)
                # Se infiere el tipo de valor por field_type Y por el nombre del campo
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
                        # type() en lugar de fill() para disparar eventos Angular
                        page.locator(selector).first.type(dummy, timeout=2000)
                        last_input_selector = selector
                    except Exception:
                        pass

                # Cerrar cualquier dialog/overlay que bloquee el formulario
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

                # Buscar y pulsar el botón de submit
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
                capture_active["value"] = True  # activar antes de intentar cualquier envío
                clicked = False
                for sel in submit_selectors:
                    try:
                        locator = page.locator(sel)
                        if locator.count() > 0:
                            # force=True para ignorar overlays CDK residuales
                            locator.first.click(timeout=2000, force=True)
                            page.wait_for_timeout(1500)
                            clicked = True
                            break
                    except Exception:
                        continue

                # Fallback: Enter en el último campo (funciona en Angular reactive forms)
                if not clicked and last_input_selector:
                    try:
                        page.locator(last_input_selector).first.press("Enter")
                        page.wait_for_timeout(1500)
                    except Exception:
                        pass

                browser.close()

        except Exception:
            pass

        return discovered

    def fetch_page(self, url: str) -> str:
        """Descarga el HTML de la URL tras ejecutar el JavaScript con Playwright."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise ImportError(
                "El modo --spa requiere Playwright. Instálalo con:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            ) from e

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()

            # Pasar cookies de sesión al contexto de Playwright
            if self.session.cookies:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                playwright_cookies = [
                    {
                        "name": c.name,
                        "value": c.value,
                        "domain": parsed.netloc,
                        "path": "/",
                    }
                    for c in self.session.cookies
                ]
                if playwright_cookies:
                    context.add_cookies(playwright_cookies)

            page = context.new_page()
            page.set_extra_http_headers({
                "User-Agent": "Gung12/1.0 (Security Scanner - Authorized Testing Only)"
            })

            page.goto(url, timeout=self.timeout * 1000)
            page.wait_for_load_state(self.wait_state, timeout=self.timeout * 1000)

            # Para SPAs con hash routing (Angular, React Router) el componente
            # se monta DESPUÉS de networkidle. Esperar a que aparezca un form o input.
            try:
                page.wait_for_selector(
                    "form, input[type='text'], input[type='email'], input[type='password']",
                    state="visible",
                    timeout=8000,
                )
            except Exception:
                # Si no aparece en 8s, extraer el HTML de todas formas
                pass

            html = page.content()
            browser.close()

        return html
