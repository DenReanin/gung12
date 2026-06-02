
import sys
from typing import List, Optional

from gung12.parser import FormParser
from gung12.models import FormData, FormField


def _ensure_browsers_path() -> None:
    import os
    if not getattr(sys, "frozen", False) or os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return
    if sys.platform.startswith("win"):
        base = os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local")),
            "ms-playwright",
        )
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Caches/ms-playwright")
    else:
        base = os.path.expanduser("~/.cache/ms-playwright")
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = base


def _install_chromium() -> bool:
    import subprocess
    _ensure_browsers_path()
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

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10,
                 headless: bool = True, wait_state: str = "networkidle"):
        super().__init__(cookies=cookies, timeout=timeout)
        self.headless = headless
        self.wait_state = wait_state

    def parse_forms(self, url: str) -> List[FormData]:
        from bs4 import BeautifulSoup

        html, endpoint_info = self._render_and_maybe_discover(url, discover=False)
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        if forms:
            return [self._parse_single_form(form_tag, url) for form_tag in forms]

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
        endpoint_info = {"action": url, "body_type": "form"}
        _ensure_browsers_path()
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
                        context.add_cookies(pw_cookies)

                page = context.new_page()

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
                page.wait_for_load_state(self.wait_state, timeout=self.timeout * 1000)

                try:
                    page.wait_for_selector(
                        "form, input[type='text'], input[type='email'], input[type='password']",
                        state="visible",
                        timeout=8000,
                    )
                except Exception:
                    pass

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
        html, _ = self._render_and_maybe_discover(url, discover=False)
        return html
