
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup


def perform_login(login_url: str, username: str, password: str,
                  session: requests.Session, timeout: int = 10) -> bool:
    try:
        resp = session.get(login_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise RuntimeError(f"No se pudo acceder a la URL de login: {e}") from e

    soup = BeautifulSoup(resp.text, "html.parser")
    form = soup.find("form")
    if not form:
        raise RuntimeError(f"No se encontró formulario de login en {login_url}")

    action = str(form.get("action") or login_url)
    if not action.startswith("http"):
        action = urljoin(login_url, action)

    method = str(form.get("method") or "post").upper()

    CSRF_FIELD_NAMES = {
        "csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token",
        "__requestverificationtoken", "csrf", "token", "user_token",
        "_csrf_token", "csrftoken", "_csrf", "anti-csrf-token", "anticsrf",
        "__csrf_magic", "xsrf_token", "_xsrf",
    }

    data: dict = {}
    user_field = None
    pass_field = None

    for inp in form.find_all(["input", "textarea", "select", "button"]):
        name = inp.get("name")
        if not name:
            continue
        name = str(name)
        tag = inp.name
        itype = str(inp.get("type") or ("submit" if tag == "button" else "text")).lower()
        if itype in ("button", "image", "reset"):
            continue

        value = str(inp.get("value") or "")
        name_lower = name.lower()

        if name_lower in CSRF_FIELD_NAMES or "token" in name_lower or "csrf" in name_lower:
            data[name] = value
            continue

        if itype == "submit":
            data[name] = value if value else "submit"
        elif itype == "password" or any(k in name_lower for k in ("pass", "pwd", "secret")):
            pass_field = name
            data[name] = password
        elif itype in ("text", "email", "tel") and any(
            k in name_lower for k in ("user", "login", "email", "mail", "uname", "username")
        ):
            user_field = name
            data[name] = username
        elif itype == "hidden":
            data[name] = value
        else:
            data[name] = value

    if not user_field or not pass_field:
        raise RuntimeError(
            f"No se detectaron campos de usuario/contraseña en {login_url}. "
            f"Campos encontrados: {list(data.keys())}"
        )

    cookies_before = {c.name for c in session.cookies}

    try:
        if method == "POST":
            resp = session.post(action, data=data, timeout=timeout, allow_redirects=True)
        else:
            resp = session.get(action, params=data, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise RuntimeError(f"Error al enviar credenciales: {e}") from e

    if resp.status_code in (401, 403):
        return False

    body_lower = resp.text.lower()

    failure_patterns = [
        "login failed", "incorrect", "invalid credentials", "invalid username",
        "invalid password", "wrong password", "wrong username", "authentication failed",
        "credenciales incorrectas", "usuario o contraseña", "contraseña incorrecta",
        "please try again", "error de autenticación",
    ]
    if any(p in body_lower for p in failure_patterns):
        return False

    success_patterns = [
        "logout", "log out", "sign out", "cerrar sesión", "cerrar sesion",
        "welcome", "bienvenido", "dashboard", "my account", "mi cuenta",
    ]
    has_success = any(p in body_lower for p in success_patterns)

    cookies_after = {c.name for c in session.cookies}
    new_cookies = cookies_after - cookies_before
    has_new_cookie = len(new_cookies) > 0

    has_token_json = False
    ct = resp.headers.get("content-type", "").lower()
    if "json" in ct:
        try:
            import json as _j
            payload_json = _j.loads(resp.text)
            if isinstance(payload_json, dict):
                token_keys = {"token", "access_token", "jwt", "session", "authentication"}
                has_token_json = any(k.lower() in token_keys for k in payload_json.keys())
        except (ValueError, TypeError):
            pass

    if not (has_success or has_new_cookie or has_token_json):
        return False

    return True
