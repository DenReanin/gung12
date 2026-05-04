"""Módulo de autenticación previa automatizada.

Permite realizar login automático antes del escaneo proporcionando
las credenciales y la URL del formulario de login.
Uso: --login-url URL --login-user USER --login-pass PASS
"""

from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup


def perform_login(login_url: str, username: str, password: str,
                  session: requests.Session, timeout: int = 10) -> bool:
    """Realiza login automático rellenando el formulario de la URL indicada.

    Detecta heurísticamente los campos de usuario y contraseña por nombre.
    Devuelve True si la petición no devolvió 401/403 (éxito probable).
    """
    try:
        resp = session.get(login_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise RuntimeError(f"No se pudo acceder a la URL de login: {e}") from e

    soup = BeautifulSoup(resp.text, "html.parser")
    form = soup.find("form")
    if not form:
        raise RuntimeError(f"No se encontró formulario de login en {login_url}")

    action = form.get("action", login_url)
    if not action.startswith("http"):
        action = urljoin(login_url, action)

    method = (form.get("method") or "post").upper()

    # Construir datos del formulario
    data: dict = {}
    user_field = None
    pass_field = None

    for inp in form.find_all(["input", "textarea", "select", "button"]):
        name = inp.get("name")
        if not name:
            continue
        tag = inp.name  # 'input', 'button', etc.
        itype = (inp.get("type") or ("submit" if tag == "button" else "text")).lower()
        if itype in ("button", "image", "reset"):
            continue

        value = inp.get("value", "")
        name_lower = name.lower()

        if itype == "submit":
            # Incluir botón submit con su valor (algunos backends lo requieren)
            data[name] = value if value else "submit"
        elif any(k in name_lower for k in ("user", "login", "email", "mail", "uname", "username")):
            user_field = name
            data[name] = username
        elif any(k in name_lower for k in ("pass", "pwd", "password", "secret", "passwd")):
            pass_field = name
            data[name] = password
        else:
            data[name] = value

    if not user_field or not pass_field:
        raise RuntimeError(
            f"No se detectaron campos de usuario/contraseña en {login_url}. "
            f"Campos encontrados: {list(data.keys())}"
        )

    try:
        if method == "POST":
            resp = session.post(action, data=data, timeout=timeout, allow_redirects=True)
        else:
            resp = session.get(action, params=data, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise RuntimeError(f"Error al enviar credenciales: {e}") from e

    if resp.status_code in (401, 403):
        return False
    return True
