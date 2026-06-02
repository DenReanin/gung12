
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import List, Optional

from gung12.models import FormData, FormField


CSRF_FIELD_NAMES = {
    "csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token",
    "__requestverificationtoken", "csrf", "token", "user_token",
    "_csrf_token", "csrftoken", "_csrf",
}


class FormParser:

    def __init__(self, cookies: Optional[dict] = None, timeout: int = 10):
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        )
        self.session.headers.update({"User-Agent": self.user_agent})

    def fetch_page(self, url: str) -> str:
        response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        response.raise_for_status()
        return response.text

    def parse_forms(self, url: str) -> List[FormData]:
        html = self.fetch_page(url)
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return []

        result = []
        for form_tag in forms:
            form_data = self._parse_single_form(form_tag, url)
            result.append(form_data)

        return result

    def _parse_single_form(self, form_tag, base_url: str) -> FormData:
        method = form_tag.get("method", "GET").upper()
        action = form_tag.get("action", "")
        action_url = urljoin(base_url, action) if action else base_url

        fields = []
        csrf_field = None

        for input_tag in form_tag.find_all("input"):
            field = self._parse_input(input_tag)
            if field:
                fields.append(field)
                if field.name.lower() in CSRF_FIELD_NAMES:
                    csrf_field = field

        for textarea in form_tag.find_all("textarea"):
            name = textarea.get("name")
            if name:
                fields.append(FormField(
                    name=name,
                    field_type="textarea",
                    value=textarea.string or "",
                ))

        for select in form_tag.find_all("select"):
            name = select.get("name")
            if name:
                options = []
                default_value = ""
                for option in select.find_all("option"):
                    val = option.get("value", option.string or "")
                    options.append(val)
                    if option.get("selected") is not None:
                        default_value = val
                if not default_value and options:
                    default_value = options[0]
                fields.append(FormField(
                    name=name,
                    field_type="select",
                    value=default_value,
                    options=options,
                ))

        has_csrf = csrf_field is not None

        return FormData(
            url=base_url,
            action=action_url,
            method=method,
            fields=fields,
            has_csrf_token=has_csrf,
            csrf_field=csrf_field,
        )

    def _parse_input(self, input_tag) -> Optional[FormField]:
        name = input_tag.get("name")
        if not name:
            return None

        field_type = input_tag.get("type", "text").lower()
        value = input_tag.get("value", "")
        required = input_tag.get("required") is not None

        return FormField(
            name=name,
            field_type=field_type,
            value=value,
            required=required,
        )

    def test_form(self, url: str) -> dict:
        try:
            forms = self.parse_forms(url)
            if not forms:
                return {
                    "status": "error",
                    "message": "No se encontraron formularios en la URL",
                    "url": url,
                }

            form = forms[0]
            return {
                "status": "ok",
                "message": f"Formulario encontrado: {len(form.fields)} campos",
                "url": url,
                "method": form.method,
                "action": form.action,
                "fields": [
                    {"name": f.name, "type": f.field_type}
                    for f in form.fields
                ],
                "injectable_fields": [
                    f.name for f in form.injectable_fields
                ],
                "has_csrf": form.has_csrf_token,
                "total_forms": len(forms),
            }
        except requests.RequestException as e:
            return {
                "status": "error",
                "message": f"Error de conexión: {e}",
                "url": url,
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error inesperado: {e}",
                "url": url,
            }
