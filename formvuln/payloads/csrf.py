"""Payloads/análisis para detección de CSRF (Cross-Site Request Forgery).

CSRF es diferente: no se detecta con payloads inyectados, sino analizando
la estructura del formulario (ausencia de tokens anti-CSRF).
"""

# No hay payloads de inyección para CSRF
# La detección se basa en análisis estático del formulario
QUICK_PAYLOADS = []
FULL_PAYLOADS = []

# Nombres conocidos de campos CSRF
CSRF_TOKEN_NAMES = [
    "csrf_token",
    "_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__requestverificationtoken",
    "csrf",
    "token",
    "user_token",
    "_csrf_token",
    "csrftoken",
    "_csrf",
    "anti-csrf-token",
    "anticsrf",
    "__csrf_magic",
    "xsrf_token",
    "_xsrf",
]

# Headers que indican protección CSRF
CSRF_HEADERS = [
    "x-csrf-token",
    "x-xsrf-token",
]

DETECTION_PATTERNS = []
