
QUICK_PAYLOADS = []
FULL_PAYLOADS = []

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

CSRF_HEADERS = [
    "x-csrf-token",
    "x-xsrf-token",
]

DETECTION_PATTERNS = []
