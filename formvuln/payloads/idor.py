"""Payloads para detección de IDOR (Insecure Direct Object Reference).

IDOR se detecta manipulando IDs en los campos del formulario y verificando
si se obtiene acceso a recursos de otros usuarios.
"""

QUICK_PAYLOADS = [
    "1",
    "2",
    "3",
    "0",
    "-1",
    "999",
    "1000",
    "admin",
    "100",
    "9999",
]

FULL_PAYLOADS = [
    "4",
    "5",
    "10",
    "50",
    "101",
    "500",
    "1001",
    "99999",
    "2147483647",    # MAX_INT
    "-2147483648",   # MIN_INT
    "null",
    "undefined",
    "true",
    "false",
    "../1",
]

# Patrones que indican IDOR (acceso a datos de otros usuarios)
# La detección real requiere comparar respuestas entre IDs diferentes
DETECTION_PATTERNS = [
    "username",
    "email",
    "password",
    "user_id",
    "profile",
    "account",
    "admin",
    "private",
    "secret",
]
