"""Payloads para detección de errores lógicos y validaciones ausentes.

Verifica que el formulario rechaza inputs que deberían ser inválidos:
campos vacíos, valores negativos, tipos incorrectos, etc.
"""

QUICK_PAYLOADS = [
    "",                          # Campo vacío
    " ",                         # Solo espacio
    "-1",                        # Valor negativo
    "0",                         # Cero
    "-999999",                   # Valor muy negativo
    "999999999999",              # Valor extremadamente grande
    "aaa@",                      # Email inválido
    "test",                      # Texto en campo numérico
    "<>",                        # Caracteres especiales
    "' \" \\ / & | ; :",        # Metacaracteres
]

FULL_PAYLOADS = [
    "   ",                       # Solo espacios
    "\t\n",                      # Tabs y newlines
    "null",                      # String null
    "undefined",                 # String undefined
    "NaN",                       # Not a Number
    "Infinity",                  # Infinito
    "-0",                        # Cero negativo
    "1e308",                     # Overflow float
    "a" * 10000,                 # Valor extremadamente largo
    "@@@.com",                   # Email malformado
    "test@",                     # Email sin dominio
    "test@.com",                 # Email sin host
    "12/13/2099",                # Fecha futura
    "00/00/0000",                # Fecha inválida
    "-1.5",                      # Decimal negativo
]

# La detección de errores lógicos es diferente:
# Si el servidor ACEPTA un input inválido (código 200 sin error), es vulnerable
DETECTION_PATTERNS = [
    "success",
    "accepted",
    "welcome",
    "created",
    "updated",
    "submitted",
]
