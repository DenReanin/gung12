# Análisis de la respuesta del profesor — 9 de Marzo

## Cambios principales al proyecto

### 1. Lista de vulnerabilidades ampliada
El profesor proporciona **30 tipos de vulnerabilidades** posibles, pero no espera que cubras todas:

```
2.2.1. XSS
2.2.2. SQLi
2.2.3. LFI
2.2.4. Errores lógicos
2.2.5. CSRF
2.2.6. SSTI
2.2.7. Command Injection / OS Command Injection
2.2.8. LDAP Injection
2.2.9. XPath Injection
2.2.10. NoSQL Injection
2.2.11. HTTP Parameter Pollution (HPP)
2.2.12. HTTP Parameter Smuggling
2.2.13. Inyección de cabeceras de correo (Email Header Injection)
2.2.14. Open Redirect
2.2.15. SSRF
2.2.16. XXE
2.2.17. IDOR
2.2.18. Mass Assignment
2.2.19. Parameter Tampering
2.2.20. Bypass de validaciones del lado cliente
2.2.21. Falta de validación de longitud, formato o tipo de datos
2.2.22. Subida arbitraria de archivos
2.2.23. DoS mediante payloads pesados
2.2.24. Enumeración de usuarios por mensajes de error
2.2.25. Fuga de información sensible
2.2.26. Falta de rate limit
2.2.27. CAPTCHA Bypass
2.2.28. Business Logic Abuse
2.2.29. Race Condition
2.2.30. Validación inconsistente frontend/backend
```

**→ Debes seleccionar las que consideres más interesantes (probablemente 8-12)**

---

### 2. CAMBIO DE ARQUITECTURA: No es un Web Crawler completo

**Lo que dijiste inicialmente:** "Hacer un crawler que busque todos los formularios"

**Lo que el profesor recomienda (Opción 2):**
- Pasarle una URL con un formulario específico
- La herramienta analiza ESE formulario
- NO hace búsqueda automática de formularios
- La búsqueda automática (`Opción 1`) queda como "futuras mejoras"

**Implicación:** Tu herramienta es más simple y acotada:
1. Input: `python tool.py -u "https://target.com/form" [opciones]`
2. Analiza el formulario en esa URL
3. Lanza payloads
4. Genera informe

---

### 3. NO usar herramientas externas

**Lo que dijiste inicialmente:** "Comparar con OWASP ZAP, usar sqlmap, etc."

**Lo que el profesor recomienda:**
- Crea tus propios payloads (no uses sqlmap, etc.)
- La lógica es: lanzar payloads → analizar respuesta → detectar anomalías
- Si encuentras algo, entonces usas herramientas especializadas a "tiro hecho"

**Implicación:** Tu herramienta es un "detector rápido", no un "sustituidor completo de ZAP"

---

### 4. Estructura técnica propuesta (2 pasos)

**Paso 1: Análisis de formulario**
```
- Acceder a la URL
- Parsear el formulario (<form>, <input>, <textarea>, <select>)
- Extraer: método (GET/POST), action, campos, valores por defecto
- Generar request válido
- Opción --test para verificar que el formulario es válido
```

**Paso 2: Lanzar payloads**
```
- Por cada tipo de vulnerabilidad: SQLi, SSTI, LDAP, etc.
- Para cada campo del formulario:
  - Enviar payload
  - Analizar respuesta
  - Detectar indicios (errores, tiempos, cambios en respuesta)
```

---

### 5. Referencia: script auth_check.py del profesor

Tu herramienta debería tener una **interfaz CLI similar**:

```bash
$ python tool.py -h
usage: tool.py [-h] -u URL [-m METHOD] [-d DATA] [-T TESTS]
               [-o OUTPUT] [-threads THREADS] [-v] [--test]

Options:
  -u, --url URL          Target URL con formulario (requerido)
  -m, --method METHOD    GET o POST (default: auto-detect)
  -d, --data DATA        Datos a enviar (opcional, para override)
  -T, --tests TESTS      Qué tipos probar: sqli,xss,ssti,ldap,etc
  -o, --output OUTPUT    Guardar informe (JSON, HTML, PDF)
  -threads THREADS       Threads concurrentes (default: 1)
  -v, --verbose          Verbose output
  --test                 Test mode: envía una request para verificar
  -F, --full             Full mode: todos los payloads (vs quick mode)
  --sleep SLEEP          Sleep entre requests para evitar WAF
  -p, --proxy PROXY      Proxy URL
  -q, --quiet            Solo mostrar findings
```

**Payloads por tipo** (ejemplo para SQLi):
```python
sqli_quick = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    # ... etc
]

sqli_full = [
    # Todo lo del quick + más payloads
    # ... 300+ payloads
]
```

---

## Resumen de cambios

| Aspecto | Antes (tu propuesta) | Ahora (profesor) |
|--------|----------------------|------------------|
| **Alcance de vulns** | XSS, SQLi, LFI, errores lógicos | Selecciona 8-12 de 30 posibles |
| **Rastreo de formularios** | Web crawler automático (spider) | URL específica del formulario |
| **Herramientas externas** | Usar ZAP, sqlmap, etc. | No, solo payloads propios |
| **Objetivo** | Sustituir a ZAP | Detector rápido + análisis local |
| **Entrada** | URL raíz de sitio | URL del formulario |
| **Complejidad** | Alta (crawler + detección) | Media (análisis + payloads) |

---

## Preguntas que aún necesitas responder (para ti)

1. **¿Cuáles vulnerabilidades cubrir?** Selecciona un subconjunto manejable (sugeencia: 8-10 máximo)
2. **¿Lenguaje**: Python? (el profesor usa Python en su referencia)
3. **¿Interfaz CLI**: ¿Copias el estilo de auth_check.py o prefieres algo más simple?
4. **¿Modos quick/full**: ¿Dos modos de payloads (rápido vs exhaustivo)?

---

## Próximos pasos

1. **Actualizar `memoria_estructura.md`** con:
   - La lista de 30 vulnerabilidades con descripción breve
   - Tu selección justificada (ej: "He elegido 10 porque X, Y, Z")
   - Cambiar arquitectura de "web crawler" a "analizador de formularios específicos"
   - Remover la idea de comparación formal con ZAP

2. **Preparar el código**:
   - Paso 1: CLI + parser de formularios
   - Paso 2: Motor de payloads por tipo
   - Paso 3: Analizador de respuestas

3. **Escribir Cap. 1 y 2** con estos cambios en mente
