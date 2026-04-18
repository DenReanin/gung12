# Estructura Memoria TFM
## Plataforma automática de detección de vulnerabilidades en formularios web
**Máster Universitario en Ciberseguridad — UA**
**Autor:** Den Reanin Gerasimov
**Tutor:** José Luis Verdeguer Navarro

---

## Portada y elementos preliminares
- Portada oficial (plantilla UA)
- Resumen (español)
- Resum (valenciano)
- Abstract (inglés)
- Motivación, justificación y objetivo general
- Agradecimientos
- Índice de contenidos
- Índice de figuras
- Índice de tablas

---

## Capítulo 1 — Introducción
### 1.1. Contextualización y justificación
- Importancia de la seguridad en aplicaciones web (datos, privacidad, reputación)
- Formularios web como vector de ataque principal (inyecciones, manipulación de datos)
- Problemática actual: herramientas DAST existentes (ZAP, Burp) son complejas, caras, requieren expertise
- Oportunidad: desarrollar una herramienta educativa simple, accesible y especializada en formularios
- Uso ético y responsable (solo en entornos autorizados: DVWA, WebGoat, aplicaciones propias)

### 1.2. Objetivos
- **Objetivo general:** Desarrollar una herramienta CLI basada en payloads que detecte 12 tipos de vulnerabilidades en formularios web específicos

- **Objetivos específicos:**
  1. Parsear un formulario HTML y extraer sus campos, método y acción
  2. Implementar un motor de pruebas con payloads para 12 tipos de vulnerabilidades
  3. Analizar respuestas del servidor para identificar indicios de vulnerabilidad
  4. Generar informes en múltiples formatos (JSON, HTML)
  5. Validar la herramienta contra entornos de prueba (DVWA, WebGoat)

### 1.3. Metodología del proyecto
- **Arquitectura modular:** parser → motor payloads → analizador → informe
- **Enfoque iterativo:** diseño → implementación → prueba por módulo
- **Modos de operación:** quick (rápido) y full (exhaustivo)
- **Fases:** Fase 1 (teoría: Cap. 1-2) → Fase 2 (código) → Fase 3 (pruebas) → Fase 4 (redacción final)
- Diagrama de fases del proyecto

---

## Capítulo 2 — Seguridad en aplicaciones web: Estado del arte
### 2.1. Contexto general de la seguridad web
- Evolución de las amenazas en aplicaciones web (últimas 5 años)
- OWASP Top 10 2025: categorización de amenazas
- Estadísticas actuales de vulnerabilidades en formularios (CVE, reportes de seguridad)
- Formularios web como superficie de ataque: por qué son vulnerables

### 2.2. Clasificación de vulnerabilidades tratadas (12 tipos)

#### 2.2.1. Cross-Site Scripting (XSS) — Reflejado
- Definición: inyección de código JavaScript que se refleja en la respuesta
- Mecanismo de explotación
- Indicios de vulnerabilidad detectables automáticamente: payload reflejado sin encoding
- Payloads típicos: `<script>alert(1)</script>`, `"><script>`, event handlers

#### 2.2.2. SQL Injection (SQLi)
- Definición y tipos (clásica, ciega, basada en tiempo)
- Mecanismo de explotación
- Mensajes de error SQL y patrones detectables
- Payloads típicos: `' OR '1'='1`, `' OR 1=1--`, `'; WAITFOR DELAY`

#### 2.2.3. Server-Side Template Injection (SSTI)
- Definición: inyección en motores de plantillas (Jinja, Mustache, ERB, etc.)
- Mecanismo de explotación
- Detección: evaluación de expresiones matemáticas (`${7*7}` → `49`)
- Payloads típicos: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`

#### 2.2.4. LDAP Injection
- Definición: inyección en consultas LDAP
- Mecanismo de explotación
- Detección: enumeración de usuarios o cambios en respuesta
- Payloads típicos: `*`, `admin*`, `*)(uid=%2A`

#### 2.2.5. Command Injection / OS Command Injection
- Definición: inyección de comandos del sistema operativo
- Mecanismo de explotación
- Detección: salida de comandos en respuesta (whoami, id, etc.)
- Payloads típicos: `; whoami`, `| id`, `&& cat /etc/passwd`

#### 2.2.6. NoSQL Injection
- Definición: inyección en consultas NoSQL (MongoDB, CouchDB, etc.)
- Mecanismo de explotación
- Detección: cambios en lógica de respuesta, bypass de autenticación
- Payloads típicos: `{"$ne":null}`, `{"$gt":""}`, `{"$regex":""}`

#### 2.2.7. XML External Entity Injection (XXE)
- Definición: explotación del parser XML
- Mecanismo de explotación: lectura de archivos, SSRF, DoS
- Detección: contenido de archivos en respuesta
- Payloads típicos: DTD malformadas con entidades externas

#### 2.2.8. Cross-Site Request Forgery (CSRF)
- Definición: solicitudes forjadas desde sitios terceros
- Detección: ausencia de tokens CSRF en formularios
- Búsqueda de campos: `_token`, `csrf_token`, `__token`, `authenticity_token`
- Análisis: validar presencia y formato de tokens

#### 2.2.9. Local File Inclusion (LFI)
- Definición: inclusión de archivos locales del servidor
- Mecanismo de explotación
- Detección: contenido de archivo en respuesta
- Payloads típicos: `../../etc/passwd`, `..%2F..%2Fetc%2Fpasswd`

#### 2.2.10. Open Redirect
- Definición: redirección no validada a URLs externas
- Mecanismo de explotación: phishing, robo de credenciales
- Detección: redirección a hosts no whitelistados
- Payloads típicos: `https://evil.com`, `//evil.com`, `///evil.com`

#### 2.2.11. Insecure Direct Object Reference (IDOR)
- Definición: acceso directo sin autorización a recursos de otros usuarios
- Mecanismo de explotación: manipulación de IDs
- Detección: acceso exitoso a recursos modificando parámetros
- Payloads típicos: cambiar `id=1` → `id=2`, `id=3`, etc.

#### 2.2.12. Errores lógicos y validaciones ausentes
- Definición: validaciones incompletas o inconsistentes
- Tipos: campos vacíos aceptados, valores fuera de rango, bypass de tipo
- Detección: aceptación de inputs que deberían ser rechazados
- Ejemplos: edad negativa, email sin @, cantidad < 0

### 2.3. OWASP como marco de referencia
- OWASP Top 10 y relación con las vulnerabilidades tratadas
- OWASP Testing Guide como guía metodológica

### 2.4. Herramientas de análisis dinámico existentes (DAST)
#### 2.4.1. OWASP ZAP
- Descripción y capacidades
- Limitaciones: payloads conocidos, SPAs, configuración compleja

#### 2.4.2. Burp Suite
- Descripción y capacidades
- Limitaciones: curva de aprendizaje, versión gratuita restringida

#### 2.4.3. Nikto
- Descripción y enfoque
- Limitaciones: no especializado en formularios

#### 2.4.4. sqlmap
- Descripción y alcance
- Limitaciones: solo SQLi, no integrado con crawler

### 2.5. Síntesis del estado del arte y oportunidad
- Limitaciones de las herramientas existentes:
  - Payloads estándar fácilmente bloqueables por WAFs
  - Dificultades con formularios en SPAs (Angular, React)
  - Dependencia de configuración manual
  - Falta de informes adaptados al contexto educativo/auditoría
- Tabla comparativa de herramientas (ya incluida en 2.4.5)
- Gap identificado que cubre este TFM

---

## Capítulo 3 — Diseño e Implementación del sistema
### 3.1. Arquitectura general del sistema
- Visión general del flujo de ejecución (4 pasos)
  1. Input: URL del formulario
  2. Parser: extrae estructura del formulario
  3. Motor: lanza payloads (12 tipos)
  4. Output: genera informe
- Decisiones de diseño principales: URL específica (no crawler), payloads propios (no herramientas externas)

### 3.2. Entorno de desarrollo y tecnologías
#### 3.2.1. Lenguaje y entorno
- Python 3.10+: justificación de elección
- Gestión de dependencias (pip, entorno virtual venv)

#### 3.2.2. Dependencias y librerías
- `requests`: peticiones HTTP
- `beautifulsoup4`: parsing HTML
- `click`: interfaz CLI
- `weasyprint` o `reportlab`: generación de informes PDF
- `json`: salida de datos estructurados

#### 3.2.3. Entorno de pruebas
- DVWA (Damn Vulnerable Web Application) en Docker
- WebGoat (OWASP) en Docker
- Justificación del uso: entornos seguros y legales con vulnerabilidades conocidas

### 3.3. Metodología técnica
- Arquitectura modular: cada módulo funciona independientemente
- Enfoque iterativo: implementar módulos en orden
- Pruebas: validar cada módulo antes de seguir al siguiente
- Diagrama de flujo del proceso completo

### 3.4. Módulo 1 — Parser de formularios
- Diseño y diagrama de flujo
- Acceso a URL específica con formulario
- Parseo HTML: identificar `<form>`, `<input>`, `<textarea>`, `<select>`
- Extracción de: método (GET/POST), action, campos, valores por defecto, CSRF tokens
- Validación: opción `--test` para verificar que el formulario es procesable
- Implementación y fragmentos de código relevantes

### 3.5. Módulo 2 — Motor de pruebas (Payload Engine)
- Diseño general y diagrama de flujo
- Estructura de payloads: quick mode (rápido) vs full mode (exhaustivo)
- Gestión de payloads: organización por tipo de vulnerabilidad (12 categorías)
- Ejecución secuencial por campo del formulario

#### 3.5.1. Pruebas XSS
- Payloads: básicos y variantes sin encoding
- Detección: búsqueda de payload reflejado en respuesta
- Falsos positivos: análisis de respuestas codificadas

#### 3.5.2. Pruebas SQLi
- Payloads: comillas, booleanos, time-based
- Detección: errores SQL, cambios en tiempo de respuesta
- Heurísticas: patrones de mensajes de error

#### 3.5.3. Pruebas SSTI
- Payloads: expresiones matemáticas (`${7*7}`, `{{7*7}}`)
- Detección: búsqueda de resultado (`49`) en respuesta

#### 3.5.4. Pruebas LDAP, Command Injection, NoSQL, XXE, etc.
- Payloads típicos por tipo
- Estrategia de detección (respuesta, tiempo, errores)

#### 3.5.5. Pruebas CSRF
- Análisis de estructura del formulario
- Búsqueda de tokens anti-CSRF

#### 3.5.6. Pruebas de errores lógicos
- Validaciones: campos vacíos, valores negativos, tipos incorrectos

### 3.6. Módulo 3 — Analizador de Respuestas
- Diseño y diagrama de flujo
- Comparación: respuesta base vs respuesta con payload
- Heurísticas por tipo de vulnerabilidad
- Detección de indicios: errores, reflexión, contenido
- Gestión de falsos positivos
- Implementación y fragmentos de código relevantes

### 3.7. Módulo 4 — Generador de Informes
- Diseño del informe: estructura y campos
- Formato JSON: especificación del esquema
- Formato HTML: diseño visual y accesibilidad
- Clasificación por severidad (CRÍTICA, ALTA, MEDIA, BAJA)
- Implementación y fragmentos de código relevantes

### 3.8. Integración: CLI completa
- Interfaz de línea de comandos: parámetros y opciones
  - `-u, --url`: URL del formulario (requerido)
  - `-T, --tests`: tipos de pruebas a ejecutar (sqli,xss,ssti,ldapi,etc.)
  - `-F, --full`: modo exhaustivo (vs rápido)
  - `-o, --output`: archivo de salida (informe)
  - `--test`: verificar configuración
- Ejemplo de uso completo: `python tool.py -u "http://target.com/form" -T sqli,xss -o report.html`
- Capturas de pantalla de ejecución

---

## Capítulo 4 — Pruebas y Validación
### 4.1. Entorno de pruebas
- Configuración de DVWA y WebGoat
- Niveles de seguridad utilizados
- Condiciones de prueba

### 4.2. Pruebas por tipo de vulnerabilidad
#### 4.2.1. Detección de XSS
- Formularios objetivo en DVWA/WebGoat
- Resultados obtenidos
- Capturas del informe generado

#### 4.2.2. Detección de SQLi
- Formularios objetivo
- Resultados obtenidos

#### 4.2.3. Detección de LFI
- Formularios objetivo
- Resultados obtenidos

#### 4.2.4. Detección de errores lógicos
- Casos probados
- Resultados obtenidos

### 4.3. Análisis de falsos positivos y falsos negativos
- Casos identificados
- Análisis de causas
- Limitaciones de las heurísticas

### 4.4. Comparativa con herramientas existentes (opcional pero recomendado)
- Mismos formularios con OWASP ZAP vs herramienta propia
- Tabla comparativa de resultados

### 4.5. Resumen de resultados

---

## Capítulo 5 — Conclusiones y Trabajo Futuro
### 5.1. Conclusiones
- Objetivos cumplidos
- Aportaciones del proyecto
- Reflexión sobre el proceso de desarrollo

### 5.2. Líneas futuras de trabajo
#### 5.2.1. Mejoras en detección
- Soporte para SPAs con Playwright/Selenium
- Payloads avanzados y evasión de WAF
- Detección basada en diferencias semánticas (no solo regex)

#### 5.2.2. Mejoras en la herramienta
- Interfaz web (dashboard de resultados)
- Soporte para autenticación previa al rastreo
- Integración con bases de datos de payloads (SecLists)

#### 5.2.3. Validación más amplia
- Pruebas contra más aplicaciones vulnerables
- Métricas de precisión (precision, recall)

---

## Referencias bibliográficas

---

## Anexos
### Anexo A — Manual de instalación y uso
- Requisitos del sistema
- Instalación paso a paso
- Ejemplos de uso
- Troubleshooting común

### Anexo B — Listado completo de payloads utilizados
- Quick mode: ~10-15 payloads por tipo
- Full mode: ~30-50+ payloads por tipo
- Fuentes: OWASP, SecLists, payloads propios

### Anexo C — Ejemplos de informes generados
- JSON (estructura)
- HTML (captura)
- Casos de ejemplo con resultados reales

### Anexo D — Código fuente
- Enlace a repositorio GitHub (público)
- Licencia: GPL v3 o similar

### Anexo E — Futuras mejoras

**Líneas futuras de trabajo:**

1. **Web Crawler automático** (IMPORTANTE: no está en alcance actual)
   - Implementar spider que rastree sitio completo
   - Detección automática de formularios sin URL manual
   - Respetar robots.txt y rate limiting

2. **Mejoras en detección**
   - Payloads avanzados y evasión de WAF básica
   - Detección basada en diferencias semánticas (más allá de regex)
   - Soporte para encoding personalizado

3. **Mejoras en la herramienta**
   - Interfaz web (Flask/Streamlit) en lugar de solo CLI
   - Soporte para autenticación previa (login antes de analizar)
   - Integración con SecLists para payloads actualizados
   - Scoring CVSS automático por vulnerabilidad

4. **Validación más amplia**
   - Pruebas contra más aplicaciones vulnerables
   - Benchmarking contra OWASP ZAP
   - Métricas de precisión (precision, recall)

---

## Notas de escritura

| Capítulo | Se puede escribir sin código | Prioridad |
|----------|------------------------------|-----------|
| Cap. 1 — Introducción | Sí, ahora mismo | Alta |
| Cap. 2 — Estado del arte | Sí, ahora mismo | Alta |
| Cap. 3 — Diseño | Parcialmente (diseño antes de código) | Media |
| Cap. 3 — Implementación | No, necesita código terminado | Baja |
| Cap. 4 — Pruebas | No, necesita código terminado | Baja |
| Cap. 5 — Conclusiones | No, al final | Baja |
