# Capítulo 3. Diseño e Implementación del sistema

En este capítulo se presenta el diseño y la implementación de Gung12, la herramienta de línea de comandos desarrollada en este Trabajo Fin de Máster. Se describen la arquitectura general del sistema, las tecnologías empleadas, la estructura modular del código y las decisiones de diseño adoptadas durante el desarrollo.



## 3.1. Arquitectura general

Gung12 sigue una arquitectura modular basada en un pipeline secuencial de cinco etapas. Cada etapa es responsable de una tarea concreta dentro del proceso de análisis, lo que facilita el mantenimiento, la extensibilidad y la comprensión del flujo de ejecución.

El pipeline completo se ejecuta de la siguiente forma:

1. **CLI** — Recibe los parámetros del usuario (URL, tipos de prueba, cookies, modo).
2. **Parser** — Accede a la URL y extrae la estructura del formulario HTML.
3. **Engine** — Inyecta payloads en los campos del formulario y captura las respuestas.
4. **Analyzer** — Compara cada respuesta con la respuesta base para detectar indicios.
5. **Reporter** — Genera un informe estructurado en JSON o HTML.

Opcionalmente, entre las etapas 4 y 5 se puede activar un módulo de análisis con inteligencia artificial que valida y prioriza los hallazgos.

[Esquema: Diagrama de flujo de la arquitectura general del pipeline]



## 3.2. Entorno de desarrollo y tecnologías

La herramienta ha sido desarrollada íntegramente en Python 3, aprovechando su ecosistema de librerías orientadas al análisis web y la manipulación de datos. A continuación se detallan las tecnologías y librerías empleadas:

| Tecnología | Versión | Propósito |
|------------|---------|-----------|
| Python | 3.12 | Lenguaje principal |
| Click | 8.x | Framework para la interfaz CLI |
| Requests | 2.x | Envío de peticiones HTTP |
| BeautifulSoup4 | 4.x | Parsing de HTML |
| Docker | — | Contenedorización de entornos de prueba (DVWA) |

Se ha utilizado un entorno virtual (`venv`) para aislar las dependencias del proyecto. El código fuente se gestiona con Git y se aloja en un repositorio de GitHub.

La estructura del proyecto es la siguiente:

```
TFM/
├── gung12/                  # Paquete principal
│   ├── __init__.py          # Versión y metadatos
│   ├── __main__.py          # Punto de entrada (python -m gung12)
│   ├── cli.py               # Interfaz de línea de comandos
│   ├── parser.py            # Módulo de parsing de formularios
│   ├── engine.py            # Motor de inyección de payloads
│   ├── analyzer.py          # Analizador de respuestas
│   ├── ai_analyzer.py       # Análisis opcional con IA
│   ├── reporter.py          # Generador de informes
│   ├── models.py            # Modelos de datos
│   └── payloads/            # Directorio de payloads
│       ├── __init__.py      # Registro de payloads
│       ├── xss.py           # Payloads XSS
│       ├── sqli.py          # Payloads SQLi
│       ├── ssti.py          # Payloads SSTI
│       ├── ldap.py          # Payloads LDAP
│       ├── cmdi.py          # Payloads Command Injection
│       ├── nosql.py         # Payloads NoSQL
│       ├── xxe.py           # Payloads XXE
│       ├── csrf.py          # Detección CSRF
│       ├── lfi.py           # Payloads LFI
│       ├── open_redirect.py # Payloads Open Redirect
│       ├── idor.py          # Payloads IDOR
│       └── logic.py         # Payloads errores lógicos
├── reportes/                # Informes generados (ignorado en Git)
├── memoria/                 # Documentación del TFM
└── venv/                    # Entorno virtual
```

[Esquema: Diagrama de la estructura de archivos del proyecto]



## 3.3. Modelos de datos

Antes de describir los módulos funcionales, es necesario comprender los modelos de datos que definen la información que fluye entre las distintas etapas del pipeline. Estos modelos están definidos en el archivo `models.py`.

Los modelos principales son:

- **FormField**: Representa un campo individual del formulario (nombre, tipo, valor por defecto, si es obligatorio).
- **FormData**: Representa un formulario completo (URL, acción, método HTTP, lista de campos, presencia de token CSRF). Expone una propiedad `injectable_fields` que filtra automáticamente los campos no inyectables (submit, button, hidden con token CSRF).
- **VulnResult**: Almacena el resultado de una detección individual (tipo de vulnerabilidad, severidad, campo afectado, payload utilizado, evidencia, descripción y puntuación de confianza).
- **ScanResult**: Agrupa los resultados de un escaneo completo (URL, formulario, lista de vulnerabilidades, modo, duración, número de peticiones y análisis IA opcional).

Además, se definen dos enumeraciones:

- **VulnType**: Los 12 tipos de vulnerabilidad soportados (XSS, SQLI, SSTI, LDAP, CMDI, NOSQL, XXE, CSRF, LFI, OPEN_REDIRECT, IDOR, LOGIC).
- **Severity**: Los cinco niveles de severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO), junto con un mapeo predefinido que asigna a cada tipo de vulnerabilidad su severidad correspondiente.

[Esquema: Diagrama de clases de los modelos de datos]



## 3.4. Módulo Parser

El módulo `parser.py` es el encargado de acceder a la URL proporcionada por el usuario, descargar el contenido HTML y extraer la estructura de los formularios presentes en la página.

El proceso de parsing se realiza en los siguientes pasos:

1. Se realiza una petición HTTP GET a la URL utilizando la librería Requests, incluyendo las cookies de sesión si fueron proporcionadas.
2. El HTML obtenido se procesa con BeautifulSoup para localizar todos los elementos `<form>`.
3. Para cada formulario encontrado, se extraen:
   - El atributo `action` (resolviendo URLs relativas).
   - El atributo `method` (GET o POST).
   - Todos los campos de entrada (`<input>`, `<textarea>`, `<select>`), identificando su nombre, tipo y valor por defecto.
4. Se verifica la presencia de tokens anti-CSRF mediante la búsqueda de campos ocultos cuyo nombre coincida con patrones conocidos (csrf_token, _token, authenticity_token, entre otros).
5. Se construye un objeto `FormData` por cada formulario encontrado.

Además, el parser ofrece un método `test_form()` que permite verificar si la URL es accesible y contiene formularios parseables, sin ejecutar ninguna prueba de seguridad.

[Esquema: Diagrama de secuencia del proceso de parsing]



## 3.5. Motor de pruebas (Engine)

El módulo `engine.py` constituye el núcleo del proceso de escaneo. Su función es orquestar la inyección de payloads en los campos del formulario y coordinar el análisis de las respuestas.

El motor opera en las siguientes fases:

### 3.5.1. Petición base

Antes de iniciar las pruebas, el motor envía una petición legítima al formulario con valores normales. Esta petición base sirve como referencia para comparar las respuestas posteriores. Se registran tres métricas de la respuesta base:

- El contenido textual de la respuesta (body).
- El código de estado HTTP.
- El tiempo de respuesta.

### 3.5.2. Inyección de payloads

Para cada tipo de vulnerabilidad seleccionado por el usuario, el motor:

1. Obtiene la lista de payloads correspondiente del módulo `payloads/`. La cantidad de payloads depende del modo de ejecución: el modo rápido (quick) utiliza un subconjunto reducido (3-10 payloads por tipo), mientras que el modo exhaustivo (full) emplea la colección completa (~25-40 payloads por tipo).
2. Para cada campo inyectable del formulario, sustituye el valor original por el payload.
3. Envía la petición HTTP al servidor (GET o POST según el método del formulario).
4. Captura la respuesta: texto, código de estado y tiempo de respuesta.

### 3.5.3. Análisis y deduplicación

Cada respuesta se envía al módulo Analyzer para su evaluación. Si se detecta un indicio de vulnerabilidad, se genera un `VulnResult`. El motor aplica una lógica de deduplicación que evita reportar la misma vulnerabilidad en el mismo campo más de una vez.

El número total de peticiones realizadas depende del número de campos inyectables, el número de tipos de vulnerabilidad y el modo seleccionado. En un escaneo completo con un solo campo, se realizan aproximadamente 318 peticiones.

[Esquema: Diagrama de flujo del motor de inyección de payloads]



## 3.6. Sistema de payloads

Los payloads están organizados en módulos independientes dentro del directorio `payloads/`, uno por cada tipo de vulnerabilidad. Cada módulo exporta tres elementos:

- **QUICK_PAYLOADS**: Lista reducida de payloads para el modo rápido. Contiene los payloads más representativos y con mayor probabilidad de éxito.
- **FULL_PAYLOADS**: Lista extendida con variantes adicionales que incluyen técnicas de evasión de filtros, codificaciones alternativas y payloads menos comunes.
- **DETECTION_PATTERNS**: Patrones de detección (expresiones regulares o cadenas) que el analizador utiliza para buscar indicios de vulnerabilidad en las respuestas.

La distribución aproximada de payloads por tipo de vulnerabilidad es:

| Tipo | Quick | Full | Total |
|------|-------|------|-------|
| XSS | 10 | 27 | 37 |
| SQLi | 10 | 32 | 42 |
| SSTI | 8 | 22 | 30 |
| LDAP | 5 | 20 | 25 |
| CMDi | 10 | 32 | 42 |
| NoSQL | 5 | 20 | 25 |
| XXE | 5 | 8 | 13 |
| LFI | 7 | 20 | 27 |
| Open Redirect | 5 | 20 | 25 |
| IDOR | 5 | 20 | 25 |
| Logic | 6 | 20 | 26 |
| CSRF | — | — | — |
| **Total** | **~76** | **~241** | **~317** |

CSRF no utiliza payloads ya que su detección se basa en análisis estático del formulario.

Este diseño modular permite añadir nuevos tipos de vulnerabilidad o ampliar las listas de payloads existentes sin modificar la lógica del motor o del analizador.

[Esquema: Ejemplo de estructura interna de un módulo de payloads (xss.py)]



## 3.7. Analizador de respuestas

El módulo `analyzer.py` es el responsable de evaluar las respuestas del servidor y determinar si una inyección ha tenido éxito. Implementa un analizador especializado para cada tipo de vulnerabilidad, registrado en un diccionario interno que el método principal `analyze()` consulta.

### 3.7.1. Técnicas de detección

El analizador emplea cuatro técnicas de detección principales:

**Reflexión directa**: Verifica si el payload enviado aparece literalmente en el cuerpo de la respuesta, sin haber sido codificado ni escapado. Es la técnica principal para detectar XSS reflejado.

**Coincidencia de patrones**: Busca en la respuesta cadenas o expresiones regulares asociadas a errores o comportamientos de sistemas vulnerables. Por ejemplo, mensajes de error de bases de datos SQL (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), errores LDAP, o contenido de archivos del sistema como `/etc/passwd`.

**Análisis temporal (time-based)**: Compara el tiempo de respuesta de la petición inyectada con el tiempo de la respuesta base. Si la diferencia supera un umbral (2,5 segundos), se considera un indicio de inyección ciega basada en tiempo (blind SQL injection o blind command injection).

**Análisis heurístico**: Detecta cambios significativos en el comportamiento de la aplicación, como variaciones en el tamaño de la respuesta superiores al 30% (inyección booleana), códigos de estado de redirección (301-308) para Open Redirect, o la aceptación de datos que deberían ser rechazados (errores lógicos).

### 3.7.2. Puntuación de confianza

Cada detección recibe una puntuación de confianza entre 0.0 y 1.0 que indica la fiabilidad del hallazgo:

| Técnica | Confianza |
|---------|-----------|
| Reflexión directa | 0.90 - 0.95 |
| Coincidencia de patrones | 0.70 - 0.85 |
| Análisis temporal | 0.60 - 0.75 |
| Heurísticas | 0.50 - 0.65 |

Esta clasificación permite al usuario priorizar los hallazgos más fiables y descartar posibles falsos positivos con baja confianza.

### 3.7.3. Caso especial: CSRF

La detección de CSRF no sigue el patrón de inyección-respuesta. En su lugar, el analizador inspecciona la estructura del formulario buscando la ausencia de tokens anti-CSRF en formularios que utilizan el método POST. Solo se reporta como vulnerabilidad si el formulario es POST y no contiene ningún campo oculto con nombres típicos de token CSRF.

[Esquema: Diagrama de decisión del analizador para una respuesta inyectada]



## 3.8. Generador de informes

El módulo `reporter.py` genera informes estructurados en dos formatos: JSON y HTML. El formato se determina automáticamente por la extensión del archivo de salida.

### 3.8.1. Formato JSON

El informe JSON contiene toda la información del escaneo en formato legible por máquinas:

- URL analizada, modo de escaneo, marca de tiempo y duración.
- Estructura del formulario (campos, método, acción).
- Resumen estadístico (total de vulnerabilidades por severidad).
- Lista detallada de vulnerabilidades con tipo, severidad, campo, payload, evidencia, descripción y confianza.
- Análisis con IA (si se activó).

### 3.8.2. Formato HTML

El informe HTML presenta los resultados en una interfaz web visual con:

- Cabecera con los metadatos del escaneo.
- Panel de estadísticas con contadores por severidad codificados por colores (rojo para críticas, naranja para altas, amarillo para medias, verde para bajas).
- Tabla de vulnerabilidades con badges de severidad, tipo, campo, descripción, payload y evidencia.
- Sección de análisis con IA (si se activó).
- Pie de página con la información de generación.

El diseño utiliza CSS nativo sin dependencias externas, con un estilo oscuro responsive.

[Esquema: Captura de pantalla de un informe HTML generado]



## 3.9. Módulo de análisis con IA (opcional)

El módulo `ai_analyzer.py` implementa una capa de análisis complementaria que utiliza modelos de lenguaje para validar y priorizar los hallazgos del escaneo. Es importante destacar que la IA no se utiliza como motor de detección, sino como segunda opinión experta.

### 3.9.1. Proveedores soportados

La herramienta soporta tres proveedores de IA con APIs gratuitas:

| Proveedor | Modelo | Método de acceso |
|-----------|--------|------------------|
| Gemini (Google) | gemini-2.0-flash-lite | API REST directa |
| Groq | llama-3.1-8b-instant | API REST (compatible OpenAI) |
| OpenAI | Configurable | API REST estándar |

La API key se puede proporcionar por línea de comandos (`--ai-key`) o mediante variables de entorno (`GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENAI_API_KEY`).

### 3.9.2. Flujo de análisis

1. Se construye un prompt estructurado que incluye la URL analizada, el método del formulario, los campos, el modo de escaneo y un resumen de cada vulnerabilidad detectada (tipo, severidad, campo, payload, evidencia y confianza).
2. El prompt solicita al modelo tres tipos de análisis: validación de verdaderos y falsos positivos, evaluación del riesgo global y recomendaciones de mitigación priorizadas.
3. La respuesta del modelo se almacena en el `ScanResult` y se incluye tanto en la salida por consola como en el informe generado.

[Esquema: Diagrama de secuencia del flujo de análisis con IA]



## 3.10. Interfaz de línea de comandos

El módulo `cli.py` implementa la interfaz de usuario mediante la librería Click. El diseño de la CLI sigue las convenciones de las herramientas de seguridad, con opciones cortas para los parámetros más habituales.

### 3.10.1. Parámetros

| Parámetro | Corto | Descripción |
|-----------|-------|-------------|
| `--url` | `-u` | URL del formulario (obligatorio) |
| `--tests` | `-T` | Tipos de pruebas (por defecto: todas) |
| `--full` | `-F` | Modo exhaustivo |
| `--output` | `-o` | Archivo de salida |
| `--cookie` | — | Cookies de sesión |
| `--form-index` | — | Índice del formulario |
| `--timeout` | — | Timeout de conexión |
| `--test` | — | Solo verificar formulario |
| `--ai` | — | Activar análisis IA |
| `--ai-provider` | — | Proveedor IA |
| `--ai-key` | — | API key |

### 3.10.2. Flujo de ejecución

El flujo de la CLI sigue estos pasos:

1. Muestra el banner con la versión y el aviso de uso autorizado.
2. Parsea las cookies y los tipos de prueba.
3. Invoca al Parser para obtener los formularios.
4. Muestra la información del formulario detectado (método, campos, token CSRF).
5. Ejecuta el Motor de pruebas con un callback de progreso que muestra cada detección en tiempo real.
6. Si se activó `--ai`, envía los resultados al módulo de IA.
7. Muestra el resumen con las vulnerabilidades encontradas codificadas por color.
8. Si se especificó `-o`, genera el informe. Los informes se guardan automáticamente en la carpeta `reportes/` cuando no se indica una ruta completa.

[Esquema: Captura de pantalla de la salida de la CLI tras un escaneo]



## 3.11. Decisiones de diseño

A lo largo del desarrollo se tomaron varias decisiones de diseño que conviene documentar:

**Nombre de la herramienta**: El nombre Gung12 proviene de Gungnir, la lanza del dios nórdico Odín que nunca fallaba su objetivo, combinado con el número 12, que representa las doce categorías de vulnerabilidades que cubre la herramienta.

**Modularidad sobre monolito**: Se optó por separar cada etapa del pipeline en un módulo independiente. Esto permite, por ejemplo, utilizar el parser sin el motor de pruebas, o añadir nuevos tipos de vulnerabilidad creando un nuevo archivo de payloads sin modificar el código existente.

**Payloads en dos modos**: La separación entre modo rápido y exhaustivo permite al usuario elegir entre velocidad y cobertura. El modo rápido es útil para una primera evaluación, mientras que el exhaustivo está diseñado para auditorías más profundas.

**IA como complemento**: Se decidió que la IA no participase en la detección, sino en la validación. Esto evita depender de APIs externas para el funcionamiento básico de la herramienta y garantiza que los resultados sean reproducibles.

**Deduplicación de resultados**: El motor evita reportar la misma vulnerabilidad múltiples veces en el mismo campo, mostrando solo la primera detección. Esto reduce el ruido en los informes sin perder información relevante.

**CSRF como análisis estático**: A diferencia del resto de vulnerabilidades, CSRF no se detecta mediante inyección sino mediante inspección de la estructura del formulario. Solo se reporta en formularios POST sin token, ya que los formularios GET no son relevantes para CSRF.

**User-Agent identificado**: Las peticiones HTTP incluyen el encabezado `User-Agent: Gung12/1.0 (Security Scanner - Authorized Testing Only)` para que los administradores del servidor puedan identificar el tráfico como legítimo en un contexto de auditoría autorizada.



---

## Referencias del Capítulo 3

*NOTA: Este capítulo no introduce referencias bibliográficas nuevas. Los conceptos técnicos se apoyan en las referencias presentadas en los capítulos 1 y 2.*
