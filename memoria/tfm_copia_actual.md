# TFM — Copia corregida de referencia (17 abril 2026)
## Plataforma automática de detección de vulnerabilidades en formularios web
**Máster Universitario en Ciberseguridad — UA**
**Autor:** Den Reanin Gerasimov
**Tutor:** José Luis Verdeguer Navarro
**Julio 2026**

---

## Resumen

Desarrollo de una herramienta en Python capaz de analizar formularios web específicos a partir de una URL concreta y ejecutar pruebas dinámicas de seguridad (XSS, SQLi, SSTI, LFI, Command Injection, entre otras) mediante el envío de payloads controlados. El sistema analiza las respuestas del servidor para detectar indicios de vulnerabilidad y genera un informe estructurado con los formularios analizados, las pruebas realizadas y los posibles fallos encontrados.

[Castellano — traducir al valenciano e inglés]

---

## 1. Introducción

En esta sección introductoria, se explicará la contextualización y justificación del proyecto, destacando los desafíos actuales en la seguridad de aplicaciones web. Adicionalmente se establecerán los objetivos generales y específicos a los cuales se quiere llegar. Finalizando con la muestra de la metodología llevada a cabo para abordar el TFM.

### 1.1. Contextualización y justificación

En la actualidad, las aplicaciones web son una parte fundamental de cualquier negocio, siendo clave para cualquier infraestructura digital. Estas son utilizadas ampliamente en todos los sectores, desde la banca y el comercio electrónico hasta la sanidad y la administración pública.

Esta relevancia las convierte en uno de los activos más codiciados y atractivos para los atacantes. Según el informe de IBM Security, el coste medio de una brecha de datos fue de 4,44 millones de dólares en 2025, tras haber alcanzado los 4,88 millones en 2024, siendo las aplicaciones web uno de los vectores de ataque más frecuentes [1].

Dentro de las aplicaciones web, los formularios representan uno de los puntos de entrada más críticos. A través de ellos, los usuarios proporcionan datos que el servidor procesa directamente: credenciales, consultas, archivos y parámetros de configuración. Cuando estos datos no se validan ni se sanean adecuadamente, pueden explotarse para ejecutar ataques de inyección, manipulación de datos o acceso no autorizado.

Las vulnerabilidades asociadas a formularios web abarcan una gran variedad de categorías, entre las que destacan la inyección SQL (SQLi), el Cross-Site Scripting (XSS), la inclusión de archivos locales (LFI) o la inyección de comandos del sistema operativo, entre otras [2] [3].

El proyecto OWASP (Open Web Application Security Project)¹, es actualmente un referente internacional en seguridad de aplicaciones, el cual publica periódicamente una lista de la llamada "Top 10". Esta lista recoge las categorías de vulnerabilidades más críticas, en su edición de 2025 las inyecciones se posicionan en mitad de tabla (A05) [4].

Los datos demuestran que, a pesar de los avances tecnológicos y el desarrollo seguro de aplicaciones, las vulnerabilidades en los formularios siguen siendo un problema a gran escala.

Para poder mitigar las amenazas, la industria ha desarrollado herramientas de análisis dinámico de seguridad (DAST). Las herramientas permiten realizar pruebas automáticas sobre aplicaciones web en ejecución [5]. Sin embargo, su uso tiene limitaciones: requieren una configuración, poseen una curva de aprendizaje compleja e incluso implican pagar unos costes por el uso [6].

Por otra parte, gran parte de estas herramientas utilizan payloads genéricos, lo que facilita su bloqueo por parte de firewalls de aplicaciones web (WAF). Adicionalmente tampoco resultan muy eficaces en situaciones donde el formulario es generado dinámicamente mediante frameworks JavaScript modernos como puede ser Angular² o React³. Tampoco ante flujos de formularios de múltiples pasos donde es necesario un estado de sesión [7].

Todas estas limitaciones dejan la oportunidad de desarrollar herramientas más específicas y orientadas a la detección en formularios concretos. En este contexto, el presente Trabajo Fin de Máster propone el desarrollo de una herramienta de línea de comandos (CLI) en Python⁴, especializada en la detección automatizada de vulnerabilidades en formularios web.

La elección del TFM surge de la experiencia previa en el desarrollo web, obtenida durante mis estudios del Grado de Ingeniería Multimedia. Durante ese tiempo, obtuve conocimientos de cómo funciona la arquitectura y los protocolos HTTP, además de la comunicación cliente-servidor.

Simultáneamente, hubo una influencia del Máster de Ciberseguridad, donde se estudiaron y se realizaron las diferentes técnicas de ataque y defensa en las aplicaciones web. Además de la presencia de la inteligencia artificial que promueve a mejorar los sistemas de detección.

> ¹ https://owasp.org/
> ² https://angular.dev/
> ³ https://react.dev/
> ⁴ https://www.python.org/

### 1.2. Objetivos

En este apartado, se expondrán los objetivos establecidos para lograr el correcto funcionamiento del Trabajo Fin de Máster. Empezando por el objetivo general y continuando con la definición de los objetivos específicos que describen la funcionalidad concreta de la herramienta.

El objetivo general es desarrollar una herramienta de línea de comandos en Python con la capacidad de analizar formularios web de manera automática. Además de ejecutar pruebas dinámicas de seguridad mediante el envío de payloads y generar informes. La herramienta no pretende ser un escáner genérico de sitios completos, sino un analizador de formularios específicos.

Los objetivos específicos que se abordarán durante el desarrollo del proyecto son:

- Diseñar e implementar un módulo de análisis de formularios HTML que permita:
  - Acceder a una URL concreta que contenga un formulario web.
  - Obtener la estructura del formulario.
  - Realizar una petición válida al servidor para verificar el correcto funcionamiento del formulario.
- Desarrollar un motor de pruebas basado en payloads que cubra doce categorías de vulnerabilidades:
  - Inyecciones: SQL Injection (SQLi), NoSQL Injection, LDAP Injection, Command Injection y Server-Side Template Injection (SSTI).
  - Ataques de inclusión y entidades: Local File Inclusion (LFI) y XML External Entity Injection (XXE).
  - Ataques del lado del cliente: Cross-Site Scripting (XSS) reflejado.
  - Fallos de protección: Cross-Site Request Forgery (CSRF) y Open Redirect.
- Implementar un analizador de respuestas capaz:
  - Clasificar los datos obtenidos por nivel de importancia.
  - Detectar comportamientos insólitos del servidor al recibir los payloads.
- Generar informes estructurados en formatos JSON y HTML que recojan:
  - Los formularios analizados y su estructura.
  - Las pruebas realizadas por tipo de vulnerabilidad.
  - Los indicios detectados con su clasificación de severidad.
- Validar la herramienta contra entornos de prueba (DVWA⁵, WebGoat⁶).

> ⁵ https://github.com/digininja/DVWA
> ⁶ https://owasp.org/www-project-webgoat/

### 1.3. Metodología del proyecto

[PENDIENTE — Definición del alcance → Revisión literatura → Implementación → Pruebas → Conclusiones]

[Explicación + Esquema Imagen]

---

## 2. Seguridad en aplicaciones web

En este capítulo se establece el marco teórico del proyecto, abordando el contexto actual de la seguridad en aplicaciones web y los principales tipos de vulnerabilidades que afectan a los formularios. Posteriormente, se analizan las herramientas de detección existentes, sus capacidades y sus limitaciones.

### 2.1. Contexto general de la seguridad web

Durante estos últimos años, la seguridad digital ha sufrido diversos cambios, muchos de ellos influenciados por la inteligencia artificial y por la sofisticación de los ataques. Por tanto, la seguridad de las aplicaciones web se ha convertido en una de las áreas más relevantes dentro de la ciberseguridad.

El enorme crecimiento de los servicios en línea, impulsado por la transformación digital, ha ampliado la superficie de ataque para los ciberdelincuentes. Según Cloudflare, en el primer trimestre de 2024 se bloquearon 209 mil millones de amenazas diarias, un 86,6 % más que el año anterior [8]. Muchas aplicaciones web que se crean y que están disponibles en internet, son puntos de entrada que tienen que ser debidamente protegidos para no llegar a problemas mayores.

Los ataques contra aplicaciones web han evolucionado tanto en sofisticación como en volumen. Según el DBIR de 2025, el 44 % de las brechas analizadas involucraron ransomware y el 30 % estuvieron relacionadas con terceros, duplicando la cifra del año anterior [9].

La presión del mercado de lanzar las aplicaciones con la máxima velocidad posible provoca riesgos que no se deberían concebir, como posponer la seguridad del servicio a un segundo plano y con la intención de solucionarlo más tarde.

El escenario actual no es un suceso reciente, sino una consecuencia directa de un comportamiento tendencial consolidado en los últimos años. La inyección ha sido un problema constante en la seguridad y hasta el momento se ha mantenido entre las categorías más críticas. Esto se puede corroborar en la publicación del OWASP Top 10 tanto en el año 2017 como en el 2025.

La pandemia de 2020 agilizó el proceso de digitalización de los servicios, multiplicando el número de aplicaciones web accesibles. Un acontecimiento más reciente es el auge de la inteligencia artificial generativa, que ha permitido crear ataques potentes, aumentando tanto el volumen como la complejidad de las amenazas [8]. La Figura 1 recoge los hitos más relevantes de los últimos años.

[Figura 1. Línea temporal — Evolución de las amenazas en seguridad web (2017–2025)]
Datos para la figura:
- 2024–2025: 4,44M$ coste medio por brecha (baja desde 4,88M$) [1]
- 2025: 44 % ransomware, 30 % brechas por terceros [9]
- 2024: 209B amenazas diarias bloqueadas (+86,6 % interanual) [8]

En las secciones siguientes se analizan en detalle las categorías de vulnerabilidades más relevantes para los formularios web, el marco de referencia OWASP y las herramientas de detección existentes.

### 2.2. Clasificación de vulnerabilidades en formularios web

En esta sección se describen las doce categorías de vulnerabilidades que cubre la herramienta desarrollada en este TFM. Para cada una se presenta su definición, el mecanismo de explotación, el impacto potencial y los indicios que permiten su detección automatizada.

#### 2.2.1. Cross-Site Scripting (XSS)

Comúnmente conocido como XSS, es una vulnerabilidad que permite a un atacante inyectar código JavaScript malicioso en páginas web que otros usuarios visualizan. El ataque explota la confianza que el navegador del usuario deposita en el contenido proveniente del servidor [11].

Las principales variantes de XSS se pueden agrupar en lo siguiente:

- El reflejado, cuando el payload se incluye en la petición y se refleja en la respuesta sin ser almacenado.
- El almacenado, donde el código infectado se guarda en el servidor y se activa cada vez que el usuario accede al contenido afectado.
- Basado en DOM, la manipulación ocurre directamente en el navegador, sin que el servidor intervenga [3].

En este trabajo se aborda principalmente el XSS reflejado, debido a que es el que más está asociado a formularios web. El procedimiento sería el siguiente: el atacante introduce un payload en un campo del formulario, la aplicación lo incluye en la respuesta HTML sin sanitizar, y el navegador lo ejecuta como código legítimo.

Para detectar el XSS reflejado, se necesita buscar la aparición del payload enviado dentro del cuerpo de la respuesta, sin que este haya sido codificado o escapado. Los payloads más comunes podrían ser etiquetas de script, manejadores de eventos y ataques que evitan filtros básicos mediante variaciones de texto [11]. La Figura 2 ilustra el flujo de este tipo de ataque.

[Figura 2. Esquema de ataque XSS reflejado]

#### 2.2.2. SQL Injection (SQLi)

La inyección SQL es una de las vulnerabilidades más antiguas y documentadas en la seguridad web. Sencillamente, consiste en la inserción de código SQL en campos de entrada que no están correctamente parametrizados y que son utilizados en consultas a la base de datos [2].

Un atacante puede aprovechar esta vulnerabilidad para evitar mecanismos de autenticación, obtener información confidencial de la base de datos, modificar o eliminar registros, e incluso ejecutar comandos en el sistema operativo [12].

Existen diferentes tipos de SQLi, empezando por inyección clásica basada en errores. Donde los mensajes de error de la base de datos dan información sobre el sistema. Por otra parte, la inyección ciega booleana, donde el atacante infiere datos mediante preguntas lógicas (VERDADERO o FALSO), analizando si el contenido de la página cambia. Por último, la inyección ciega basada en tiempo, donde el atacante obtiene información a partir del tiempo de respuesta del servidor, esto se puede manejar mediante comandos de pausa [13].

La detección automatizada se apoya en el envío de payloads que alteran la sintaxis SQL (comillas simples, operadores OR 1=1, comentarios --) y en el análisis de las respuestas buscando mensajes de error de bases de datos conocidas (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) o cambios significativos en el contenido de la respuesta [12]. La Figura 3 muestra el esquema de este ataque.

[Figura 3. Esquema de ataque SQL Injection]

#### 2.2.3. Server-Side Template Injection (SSTI)

La inyección en plantillas del lado del servidor (SSTI) ocurre cuando la entrada del usuario es interpretada como parte de una plantilla de un motor de renderizado (Jinja2, Twig, Freemarker, ERB, entre otros), en lugar de tratarse como un dato común [14].

Esta vulnerabilidad puede tener un impacto crítico, debido a que los motores de plantillas suelen tener acceso al sistema de archivos, variables de entorno y ejecución de código arbitrario. Un formulario que inserte directamente los datos del usuario en una plantilla sin aplicar un filtrado puede ser explotado para leer archivos, ejecutar comandos o comprometer el servidor por completo [14].

El mecanismo de detección más común consiste en enviar expresiones matemáticas específicas de cada motor de plantillas y observar si la respuesta contiene el resultado esperado (49). Este número indica que la entrada fue procesada como código de plantilla [15]. La Figura 4 representa el flujo de detección.

[Figura 4. Esquema de ataque SSTI]

#### 2.2.4. LDAP Injection

LDAP (Lightweight Directory Access Protocol) es un protocolo que se utiliza en entornos corporativos para gestionar la autenticación y la información de los usuarios. Por tanto, la inyección de LDAP sucede cuando los datos del usuario se incorporan sin sanitizar en las consultas [16].

Un atacante puede manipular las consultas LDAP para modificar los filtros de búsqueda, eludir el proceso de autenticación o acceder a información de otros usuarios almacenada en el directorio. Un caso sería la inyección de un comodín (*) en un formulario de inicio de sesión.

La detección se centra en el envío de caracteres especiales (como *, (, ), |) y en el análisis de la respuesta para detectar cambios en el comportamiento de la aplicación, errores del servidor LDAP o accesos no autorizados a información del directorio [16]. La Figura 5 muestra este proceso.

[Figura 5. Esquema de ataque LDAP Injection]

#### 2.2.5. Command Injection

Cuando una aplicación web envía los datos proporcionados por el usuario directamente a una función que ejecuta comandos en el sistema operativo (system(), exec(), popen()), se conoce como inyección de comandos del sistema operativo [17].

Se considera como una vulnerabilidad importante, porque el atacante tiene la capacidad de ejecutar comandos con permisos del servidor web. Esto implica la lectura de archivos sensibles, la instalación de puertas traseras, entre otras capacidades.

Los payloads habituales utilizan caracteres de concatenación de comandos propios de distintos sistemas operativos: el punto y coma (;) y el pipe (|) en Linux, o el ampersand (&) en Windows. Para poder detectar automáticamente esta vulnerabilidad, consiste en buscar en la respuesta la salida de comandos conocidos como whoami, id, uname, etc. [17]. La Figura 6 ilustra el esquema de explotación.

[Figura 6. Esquema de ataque Command Injection]

#### 2.2.6. NoSQL Injection

La inyección NoSQL es similar a la inyección SQL, pero dirigida a las bases de datos no relacionales como MongoDB o Firebase. Estas bases de datos al tener otro formato de consulta alteran tanto la explotación como la detección [18].

Un atacante tiene la capacidad de manipular las consultas NoSQL con operadores especiales como $ne (no igual), $gt (mayor que) o $regex, insertados en los datos del formulario. Esto permite engañar la autenticación o extraer datos de forma no autorizada, un ejemplo: `{"$ne": ""}` [18].

La detección se basa en el envío de payloads con operadores NoSQL en el cuerpo de la petición y en la observación de cambios en el comportamiento de la aplicación, como respuestas exitosas ante credenciales claramente inválidas [19]. La Figura 7 presenta el flujo de este ataque.

[Figura 7. Esquema de ataque NoSQL Injection]

#### 2.2.7. XML External Entity Injection (XXE)

Esta vulnerabilidad explota el procesamiento de documentos XML por parte del servidor. Cuando una aplicación acepta entradas en formato XML y su parser tiene habilitada la resolución de entidades externas, un atacante puede definir entidades que apunten a recursos del sistema de archivos del servidor o a servicios internos de la red [20].

El impacto de XXE abarca desde la lectura de archivos sensibles del servidor, hasta la realización de ataques de tipo Server-Side Request Forgery (SSRF) [20]. En el contexto de formularios web, XXE es relevante cuando la aplicación acepta datos en formato XML.

La detección consiste en enviar documentos XML con definiciones de entidades externas que referencien archivos conocidos y verificar si su contenido aparece en la respuesta. La Figura 8 esquematiza este proceso.

[Figura 8. Esquema de ataque XXE]

#### 2.2.8. Cross-Site Request Forgery (CSRF)

Es un vector de ataque que obliga al navegador de un usuario autenticado a enviar una petición no deseada a una aplicación web en la que tiene una sesión activa. CSRF explota la confianza del sitio en el navegador del usuario, mientras que el XSS se basa en comprometer la confianza del usuario hacia el sitio [21].

Una manera básica para protegerse es incluir un token único en cada formulario, que debe ser verificado por el servidor. El no uso del token deja al formulario vulnerable a acciones no autorizadas por el atacante.

Esta vulnerabilidad tiene un punto diferenciador y es que su detección no se realiza mediante payloads, sino mediante el análisis de la estructura del formulario. La herramienta inspecciona si el formulario contiene campos ocultos con tokens anti-CSRF y si estos muestran valores únicos entre distintas peticiones [21]. La Figura 9 muestra el esquema de detección.

[Figura 9. Esquema de detección CSRF]

#### 2.2.9. Local File Inclusion (LFI)

LFI es una vulnerabilidad que surge cuando una aplicación web usa las entradas del usuario para determinar qué archivos se deben cargar, sin validar la ruta adecuadamente. Esto permite a un atacante navegar por la estructura de directorios del servidor mediante saltos de directorio (../) para acceder a archivos fuera del directorio esperado [10].

El objetivo de este ataque es extraer información sensible como /etc/passwd en sistemas Linux o claves SSH, entre otras. También existe la posibilidad de ejecución remota de código.

Para poder detectarlo, radica en el envío de rutas relativas con secuencias de retroceso (../../etc/passwd, sus variantes con codificación URL %2e%2e%2f, y variantes con doble codificación) y en la búsqueda de contenido conocido de dichos archivos en la respuesta del servidor [10]. La Figura 10 ilustra el proceso.

[Figura 10. Esquema de ataque LFI]

#### 2.2.10. Open Redirect

La redirección abierta sucede cuando una aplicación web acepta una URL que fue proporcionada por el usuario como destino de una redirección. La parte grave está en que dicha URL no está validada, es decir, si es legítima. Entonces esto permite que un atacante tenga la capacidad de construir enlaces que redirijan a la víctima a un sitio malicioso [22].

Su uso preferencial es en phishing, ya que el enlace inicial apunta a un dominio legítimo, lo que aumenta la credibilidad del ataque y puede facilitar el robo de credenciales.

La detección se realiza enviando como valor del parámetro de redirección URLs de dominios externos y verificando si la respuesta del servidor incluye una redirección HTTP hacia el dominio establecido. La Figura 11 muestra este esquema.

[Figura 11. Esquema de ataque Open Redirect]

#### 2.2.11. Insecure Direct Object Reference (IDOR)

La referencia directa insegura a objetos es una vulnerabilidad que sucede cuando no se comprueba si el usuario solicitante tiene los permisos suficientes para ese recurso. Ocurre porque la aplicación utiliza identificadores proporcionados por el usuario como IDs numéricos o nombres de archivo [4].

Un ejemplo habitual se presenta en formularios que incluyen campos ocultos con el identificador del usuario (como user_id=001). Si el servidor no valida que el usuario autenticado corresponde al ID proporcionado, un atacante puede modificar dicho valor para acceder a los datos o funcionalidades de otros usuarios.

La detección automatizada consiste en modificar los valores de los parámetros de identificación y comprobar si el servidor devuelve información correspondiente a otros recursos sin devolver un error de autorización. La Figura 12 representa este proceso.

[Figura 12. Esquema de ataque IDOR]

#### 2.2.12. Errores lógicos y validaciones ausentes

Los errores lógicos son la ausencia de validaciones sobre los datos enviados por el usuario, no es una técnica de inyección. Estos errores se detectan comprobando si la aplicación acepta datos que deberían ser rechazados [23].

Ejemplos clásicos:

- campos obligatorios que admiten valores vacíos
- campos numéricos que aceptan valores negativos o fuera de rango
- campos de correo electrónico que no validan el formato
- longitudes de entrada sin restricción que pueden provocar comportamientos inesperados

La detección se basa en poner la aplicación web al límite, buscando errores y realizando acciones para las cuales no estaba destinado el formulario. De esta manera, se podrá verificar si el servidor procesa los datos sin devolver algún error de validación. Las pruebas buscan comprobar la robustez de la lógica de negocio del formulario. La Figura 13 esquematiza la detección.

[Figura 13. Esquema de detección de errores lógicos]

### 2.3. OWASP como marco de referencia

El Open Web Application Security Project o mejor conocido como OWASP, es una fundación sin ánimo de lucro que se dedica a mejorar la seguridad del software. Una de sus más famosas iniciativas es el OWASP Top 10 que es una lista donde se identifica y clasifica las diez categorías con mayor riesgo en las aplicaciones web. Este contenido se actualiza periódicamente obteniendo datos reales de la comunidad [4].

En su edición de 2025, las categorías del OWASP Top 10 son las siguientes:

Tabla 1. Categorías del OWASP Top 10 — 2025 [4].

| Posición | Categoría |
|----------|-----------|
| A01 | Broken Access Control (Control de acceso deficiente) |
| A02 | Security Misconfiguration (Configuraciones incorrectas) |
| A03 | Software Supply Chain Failures (Fallos en la cadena de suministro) |
| A04 | Cryptographic Failures (Fallos criptográficos) |
| A05 | Injection (Inyección) |
| A06 | Insecure Design (Diseño inseguro) |
| A07 | Authentication Failures (Fallos de autenticación) |
| A08 | Software or Data Integrity Failures (Fallos de integridad) |
| A09 | Security Logging and Alerting Failures (Fallos de monitorización) |
| A10 | Mishandling of Exceptional Conditions (Manejo inadecuado de excepciones) |

Las doce vulnerabilidades tratadas en este TFM se relacionan con varias de estas categorías. La siguiente tabla muestra la correspondencia:

Tabla 2. Correspondencia entre las vulnerabilidades tratadas y las categorías OWASP 2025.

| Vulnerabilidad tratada | Categoría OWASP 2025 |
|------------------------|---------------------|
| SQLi, NoSQL, LDAP, Command Injection, SSTI, XXE | A05 — Injection |
| XSS (reflejado) | A05 — Injection |
| LFI | A05 — Injection |
| CSRF | A01 — Broken Access Control |
| IDOR | A01 — Broken Access Control |
| Open Redirect | A01 — Broken Access Control |
| Errores lógicos | A06 — Insecure Design / A10 — Mishandling of Exceptional Conditions |

Como se observa, la gran parte de las vulnerabilidades analizadas se encuadran en la categoría A05, que agrupa todo tipo de ataques donde la entrada del usuario se interpreta como código o comandos. El resto se relaciona con el control de acceso (A01) y el diseño inseguro (A06).

Otra iniciativa que proporciona OWASP es la Testing Guide, que describe las técnicas y procedimientos para evaluar la seguridad de aplicaciones web [15]. Esta guía ha servido como referencia para definir las estrategias de detección aplicadas a cada vulnerabilidad.

### 2.4. Herramientas de análisis dinámico existentes

Como se mencionaba en la Contextualización y justificación, un DAST es una herramienta de análisis dinámico de seguridad de aplicaciones que valora la seguridad de una aplicación web en tiempo de ejecución. Lo realiza mediante el envío de peticiones HTTP y analizando las respuestas del servidor. A continuación, se analizan las herramientas más representativas del sector.

#### 2.4.1. OWASP ZAP

Zed Attack Proxy⁷ es una herramienta de código abierto desarrollada y mantenida por la comunidad OWASP. Funciona como un proxy de interceptación que permite analizar el tráfico entre el navegador y el servidor. Además de incorporar un escáner activo que lanza automáticamente pruebas de vulnerabilidad contra los endpoints detectados [5].

Sus principales características:

- El spidering automático de aplicaciones web.
- El escaneo activo y pasivo de vulnerabilidades.
- Un sistema de alertas con clasificación por severidad.
- Posible uso de API REST.

Su uso está orientado principalmente para un ámbito educativo y para auditorías de seguridad de nivel básico e intermedio. No obstante, tiene unas limitaciones entre ellas está su pérdida de rendimiento en aplicaciones de gran tamaño. También existen casos donde su configuración requiera un esfuerzo adicional elevado. Muchos de sus payloads que están documentados pueden ser bloqueados por WAFs [6].

> ⁷ https://www.zaproxy.org/

#### 2.4.2. Burp Suite

Desarrollada por PortSwigger⁸, esta plataforma es considerada el estándar de la industria en el ámbito de la seguridad web profesional. Es una aplicación que integra varios módulos, entre estos: un proxy de interceptación, escáner automatizado, un intruder personalizado, entre otros módulos [10].

En la versión Professional, la cual es de pago, tiene un escáner automatizado que es considerado de los más precisos del mercado. Sin embargo, la versión Community (gratuita) no tiene disponible esa funcionalidad lo que limita su uso para pruebas de detección automatizada.

Las principales limitaciones de Burp Suite [6]:

- Curva de aprendizaje elevada
- Precio alto por la licencia de pago
- Configuración manual para escenarios complejos

Por tanto, es una gran herramienta, pero debido a sus limitaciones, se puede llegar a considerar otras alternativas más atractivas.

> ⁸ https://portswigger.net/burp

#### 2.4.3. Nikto

A diferencia de las herramientas anteriores, Nikto⁹ no analiza aplicaciones web al completo, sino que se especializa en evaluar la configuración del servidor. De carácter abierto y gratuito, sus análisis se centran en [24]:

- Configuraciones incorrectas del servidor
- Archivos peligrosos accesibles públicamente
- Versiones de software con vulnerabilidades conocidas
- Cabeceras HTTP mal configuradas

Su enfoque está orientado a la infraestructura del servidor más que a la lógica de la aplicación, por lo que no es directamente comparable con herramientas de análisis de formularios. No obstante, su análisis resulta un complemento útil para obtener una visión más amplia de la seguridad del entorno.

En el contexto de este TFM, Nikto no resulta aplicable ya que no analiza formularios web ni envía payloads a campos de entrada.

> ⁹ https://cirt.net/Nikto2

#### 2.4.4. sqlmap

Mientras que las herramientas anteriores cubren múltiples categorías de vulnerabilidades, sqlmap¹⁰ adopta un enfoque opuesto: se dedica exclusivamente a la detección y explotación automatizada de inyecciones SQL. Distribuido bajo licencia libre, incorpora un motor de detección avanzado con soporte para múltiples sistemas de gestión de bases de datos y técnicas tanto de inyección clásica como ciega [25].

En su ámbito concreto, sus capacidades superan a las de cualquier escáner genérico. Sin embargo, su alcance se limita a la inyección SQL, sin cubrir ninguna otra categoría de vulnerabilidad. Además, requiere que se le proporcionen manualmente los endpoints y parámetros, lo que la hace dependiente de un análisis previo de la aplicación.

> ¹⁰ https://sqlmap.org/

#### 2.4.5. Tabla comparativa de herramientas

Tabla 3. Comparativa de herramientas DAST existentes.

|                     | OWASP ZAP    | Burp Suite    | Nikto        | sqlmap       |
|---------------------|-------------|---------------|-------------|-------------|
| **Licencia**        | Open source | Freemium      | Open source | Open source |
| **Tipo de análisis**| DAST general| DAST general  | Servidor    | SQLi específico |
| **Análisis de formularios** | Sí  | Sí (Pro)     | No          | Parcial     |
| **Tipos de vuln.**  | Múltiples   | Múltiples     | Configuración| Solo SQLi  |
| **Curva de aprendizaje** | Media  | Alta         | Baja        | Media       |
| **Payloads propios**| Sí          | Sí            | N/A         | Sí          |
| **Evasión de WAF**  | Limitada    | Avanzada (Pro)| No          | Sí          |
| **Informes**        | HTML/XML    | HTML/XML (Pro)| Texto/CSV   | Texto       |
| **Coste**           | Gratuito    | 475€/año (Pro)| Gratuito    | Gratuito    |

### 2.5. Síntesis del estado del arte y oportunidad

El análisis del contexto actual demuestra que las aplicaciones web siguen siendo actualmente un vector de ataque, con un 44 % de las brechas involucrando ransomware y un 30 % relacionadas con terceros [9]. Los formularios web siguen considerándose como un punto crítico de entrada, debido a la presión de desplegar los servicios con más rapidez y la evolución de los ataques de ciberseguridad.

Se han identificado doce categorías de vulnerabilidades que afectan directamente a formularios web, la mayoría se clasifican en la categoría A05 (Injection) del OWASP Top 10 2025. Estas abarcan desde inyecciones clásicas (SQLi, XSS) hasta fallos de diseño (IDOR, errores lógicos), demostrando la gran cantidad de peligros que pueden llegar a afectar a un formulario mal protegido.

Gracias al trabajo realizado en la sección anterior se puede identificar tanto las fortalezas como las carencias del panorama actual de las herramientas de análisis dinámico de seguridad. Por una parte, existen herramientas que ofrecen facilidades para detectar vulnerabilidades como OWASP ZAP o Burp Suite. Sin embargo, presentan limitaciones como la complejidad de uso, payloads genéricos, coste e insuficiencia en especialización en formularios.

Adicionalmente, hay otras herramientas que no cubren de manera completa las vulnerabilidades que afectan a los formularios porque están especializadas en otras tareas. Por tanto, este análisis del estado del arte evidencia la oportunidad de desarrollar una herramienta que se centre específicamente en formularios web como vector de ataque.

Además de tener otras características como ligereza de la herramienta, cubrir múltiples vectores de ataque y fácil de usar. Es este vacío el que el presente Trabajo Fin de Máster pretende cubrir con el desarrollo de la herramienta propuesta.

---

## 3. Diseño e Implementación del sistema

[PENDIENTE — Requiere código]

## 4. Pruebas y Validación

[PENDIENTE — Requiere código]

## 5. Conclusiones y trabajo futuro

### 5.1. Conclusiones
### 5.2. Líneas de Trabajo futuro

---

## Referencias

1. IBM. (2025). Cost of a Data Breach Report 2025. https://www.ibm.com/reports/data-breach
2. Halfond, W. G., Viegas, J., & Orso, A. (2006). A classification of SQL-injection attacks and countermeasures. In Proceedings of the IEEE International Symposium on Secure Software Engineering (Vol. 1, pp. 13-15).
3. Hydara, I., Sultan, A. B. M., Zulzalil, H., & Admodisastro, N. (2015). Current state of research on cross-site scripting (XSS)–A systematic literature review. Information and Software Technology, 58, 170-186.
4. OWASP Foundation. (2025). OWASP Top 10:2025. https://owasp.org/Top10/
5. Bau, J., Bursztein, E., Guber, D., & Mitchell, J. (2010). State of the art: Automated black-box web application vulnerability testing. In 2010 IEEE Symposium on Security and Privacy (pp. 332-345). IEEE.
6. Doupé, A., Cova, M., & Vigna, G. (2010). Why Johnny can't pentest: An analysis of black-box web vulnerability scanners. In Proceedings of the 7th International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment (pp. 111-131). Springer.
7. Makino, Y., & Klyuev, V. (2015). Evaluation of web vulnerability scanners. In 2015 IEEE 8th International Conference on Intelligent Data Acquisition and Advanced Computing Systems: Technology and Applications (IDAACS) (pp. 399-402). IEEE.
8. Tremante, M., Zejnilovic, S., & Newcomb, C. (2024). Application Security Report: 2024 Update. Cloudflare. https://blog.cloudflare.com/application-security-report-2024-update/
9. Verizon. (2025). 2025 Data Breach Investigations Report (DBIR). https://www.verizon.com/business/resources/reports/dbir/
10. Stuttard, D., & Pinto, M. (2011). The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws (2nd ed.). Wiley.
11. Gupta, S., & Gupta, B. B. (2017). Cross-Site Scripting (XSS) attacks, defensive mechanisms, and a comprehensive, real-world, novel defence mechanism. Expert Systems with Applications, 87, 52-74.
12. Shar, L. K., & Tan, H. B. K. (2013). Defeating SQL injection. Computer, 46(3), 69-77.
13. Clarke, J. (2012). SQL Injection Attacks and Defense (2nd ed.). Syngress/Elsevier.
14. Kettle, J. (2015). Server-Side Template Injection. PortSwigger Research. Disponible en: https://portswigger.net/research/server-side-template-injection
15. OWASP Foundation. (2020). OWASP Web Security Testing Guide (WSTG) v4.2. https://owasp.org/www-project-web-security-testing-guide/
16. Alonso, J. M., Bordon, R., Beltrán, M., & Guzmán, A. (2008). LDAP injection techniques. In 2008 11th IEEE Singapore International Conference on Communication Systems (pp. 1273-1277). IEEE.
17. Stasinopoulos, A., Ntantogian, C., & Xenakis, C. (2019). Commix: automating evaluation and exploitation of command injection vulnerabilities in web applications. International Journal of Information Security, 18(1), 49-72.
18. Ron, A., Shulman-Peleg, A., & Puzanov, A. (2015). Analysis and mitigation of NoSQL injections. IEEE Security & Privacy, 14(2), 30-39.
19. Sadeghian, A., Zamani, M., & Manaf, A. A. (2013). A taxonomy of SQL injection detection and prevention techniques. In 2013 International Conference on Informatics and Creative Multimedia (pp. 53-56). IEEE.
20. Sullivan, B., & Liu, V. (2011). Web Application Security: A Beginner's Guide. McGraw-Hill Education.
21. Barth, A., Jackson, C., & Mitchell, J. C. (2008). Robust defenses for cross-site request forgery. In Proceedings of the 15th ACM Conference on Computer and Communications Security (pp. 75-88). ACM.
22. OWASP Foundation. (2021). Unvalidated Redirects and Forwards Cheat Sheet. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
23. OWASP Foundation. (2021). Testing for Business Logic. OWASP Testing Guide. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
24. Sullo, C. (2025). Nikto Web Server Scanner (v2.6). Hack LLC. https://cirt.net/Nikto2
25. Stampar, M., & Damele, B. A. (2019). sqlmap: Automatic SQL injection and database takeover tool. Disponible en: https://sqlmap.org/
