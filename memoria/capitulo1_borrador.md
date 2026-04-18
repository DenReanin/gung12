# Capítulo 1. Introducción

En esta sección introductoria, se explicará la contextualización y justificación del proyecto, destacando los desafíos actuales en la seguridad de aplicaciones web. Adicionalmente se establecerán los objetivos generales y específicos a los cuales se quiere llegar. Finalizando con la muestra de la metodología llevada a cabo para abordar el TFM.



## 1.1. Contextualización y justificación

En la actualidad, las aplicaciones web son una parte fundamental de cualquier negocio, siendo clave para cualquier infraestructura digital. Estas son utilizadas ampliamente en todos los sectores, desde la banca y el comercio electrónico hasta la sanidad y la administración pública.

Esta relevancia las convierte en uno de los activos más codiciados y atractivos para los atacantes. Según el informe de IBM Security, el coste medio de una brecha de datos fue de 4,44 millones de dólares en 2025, tras haber alcanzado los 4,88 millones en 2024, siendo las aplicaciones web uno de los vectores de ataque más frecuentes [1].

Dentro de las aplicaciones web, los formularios representan uno de los puntos de entrada más críticos. A través de ellos, los usuarios proporcionan datos que el servidor procesa directamente: credenciales, consultas, archivos y parámetros de configuración. Cuando estos datos no se validan ni se sanean adecuadamente, pueden explotarse para ejecutar ataques de inyección, manipulación de datos o acceso no autorizado.

Las vulnerabilidades asociadas a formularios web abarcan una gran variedad de categorías, entre las que destacan la inyección SQL (SQLi), el Cross-Site Scripting (XSS), la inclusión de archivos locales (LFI) o la inyección de comandos del sistema operativo, entre otras [2] [3].

El proyecto OWASP¹ (Open Web Application Security Project), es actualmente un referente internacional en seguridad de aplicaciones, el cual publica periódicamente una lista de la llamada "Top 10". Esta lista recoge las categorías de vulnerabilidades más críticas, en su edición de 2025 las inyecciones se posicionan en mitad de tabla (A05) [4].

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



## 1.2. Objetivos

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
  - Detectar comportamientos extraños del servidor al recibir los payloads.
- Generar informes estructurados en formatos JSON y HTML que recojan:
  - Los formularios analizados y su estructura.
  - Las pruebas realizadas por tipo de vulnerabilidad.
  - Los indicios detectados con su clasificación de severidad.
- Validar la herramienta contra entornos de prueba.



## 1.3. Metodología del proyecto

Definición del alcance y objetivos principales → [Revisión de la literatura] → [Implementación del proyecto] → [Pruebas] → Conclusión y trabajo futuro

[Explicación]

[Esquema Imagen]



---

## Referencias del Capítulo 1

[1] IBM. (2025). Cost of a Data Breach Report 2025. https://www.ibm.com/reports/data-breach

[2] Halfond, W. G., Viegas, J., & Orso, A. (2006). A classification of SQL injection attacks and countermeasures.

[3] Hydara, I., Sultan, A. B. M., Zulzalil, H., & Admodisastro, N. (2015). Current state of research on cross-site scripting (XSS)–A systematic literature review. Information and Software Technology, 58, 170-186.

[4] OWASP Foundation. (2025). OWASP Top 10:2025. https://owasp.org/Top10/

[5] Bau, J., Bursztein, E., Gupta, D., & Mitchell, J. (2010). State of the art: Automated black-box web application vulnerability testing. In 2010 IEEE Symposium on Security and Privacy (pp. 332-345). IEEE.

[6] Doupé, A., Cova, M., & Vigna, G. (2010). Why Johnny can't pentest: An analysis of black-box web vulnerability scanners. In International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment (pp. 111-131). Springer Berlin Heidelberg.

[7] Makino, Y., & Klyuev, V. (2015). Evaluation of web vulnerability scanners. In 2015 IEEE 8th International Conference on Intelligent Data Acquisition and Advanced Computing Systems: Technology and Applications (IDAACS) (Vol. 1, pp. 399-402). IEEE.
