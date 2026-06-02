# Gung12

[![Release](https://img.shields.io/github/v/release/DenReanin/gung12)](https://github.com/DenReanin/gung12/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

DAST (Dynamic Application Security Testing) especializado en la detección de vulnerabilidades en **formularios web**. Cubre 12 categorías alineadas con el OWASP Top 10 con un enfoque dirigido y pensado para integración en flujos de CI/CD.

## Características

- 12 categorías de vulnerabilidad: XSS, SQLi, SSTI, XPath, CMDi, NoSQL, XXE, CSRF, File Upload, Open Redirect, HTML Injection, Logic
- Soporte para SPAs (Angular/React/Vue) mediante Playwright y descubrimiento automático de endpoints REST
- Análisis con IA (Gemini, Groq) como segunda opinión sobre los hallazgos
- Autenticación previa automática (`--login-url`)
- Evasión de WAFs basados en firmas (`--waf-bypass`)
- Filtro automático de falsos positivos por reflexión total
- Informes HTML y JSON con coloreado por severidad

## Instalación

### Desde código fuente

```bash
git clone https://github.com/DenReanin/gung12
cd gung12
pip install -r requirements.txt
python -m gung12 --help
```

> **Nota:** el modo `--spa` usa el navegador Chromium de Playwright. Gung12 lo **descarga automáticamente** la primera vez que se utiliza (~280 MB, en la caché del usuario). Si prefieres instalarlo a mano o la descarga automática falla (sin conexión o tras un proxy), ejecuta `playwright install chromium`.

### Ejecutable

Descargar desde [Releases](https://github.com/DenReanin/gung12/releases) el binario para tu plataforma (Windows, Linux o macOS) y ejecutarlo directamente. No requiere Python instalado.

El binario incluye Playwright. La primera vez que se utilice `--spa`, Playwright descargará Chromium en la caché del usuario (~280 MB).

## Uso básico

```bash
# Escaneo rápido con XSS y SQLi
gung12 -u "http://target/form" -T xss,sqli

# Escaneo completo con login previo
gung12 -u "http://target/admin/profile" \
       --login-url "http://target/login" \
       --login-user "admin" --login-pass "secret" \
       -T all -F -o report.html

# Modo SPA contra OWASP Juice Shop (Angular)
gung12 -u "http://localhost:3000/#/login" --spa -T sqli,nosql

# CI/CD: salida silenciosa con exit code útil
gung12 -u "$TARGET" -T all --quiet -o report.json
# exit 0 = sin hallazgos relevantes, 1 = ALTA/MEDIA, 2 = error
```

## Modos de salida

| Modo | Flag | Uso recomendado |
|---|---|---|
| Por defecto | (ninguno) | Defensa, demos, ejecuciones manuales |
| Silencioso | `-q` / `--quiet` | Pipelines CI/CD (solo hallazgos) |
| Verboso | `-v` / `--verbose` | Debugging y pentesting (muestra payloads) |

## Códigos de retorno (CI/CD)

| Código | Significado |
|---|---|
| 0 | Sin hallazgos o solo de severidad BAJA |
| 1 | Hallazgos de severidad ALTA o MEDIA |
| 2 | Error de ejecución (URL inaccesible, argumentos inválidos) |

## Aviso legal

Esta herramienta está diseñada para **uso autorizado únicamente** sobre sistemas propios o con permiso explícito por escrito del propietario. El uso contra sistemas no autorizados constituye un delito tipificado en el artículo 197 bis del Código Penal español y en la normativa europea sobre ciberseguridad.

## Licencia

MIT. Proyecto académico desarrollado como Trabajo Fin de Máster en el Máster Universitario en Ciberseguridad de la Universidad de Alicante.
