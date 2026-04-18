# TFM — Plan de 10 días (18-28 Abril 2026)

## Estado actual (18 Abril)
- **Cap 1-2:** COMPLETADOS
- **Código:** COMPLETO — herramienta funcional con 12 tipos de vulnerabilidad
- **Pendiente:** Docker/DVWA, testing, Cap 3-4-5, revisión final

---

## DÍA 1 (18 Abr) — Setup entorno ✅ EN CURSO
- [x] Crear estructura proyecto Python
- [x] Implementar todos los módulos (parser, engine, analyzer, reporter, CLI)
- [x] Implementar 12 tipos de payloads
- [x] Implementar módulo IA opcional (Gemini/Groq)
- [x] Instalar Docker Desktop
- [x] Levantar DVWA (`docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa`)
- [x] Configurar DVWA: security LOW, crear DB
- [x] Primera prueba real: `python -m formvuln -u "http://localhost/vulnerabilities/xss_r/" --test --cookie "..."`

## DÍA 2 (19 Abr) — Testing XSS + SQLi + Command Injection
- [ ] Probar XSS contra DVWA `/vulnerabilities/xss_r/`
- [ ] Probar SQLi contra DVWA `/vulnerabilities/sqli/`
- [ ] Probar Command Injection contra DVWA `/vulnerabilities/exec/`
- [ ] Ajustar heurísticas del analyzer si hay falsos positivos/negativos
- [ ] Generar informes de ejemplo (JSON + HTML)
- [ ] Capturas de pantalla para Cap. 4

## DÍA 3 (20 Abr) — Testing LFI + CSRF + resto de vulnerabilidades
- [ ] Probar LFI contra DVWA `/vulnerabilities/fi/`
- [ ] Probar CSRF contra DVWA `/vulnerabilities/csrf/`
- [ ] Instalar bWAPP (`docker run -d -p 8080:80 raesene/bwapp`)
- [ ] Probar SSTI, LDAP, NoSQL, XXE contra bWAPP
- [ ] Probar errores lógicos y Open Redirect
- [ ] Documentar todos los resultados con capturas

## DÍA 4 (21 Abr) — Prueba con IA + ajustes finales código
- [ ] Obtener API key de Gemini (https://aistudio.google.com/apikey)
- [ ] Probar modo `--ai` con resultados reales
- [ ] Ajustar prompts de IA si es necesario
- [ ] Corregir bugs encontrados durante testing
- [ ] Generar informes finales de ejemplo para los Anexos

## DÍA 5 (22 Abr) — Redactar Cap. 3 (Diseño e Implementación)
- [ ] 3.1 Arquitectura general (diagrama de flujo)
- [ ] 3.2 Entorno de desarrollo y tecnologías
- [ ] 3.3 Metodología técnica
- [ ] 3.4 Módulo Parser
- [ ] 3.5 Módulo Motor de payloads (con fragmentos de código)
- [ ] 3.6 Módulo Analizador
- [ ] 3.7 Módulo Generador de informes
- [ ] 3.8 Módulo IA opcional
- [ ] 3.9 Integración CLI

## DÍA 6 (23 Abr) — Redactar Cap. 4 (Pruebas y Validación)
- [ ] 4.1 Entorno de pruebas (DVWA, bWAPP)
- [ ] 4.2 Pruebas por tipo de vulnerabilidad (con capturas)
- [ ] 4.3 Análisis de falsos positivos/negativos
- [ ] 4.4 Comparativa con OWASP ZAP (opcional)
- [ ] 4.5 Resumen de resultados (tabla)

## DÍA 7 (24 Abr) — Redactar Cap. 5 + Cap. 1.3 + Resúmenes
- [ ] 5.1 Conclusiones
- [ ] 5.2 Líneas futuras de trabajo
- [ ] 1.3 Metodología (ahora que el código está hecho)
- [ ] Resumen (español), Resum (valenciano), Abstract (inglés)
- [ ] Motivación, justificación, agradecimientos

## DÍA 8 (25 Abr) — Anexos + Referencias
- [ ] Anexo A: Manual de instalación y uso
- [ ] Anexo B: Listado completo de payloads
- [ ] Anexo C: Ejemplos de informes generados
- [ ] Anexo D: Enlace a repositorio GitHub
- [ ] Verificar todas las referencias bibliográficas [1]-[25+]
- [ ] Índice de figuras y tablas

## DÍA 9 (26 Abr) — Revisión completa
- [ ] Lectura completa de toda la memoria
- [ ] Verificar coherencia entre capítulos
- [ ] Corregir erratas y formato
- [ ] Verificar que todas las figuras tienen nombre y referencia
- [ ] Verificar notas al pie
- [ ] Formato plantilla UA

## DÍA 10 (27 Abr) — Entrega
- [ ] Última revisión
- [ ] Exportar PDF final
- [ ] Subir código a GitHub (público)
- [ ] Entregar memoria

---

## Comandos de referencia rápida

```bash
# Activar entorno virtual
cd C:\Users\denge\Documents\TFM
.\venv\Scripts\activate

# Docker DVWA
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# Docker bWAPP
docker run -d -p 8080:80 --name bwapp raesene/bwapp

# Test rápido (solo parser)
python -m formvuln -u "http://localhost/vulnerabilities/xss_r/" --test --cookie "PHPSESSID=xxx;security=low"

# Escaneo XSS + SQLi
python -m formvuln -u "http://localhost/vulnerabilities/xss_r/" -T xss,sqli --cookie "PHPSESSID=xxx;security=low" -o report.html

# Escaneo completo modo exhaustivo
python -m formvuln -u "http://localhost/vulnerabilities/sqli/" -T all -F --cookie "PHPSESSID=xxx;security=low" -o informe_sqli.html

# Con IA (Gemini)
python -m formvuln -u "..." -T all --ai --ai-key "AIzaSy..." -o report.html

# Con IA (Groq)
python -m formvuln -u "..." -T all --ai --ai-provider groq --ai-key "gsk_..." -o report.html
```

## API Keys — Dónde conseguirlas

| Proveedor | URL | Variable de entorno |
|-----------|-----|-------------------|
| Gemini | https://aistudio.google.com/apikey | GEMINI_API_KEY |
| Groq | https://console.groq.com/keys | GROQ_API_KEY |
| Grok (xAI) | https://console.x.ai/ | OPENAI_API_KEY + OPENAI_BASE_URL |

Las keys NO van en el código. Van como argumento `--ai-key` o como variable de entorno.
