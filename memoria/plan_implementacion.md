# TFM — Plan de 10 días (18-28 Abril 2026)

## Estado actual (18 Abril — actualizado)
- **Cap 1-2:** COMPLETADOS (referencias corregidas, datos 2025 actualizados)
- **Código:** COMPLETO — herramienta Gung12 funcional con 12 tipos de vulnerabilidad
- **Renombrado:** FormVuln → Gung12 (Gungnir + 12 vulnerabilidades)
- **Reportes:** Se guardan automáticamente en `reportes/`
- **Pylance:** Error en ai_analyzer.py corregido (API REST directa, sin dependencia google-generativeai)
- **Pruebas DVWA:** XSS, SQLi, CMDi verificados en nivel LOW y MEDIUM
- **Pendiente:** Cap 3-4-5, pruebas adicionales, revisión final

---

## DÍA 1 (18 Abr) — Setup entorno + Testing inicial ✅ COMPLETADO
- [x] Crear estructura proyecto Python
- [x] Implementar todos los módulos (parser, engine, analyzer, reporter, CLI)
- [x] Implementar 12 tipos de payloads
- [x] Implementar módulo IA opcional (Gemini/Groq)
- [x] Instalar Docker Desktop
- [x] Levantar DVWA (`docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa`)
- [x] Configurar DVWA: security LOW, crear DB
- [x] Pruebas reales: XSS, SQLi, CMDi contra DVWA LOW
- [x] Renombrar herramienta a Gung12
- [x] Corregir referencias Cap 1-2 (IBM 2025, Cloudflare, DBIR 2025, WSTG, Nikto)
- [x] Pruebas DVWA MEDIUM: XSS (evasión <script>), SQLi (POST), CMDi (| pipe)
- [x] Configurar reportes en carpeta `reportes/`

## DÍA 2 (19 Abr) — Testing completo + Cap 3
- [ ] Probar todos los tipos restantes contra DVWA medium
- [ ] Probar DVWA HIGH para documentar limitaciones
- [ ] Instalar bWAPP para SSTI, LDAP, NoSQL, XXE
- [ ] Probar modo --ai con Groq/Gemini
- [ ] Generar informes finales de ejemplo
- [ ] Capturas de pantalla para Cap. 3 y 4
- [ ] Redactar Cap. 3 (Diseño e Implementación)

## DÍA 3 (20 Abr) — Cap 3 + Cap 4
- [ ] Finalizar Cap. 3 con diagramas y fragmentos de código
- [ ] Redactar Cap. 4 (Pruebas y Validación)
- [ ] Documentar resultados LOW vs MEDIUM vs HIGH

## DÍA 4 (21 Abr) — Cap 4 + Cap 5
- [ ] Completar Cap. 4 con tablas de resultados
- [ ] Redactar Cap. 5 (Conclusiones y trabajo futuro)
- [ ] Redactar sección 1.3 (Metodología)

## DÍA 5 (22 Abr) — Resúmenes + Anexos
- [ ] Resumen (español), Resum (valenciano), Abstract (inglés)
- [ ] Motivación, justificación, agradecimientos
- [ ] Anexo A: Manual de instalación y uso
- [ ] Anexo B: Listado de payloads
- [ ] Anexo C: Ejemplos de informes generados

## DÍA 6 (23 Abr) — Revisión completa
- [ ] Lectura completa de toda la memoria
- [ ] Verificar coherencia entre capítulos
- [ ] Corregir erratas y formato
- [ ] Verificar figuras, tablas y referencias
- [ ] Formato plantilla UA

## DÍA 7 (24 Abr) — Entrega
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
python -m gung12 -u "http://localhost/vulnerabilities/xss_r/" --test --cookie "PHPSESSID=xxx;security=low"

# Escaneo XSS + SQLi
python -m gung12 -u "http://localhost/vulnerabilities/xss_r/" -T xss,sqli --cookie "PHPSESSID=xxx;security=low" -o report.html

# Escaneo completo modo exhaustivo
python -m gung12 -u "http://localhost/vulnerabilities/sqli/" -T all -F --cookie "PHPSESSID=xxx;security=low" -o informe_sqli.html

# Con IA (Gemini)
python -m gung12 -u "..." -T all --ai --ai-key "AIzaSy..." -o report.html

# Con IA (Groq)
python -m gung12 -u "..." -T all --ai --ai-provider groq --ai-key "gsk_..." -o report.html
```

## API Keys — Dónde conseguirlas

| Proveedor | URL | Variable de entorno |
|-----------|-----|-------------------|
| Gemini | https://aistudio.google.com/apikey | GEMINI_API_KEY |
| Groq | https://console.groq.com/keys | GROQ_API_KEY |
| Grok (xAI) | https://console.x.ai/ | OPENAI_API_KEY + OPENAI_BASE_URL |

Las keys NO van en el código. Van como argumento `--ai-key` o como variable de entorno.

## Resultados de pruebas (18 Abr)

| Test | DVWA LOW | DVWA MEDIUM |
|------|----------|-------------|
| XSS | `<script>alert("XSS")</script>` | `<img src=x onerror=alert("XSS")>` (evasión) |
| SQLi | `' OR '1'='1` (GET) | `' OR '1'='1` (POST, error SQL) |
| CMDi | `; whoami` | `\| whoami` (evasión de filtro `;`) |
| CSRF | No detectado (GET correcto) | — |
| LFI (DVWA) | Sin formulario HTML | — |
