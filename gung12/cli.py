"""Interfaz de línea de comandos (CLI) para Gung12."""

import os
import sys
import json
import time
import click
from typing import Optional

from gung12 import __version__
from gung12.models import VulnType
from gung12.parser import FormParser
from gung12.engine import ScanEngine
from gung12.reporter import ReportGenerator


ALL_VULN_TYPES = [v for v in VulnType]
VULN_TYPE_MAP = {v.value: v for v in VulnType}


def parse_cookies(cookie_string: str) -> dict:
    """Parsea string de cookies 'key=val;key2=val2' a dict."""
    cookies = {}
    if not cookie_string:
        return cookies
    for pair in cookie_string.split(";"):
        pair = pair.strip()
        if "=" in pair:
            key, val = pair.split("=", 1)
            cookies[key.strip()] = val.strip()
    return cookies


def parse_test_types(test_string: str) -> list:
    """Parsea string de tipos 'xss,sqli,ssti' a lista de VulnType."""
    if not test_string or test_string.lower() == "all":
        return ALL_VULN_TYPES

    types = []
    for t in test_string.split(","):
        t = t.strip().lower()
        if t in VULN_TYPE_MAP:
            types.append(VULN_TYPE_MAP[t])
        else:
            click.echo(f"[!] Tipo desconocido: '{t}'", err=True)
    return types if types else ALL_VULN_TYPES


def severity_of(confidence: float) -> tuple:
    """Mapea confianza numérica a (etiqueta, color) para mostrar en CLI."""
    if confidence >= 0.85:
        return ("ALTA", "red")
    if confidence >= 0.65:
        return ("MEDIA", "yellow")
    return ("BAJA", "blue")


# Banner ASCII al estilo clásico (sqlmap / nmap / nikto)
BANNER = r"""
   _____                  _ ___
  / ____|                | |__ \
 | |  __ _   _ _ __   __ _   ) |
 | | |_ | | | | '_ \ / _` | / /
 | |__| | |_| | | | | (_| |/ /_
  \_____|\__,_|_| |_|\__, |____|
                      __/ |
                     |___/   v{version}
"""


@click.command()
@click.option("-u", "--url", required=True, help="URL del formulario a analizar")
@click.option("-T", "--tests", default="all",
              help="Tipos de pruebas separados por coma (xss,sqli,ssti,xpath,cmdi,nosql,xxe,csrf,file_upload,redirect,htmli,logic)")
@click.option("-F", "--full", is_flag=True, default=False,
              help="Modo exhaustivo (más payloads)")
@click.option("-o", "--output", default=None,
              help="Archivo de salida (.json o .html)")
@click.option("--cookie", default=None,
              help="Cookies de sesión (formato: 'key=val;key2=val2')")
@click.option("--test", "test_only", is_flag=True, default=False,
              help="Solo verificar que el formulario es parseable")
@click.option("--form-index", default=0, type=int,
              help="Índice del formulario a analizar (si hay varios)")
@click.option("--timeout", default=10, type=int,
              help="Timeout de conexión en segundos")
@click.option("--spa", "use_spa", is_flag=True, default=False,
              help="Usar Playwright para renderizar SPAs (requiere: pip install playwright && playwright install chromium)")
@click.option("--ai", "use_ai", is_flag=True, default=False,
              help="Usar IA para análisis avanzado de resultados")
@click.option("--ai-provider", default="gemini",
              help="Proveedor de IA: gemini, groq")
@click.option("--ai-key", default=None,
              help="API key del proveedor de IA (o variable de entorno)")
@click.option("--waf-bypass", "waf_bypass", is_flag=True, default=False,
              help="Activar técnicas de evasión WAF (URL encoding, case variation, null bytes)")
@click.option("--login-url", default=None,
              help="URL del formulario de login para autenticación previa automática")
@click.option("--login-user", default=None,
              help="Usuario para autenticación previa (usar con --login-url)")
@click.option("--login-pass", default=None,
              help="Contraseña para autenticación previa (usar con --login-url)")
@click.option("-q", "--quiet", is_flag=True, default=False,
              help="Modo silencioso: solo muestra hallazgos y el resumen final")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Modo verboso: muestra cada payload probado y el progreso por tipo")
@click.option("--no-banner", is_flag=True, default=False,
              help="No mostrar el banner ASCII inicial")
@click.version_option(version=__version__)
def main(url: str, tests: str, full: bool, output: Optional[str],
         cookie: Optional[str], test_only: bool, form_index: int,
         timeout: int, use_spa: bool, use_ai: bool, ai_provider: str,
         ai_key: Optional[str], waf_bypass: bool,
         login_url: Optional[str], login_user: Optional[str], login_pass: Optional[str],
         quiet: bool, verbose: bool, no_banner: bool):
    """Gung12 - Detector de vulnerabilidades en formularios web.

    Analiza un formulario web específico mediante inyección de payloads
    para detectar 12 tipos de vulnerabilidades.

    Ejemplo: python -m gung12 -u "http://localhost/vuln/xss/" -T xss,sqli -o report.html

    Uso autorizado únicamente en entornos de prueba o sistemas propios.
    """
    # ---- Configuración del nivel de detalle ----
    def info(msg, **style):
        """Mensaje informativo: oculto en modo --quiet."""
        if not quiet:
            click.echo(click.style(msg, **style) if style else msg)

    def warn(msg):
        click.echo(click.style(msg, fg="yellow"))

    def err(msg):
        click.echo(click.style(msg, fg="red"), err=True)

    def ok(msg):
        info(msg, fg="green")

    # ---- Banner ----
    if not no_banner and not quiet:
        click.echo(click.style(BANNER.format(version=__version__), fg="cyan"))
        click.echo(click.style("    DAST para formularios web - uso autorizado únicamente",
                               fg="yellow"))
        click.echo(click.style(f"    {time.strftime('[*] Inicio: %H:%M:%S - %Y-%m-%d')}\n",
                               fg="white", dim=True))

    cookies = parse_cookies(cookie) if cookie else None

    # User-Agent realista por defecto (Firefox) — evita delatar al scanner
    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    )

    # ---- 0. Autenticación previa (--login-url) ----
    if login_url:
        if not login_user or not login_pass:
            err("[ERROR] --login-url requiere también --login-user y --login-pass")
            sys.exit(2)
        info(f"[*] Autenticando en {login_url}")
        try:
            from gung12.auth import perform_login
            import requests as _req
            pre_auth = _req.Session()
            pre_auth.headers.update({"User-Agent": DEFAULT_UA})
            if cookies:
                pre_auth.cookies.update(cookies)
            success = perform_login(login_url, login_user, login_pass,
                                    pre_auth, timeout=timeout)
            if success:
                ok(f"[+] Login OK como '{login_user}'")
                merged: dict = {}
                for c in pre_auth.cookies:
                    merged[c.name] = c.value
                cookies = merged
            else:
                warn("[!] Login no confirmado - credenciales incorrectas o backend desconocido")
        except Exception as e:
            err(f"[ERROR] Autenticación previa fallida: {e}")
            sys.exit(2)

    if waf_bypass:
        info("[*] WAF bypass activado")
    if use_spa:
        info("[*] Modo SPA: renderizando con Playwright")

    # ---- 1. Parsing del formulario ----
    info(f"[*] Objetivo: {url}")
    if use_spa:
        from gung12.spa_parser import SPAFormParser
        parser = SPAFormParser(cookies=cookies, timeout=timeout)
    else:
        parser = FormParser(cookies=cookies, timeout=timeout)

    if test_only:
        result = parser.test_form(url)
        click.echo(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result["status"] == "ok" else 1)

    try:
        forms = parser.parse_forms(url)
    except RuntimeError as e:
        err(f"[ERROR] {e}")
        sys.exit(2)
    except Exception as e:
        err(f"[ERROR] No se pudo acceder a la URL: {e}")
        sys.exit(2)

    if not forms:
        err("[ERROR] No se encontraron formularios en la URL")
        if not use_spa:
            warn("[!] Si el sitio usa JavaScript o un framework SPA (Angular, React, Vue), "
                 "prueba a añadir la opción --spa para renderizarlo con Playwright.")
        sys.exit(2)

    if form_index >= len(forms):
        err(f"[ERROR] Índice {form_index} fuera de rango (formularios encontrados: {len(forms)})")
        sys.exit(2)

    form = forms[form_index]
    method_action = f"{form.method} -> {form.action}"
    fields_str = ", ".join(f.name for f in form.fields) or "(ninguno)"
    inj_str = ", ".join(f.name for f in form.injectable_fields) or "(ninguno)"
    csrf_str = "sí" if form.has_csrf_token else "no"

    ok(f"[+] Formulario: {method_action}")
    info(f"    Campos: {fields_str}")
    info(f"    Inyectables: {inj_str}  ·  CSRF: {csrf_str}")

    if not form.injectable_fields:
        warn("[!] No hay campos inyectables - escaneo abortado")
        sys.exit(0)

    # ---- 2. Tipos de prueba ----
    test_types = parse_test_types(tests)
    mode = "full" if full else "quick"
    info(f"[*] Modo {mode} · {len(test_types)} tipo(s) · {len(form.injectable_fields)} campo(s)")
    info("")

    # ---- 3. Ejecución del escaneo ----
    engine = ScanEngine(cookies=cookies, timeout=timeout, verbose=verbose,
                        use_spa=use_spa, waf_bypass=waf_bypass)

    def progress_callback(msg):
        # Las detecciones "[!] ..." emitidas por el engine en tiempo real se
        # suprimen porque el resumen final ya las agrupa por severidad.
        if "[!]" in msg:
            return
        # Los avisos de bloqueo se muestran siempre y de forma destacada.
        if "[BLOQUEO]" in msg:
            click.echo(click.style(msg.strip(), fg="red", bold=True))
            return
        # El progreso por tipo se muestra en modo normal y verbose (no en quiet),
        # para que en escaneos largos se vea que la herramienta sigue trabajando.
        if not quiet:
            click.echo(click.style(f"    {msg.strip()}", fg="white", dim=True))

    t0 = time.time()
    scan_result = engine.scan(
        form=form,
        test_types=test_types,
        full_mode=full,
        callback=progress_callback,
    )
    elapsed = time.time() - t0

    # ---- 3.b Bloqueo de WAF/anti-bot detectado ----
    if scan_result.blocked:
        click.echo()
        warn("[!] Escaneo detenido: la respuesta parece un bloqueo de WAF o anti-bot "
             "(por ejemplo, un desafío de Cloudflare).")
        warn("    Los resultados no serían fiables, así que no se reporta ningún hallazgo. "
             "Revisa el acceso al objetivo o prueba con otro entorno.")
        sys.exit(2)

    # ---- 4. Análisis IA (opcional) ----
    if use_ai and scan_result.vulnerabilities:
        info(f"\n[*] Análisis IA ({ai_provider})...")
        try:
            from gung12.ai_analyzer import AIAnalyzer
            ai = AIAnalyzer(provider=ai_provider, api_key=ai_key)
            ai_result = ai.analyze_results(scan_result)
            scan_result.ai_analysis = ai_result
            ok("[+] Análisis IA completado")
        except Exception as e:
            warn(f"[!] Error en análisis IA: {e}")

    # ---- 5. Resumen de hallazgos ----
    vulns = scan_result.vulnerabilities
    click.echo()
    click.echo(click.style("[*] " + "-" * 56, fg="cyan", dim=True))

    if vulns:
        # Agrupar por severidad
        groups: dict = {"ALTA": [], "MEDIA": [], "BAJA": []}
        for v in vulns:
            sev_label, _ = severity_of(v.confidence)
            groups[sev_label].append(v)

        total_h = sum(len(g) for g in groups.values())
        click.echo(click.style(f"[!] {total_h} hallazgo(s) en {elapsed:.1f}s", fg="red", bold=True))
        click.echo()

        for sev_label in ("ALTA", "MEDIA", "BAJA"):
            for v in groups[sev_label]:
                _, sev_color = severity_of(v.confidence)
                tag = click.style(f"[{sev_label}]", fg=sev_color, bold=True)
                vtype = click.style(v.vuln_type.value.upper(), fg=sev_color)
                artifact = click.style("  [reflexión?]", fg="yellow") if v.reflection_artifact else ""
                click.echo(f"  {tag} {vtype} en '{v.field_name}'{artifact}")
                click.echo(click.style(f"        {v.description}", fg="white"))
                if v.payload and v.payload != "N/A - análisis estático":
                    payload_short = v.payload[:80] + ("..." if len(v.payload) > 80 else "")
                    click.echo(click.style(f"        Payload: {payload_short}", fg="white", dim=True))
                click.echo(click.style(
                    f"        Petición: {form.method} {form.action}  ·  campo: {v.field_name}",
                    fg="white", dim=True))
                click.echo()

        # Línea de conteo por severidad
        summary = " · ".join([
            click.style(f"{len(groups['ALTA'])} alta", fg="red", bold=True),
            click.style(f"{len(groups['MEDIA'])} media", fg="yellow"),
            click.style(f"{len(groups['BAJA'])} baja", fg="blue"),
        ])
        click.echo(f"[*] Resumen: {summary}")
    else:
        ok(f"[+] Sin hallazgos en {elapsed:.1f}s")

    # ---- 6. Generación del informe ----
    if output:
        if os.path.dirname(output) == "":
            reportes_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "reportes",
            )
            os.makedirs(reportes_dir, exist_ok=True)
            output = os.path.join(reportes_dir, output)
        reporter = ReportGenerator()
        reporter.generate(scan_result, output)
        ok(f"[+] Informe: {output}")

    click.echo()

    # ---- 7. Exit code para CI/CD ----
    # 0 = sin hallazgos
    # 1 = hay hallazgos de severidad ALTA o MEDIA
    # 2 = error de ejecución (URL inaccesible, etc.) — ya gestionado arriba con sys.exit(2)
    if vulns:
        has_high_or_medium = any(v.confidence >= 0.65 for v in vulns)
        sys.exit(1 if has_high_or_medium else 0)
    sys.exit(0)


if __name__ == "__main__":
    main()
