"""Interfaz de línea de comandos (CLI) para Gung12."""

import os
import sys
import json
import click
from typing import Optional

from gung12 import __version__
from gung12.models import VulnType, Severity
from gung12.parser import FormParser
from gung12.engine import ScanEngine
from gung12.reporter import ReportGenerator


# Todos los tipos de vulnerabilidad disponibles
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
            click.echo(f"  Tipo desconocido: '{t}'. Tipos validos: {', '.join(VULN_TYPE_MAP.keys())}", err=True)
    return types if types else ALL_VULN_TYPES


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
              help="Proveedor de IA: gemini, groq, openai")
@click.option("--ai-key", default=None,
              help="API key del proveedor de IA (o variable de entorno)")
@click.version_option(version=__version__)
def main(url: str, tests: str, full: bool, output: Optional[str],
         cookie: Optional[str], test_only: bool, form_index: int,
         timeout: int, use_spa: bool, use_ai: bool, ai_provider: str,
         ai_key: Optional[str]):
    """Gung12 - Detector de vulnerabilidades en formularios web.

    Analiza un formulario web específico mediante inyección de payloads
    para detectar 12 tipos de vulnerabilidades.

    Ejemplo: python -m gung12 -u "http://localhost/vuln/xss/" -T xss,sqli -o report.html
    """
    # Banner
    click.echo(click.style("\n Gung12 v" + __version__ + " - Detector de Vulnerabilidades en Formularios Web", fg="cyan", bold=True))
    click.echo(click.style(" Solo para uso autorizado en entornos de prueba\n", fg="yellow"))

    # Parsear cookies
    cookies = parse_cookies(cookie) if cookie else None

    # 1. Parsear formulario
    click.echo(f"[*] Analizando formulario en: {url}")
    if use_spa:
        click.echo(click.style("[*] Modo SPA: usando Playwright para renderizar JavaScript", fg="cyan"))
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
    except Exception as e:
        click.echo(click.style(f"[ERROR] No se pudo acceder a la URL: {e}", fg="red"))
        sys.exit(1)

    if not forms:
        click.echo(click.style("[ERROR] No se encontraron formularios en la URL", fg="red"))
        sys.exit(1)

    if form_index >= len(forms):
        click.echo(click.style(f"[ERROR] Índice {form_index} fuera de rango. Formularios encontrados: {len(forms)}", fg="red"))
        sys.exit(1)

    form = forms[form_index]
    click.echo(f"[+] Formulario encontrado: {form.method} -> {form.action}")
    click.echo(f"    Campos: {', '.join(f.name for f in form.fields)}")
    click.echo(f"    Campos inyectables: {', '.join(f.name for f in form.injectable_fields)}")
    click.echo(f"    Token CSRF: {'Si' if form.has_csrf_token else 'No'}")

    if not form.injectable_fields:
        click.echo(click.style("[!] No hay campos inyectables", fg="yellow"))
        sys.exit(0)

    # 2. Determinar tipos de pruebas
    test_types = parse_test_types(tests)
    mode = "FULL" if full else "QUICK"
    click.echo(f"\n[*] Modo: {mode}")
    click.echo(f"[*] Pruebas: {', '.join(t.value for t in test_types)}")
    click.echo()

    # 3. Ejecutar escaneo
    engine = ScanEngine(cookies=cookies, timeout=timeout, verbose=True, use_spa=use_spa)

    def progress_callback(msg):
        click.echo(f"    {msg}")

    scan_result = engine.scan(
        form=form,
        test_types=test_types,
        full_mode=full,
        callback=progress_callback,
    )

    # 4. Análisis con IA (opcional)
    if use_ai and scan_result.vulnerabilities:
        click.echo(f"\n[*] Ejecutando análisis con IA ({ai_provider})...")
        try:
            from gung12.ai_analyzer import AIAnalyzer
            ai = AIAnalyzer(provider=ai_provider, api_key=ai_key)
            ai_result = ai.analyze_results(scan_result)
            scan_result.ai_analysis = ai_result
            click.echo(click.style("[+] Análisis con IA completado", fg="green"))
        except Exception as e:
            click.echo(click.style(f"[!] Error en análisis IA: {e}", fg="yellow"))

    # 5. Mostrar resumen
    click.echo(click.style(f"\n{'='*60}", fg="cyan"))
    click.echo(click.style(" RESUMEN DEL ESCANEO", fg="cyan", bold=True))
    click.echo(click.style(f"{'='*60}", fg="cyan"))
    click.echo(f" URL:        {scan_result.url}")
    click.echo(f" Modo:       {scan_result.scan_mode}")
    click.echo(f" Duracion:   {scan_result.duration_seconds}s")
    click.echo(f" Peticiones: {scan_result.total_requests}")
    click.echo()

    if scan_result.vulnerabilities:
        click.echo(click.style(f" VULNERABILIDADES ENCONTRADAS: {len(scan_result.vulnerabilities)}", fg="red", bold=True))
        for v in sorted(scan_result.vulnerabilities,
                        key=lambda x: list(Severity).index(x.severity)):
            severity_colors = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "green",
                Severity.INFO: "blue",
            }
            color = severity_colors.get(v.severity, "white")
            click.echo(f"  {click.style(f'[{v.severity.value}]', fg=color)} "
                        f"{v.vuln_type.value.upper()} en '{v.field_name}': {v.description}")
    else:
        click.echo(click.style(" No se detectaron vulnerabilidades.", fg="green"))

    click.echo()

    # 6. Generar informe
    if output:
        # Si la ruta no tiene directorio, guardar en reportes/
        if os.path.dirname(output) == "":
            reportes_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reportes")
            os.makedirs(reportes_dir, exist_ok=True)
            output = os.path.join(reportes_dir, output)
        reporter = ReportGenerator()
        reporter.generate(scan_result, output)
        click.echo(click.style(f"[+] Informe generado: {output}", fg="green"))

    click.echo()


if __name__ == "__main__":
    main()
