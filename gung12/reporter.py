"""Módulo 4: Generador de informes.

Genera informes en formato JSON y HTML con los resultados del escaneo.
"""

import json
from datetime import datetime
from typing import Optional

from gung12.models import ScanResult, Severity


class ReportGenerator:
    """Genera informes de resultados de escaneo."""

    def generate_json(self, result: ScanResult, output_path: str):
        """Genera informe en formato JSON."""
        data = result.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def generate_html(self, result: ScanResult, output_path: str):
        """Genera informe en formato HTML."""
        html = self._build_html(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def generate(self, result: ScanResult, output_path: str):
        """Auto-detecta formato por extensión y genera el informe."""
        if output_path.endswith(".json"):
            self.generate_json(result, output_path)
        elif output_path.endswith(".html") or output_path.endswith(".htm"):
            self.generate_html(result, output_path)
        else:
            # Por defecto JSON
            self.generate_json(result, output_path)

    def _severity_color(self, severity: Severity) -> str:
        colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#28a745",
            Severity.INFO: "#17a2b8",
        }
        return colors.get(severity, "#6c757d")

    def _severity_badge(self, severity: Severity) -> str:
        color = self._severity_color(severity)
        return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.85em;font-weight:bold">{severity.value}</span>'

    def _build_html(self, result: ScanResult) -> str:
        """Construye el HTML del informe."""
        vuln_rows = ""
        for v in sorted(result.vulnerabilities,
                        key=lambda x: list(Severity).index(x.severity)):
            evidence_escaped = (v.evidence
                                .replace("&", "&amp;")
                                .replace("<", "&lt;")
                                .replace(">", "&gt;"))
            payload_escaped = (v.payload
                               .replace("&", "&amp;")
                               .replace("<", "&lt;")
                               .replace(">", "&gt;"))
            vuln_rows += f"""
            <tr>
                <td>{self._severity_badge(v.severity)}</td>
                <td><strong>{v.vuln_type.value.upper()}</strong></td>
                <td><code>{v.field_name}</code></td>
                <td>{v.description}</td>
                <td><code style="font-size:0.8em;word-break:break-all">{payload_escaped}</code></td>
                <td style="font-size:0.85em">{evidence_escaped[:300]}</td>
                <td>{v.confidence:.0%}</td>
            </tr>"""

        no_vulns_msg = ""
        if not result.vulnerabilities:
            no_vulns_msg = '<p style="color:#28a745;font-size:1.2em;text-align:center;padding:2em">No se detectaron vulnerabilidades.</p>'

        summary = result.to_dict()["summary"]

        ai_section = ""
        if result.ai_analysis:
            ai_escaped = (result.ai_analysis
                          .replace("&", "&amp;")
                          .replace("<", "&lt;")
                          .replace(">", "&gt;")
                          .replace("\n", "<br>"))
            ai_section = f"""
            <div style="margin-top:2em;padding:1.5em;background:#f0f4ff;border:1px solid #b3c7ff;border-radius:8px">
                <h2 style="color:#2c5aa0;margin-top:0">Analisis con IA</h2>
                <p>{ai_escaped}</p>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gung12 - Informe de Seguridad</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2em; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e);
                   color: white; padding: 2em; border-radius: 8px; margin-bottom: 2em; }}
        .header h1 {{ font-size: 1.8em; margin-bottom: 0.5em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                  gap: 1em; margin: 1.5em 0; }}
        .stat {{ background: white; padding: 1em; border-radius: 8px; text-align: center;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        .stat .label {{ font-size: 0.85em; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; font-size: 0.9em; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 0.9em; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        .meta {{ color: rgba(255,255,255,0.8); font-size: 0.9em; }}
        .footer {{ text-align: center; margin-top: 2em; color: #999; font-size: 0.85em; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Gung12 - Informe de Seguridad</h1>
        <div class="meta">
            <p><strong>URL:</strong> {result.url}</p>
            <p><strong>Fecha:</strong> {result.timestamp}</p>
            <p><strong>Modo:</strong> {result.scan_mode} | <strong>Peticiones:</strong> {result.total_requests} | <strong>Duracion:</strong> {result.duration_seconds}s</p>
            <p><strong>Metodo:</strong> {result.form.method} | <strong>Action:</strong> {result.form.action}</p>
            <p><strong>Campos analizados:</strong> {', '.join(f.name for f in result.form.injectable_fields)}</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="number" style="color:#dc3545">{summary['critical']}</div>
            <div class="label">CRITICAS</div>
        </div>
        <div class="stat">
            <div class="number" style="color:#fd7e14">{summary['high']}</div>
            <div class="label">ALTAS</div>
        </div>
        <div class="stat">
            <div class="number" style="color:#ffc107">{summary['medium']}</div>
            <div class="label">MEDIAS</div>
        </div>
        <div class="stat">
            <div class="number" style="color:#28a745">{summary['low']}</div>
            <div class="label">BAJAS</div>
        </div>
        <div class="stat">
            <div class="number">{summary['total_vulnerabilities']}</div>
            <div class="label">TOTAL</div>
        </div>
    </div>

    {no_vulns_msg}

    {"<table><thead><tr><th>Severidad</th><th>Tipo</th><th>Campo</th><th>Descripcion</th><th>Payload</th><th>Evidencia</th><th>Confianza</th></tr></thead><tbody>" + vuln_rows + "</tbody></table>" if result.vulnerabilities else ""}

    {ai_section}

    <div class="footer">
        <p>Generado por Gung12 v1.0.0 — Solo para uso autorizado en entornos de prueba</p>
        <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</div>
</body>
</html>"""
