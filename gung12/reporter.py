
import json
import re
import html as _html
from datetime import datetime
from typing import Optional

from gung12 import __version__
from gung12.models import ScanResult


class ReportGenerator:

    def generate_json(self, result: ScanResult, output_path: str):
        data = result.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def generate_html(self, result: ScanResult, output_path: str):
        html = self._build_html(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def generate(self, result: ScanResult, output_path: str):
        if output_path.endswith(".json"):
            self.generate_json(result, output_path)
        elif output_path.endswith(".html") or output_path.endswith(".htm"):
            self.generate_html(result, output_path)
        else:
            self.generate_json(result, output_path)

    @staticmethod
    def _severity_for(confidence: float) -> str:
        if confidence >= 0.85:
            return "alta"
        if confidence >= 0.65:
            return "media"
        return "baja"

    def _build_html(self, result: ScanResult) -> str:
        vulns = result.vulnerabilities

        sev_counts = {"alta": 0, "media": 0, "baja": 0}
        for v in vulns:
            sev_counts[self._severity_for(v.confidence)] += 1

        sev_order = {"alta": 0, "media": 1, "baja": 2}
        sorted_vulns = sorted(vulns, key=lambda v: sev_order[self._severity_for(v.confidence)])

        cards = "\n".join(self._render_card(v, result.form) for v in sorted_vulns)

        blocked_notice = ""
        if getattr(result, "blocked", False):
            blocked_notice = (
                '<div class="blocked">'
                '<p><strong>Escaneo detenido.</strong> La respuesta parece un bloqueo de '
                'WAF o anti-bot (por ejemplo, un desafío de Cloudflare). Los resultados no '
                'serían fiables, por lo que no se reporta ningún hallazgo.</p>'
                '</div>'
            )

        empty_state = ""
        if not vulns and not blocked_notice:
            empty_state = (
                '<div class="empty">'
                '<p>Sin hallazgos. El formulario no presenta indicios de vulnerabilidad '
                'detectables con los tipos seleccionados.</p>'
                '</div>'
            )

        ai_section = ""
        if result.ai_analysis:
            ai_html = self._markdown_to_html(result.ai_analysis)
            ai_section = (
                '<section class="ai">'
                '<h2>Análisis con IA</h2>'
                f'<div class="ai-body">{ai_html}</div>'
                '</section>'
            )

        ts = result.timestamp.replace("T", " ").split(".")[0]
        objective = f"{result.form.method} {self._escape(result.form.action)}"
        fields_str = ", ".join(f.name for f in result.form.injectable_fields) or "—"
        total = len(vulns)

        if total == 0:
            summary_line = "Sin hallazgos"
        else:
            summary_line = (
                f"{total} hallazgo{'s' if total != 1 else ''}"
                f' · <span class="pill pill-alta">{sev_counts["alta"]} alta</span>'
                f' · <span class="pill pill-media">{sev_counts["media"]} media</span>'
                f' · <span class="pill pill-baja">{sev_counts["baja"]} baja</span>'
            )

        gen_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gung12 · Informe de seguridad</title>
<style>
{self._stylesheet()}
</style>
</head>
<body>
<main class="container">

  <header class="report-head">
    <div class="report-title">
      <h1>Gung12</h1>
      <span class="report-kicker">Informe de seguridad</span>
    </div>
    <dl class="meta">
      <div><dt>Objetivo</dt><dd>{objective}</dd></div>
      <div><dt>Campos</dt><dd>{self._escape(fields_str)}</dd></div>
      <div><dt>Modo</dt><dd>{result.scan_mode}</dd></div>
      <div><dt>Fecha</dt><dd>{ts}</dd></div>
    </dl>
  </header>

  <section class="summary">
    <p class="summary-line">{summary_line}</p>
  </section>

  {blocked_notice}

  {empty_state}

  <section class="findings">
    {cards}
  </section>

  {ai_section}

  <footer class="report-foot">
    Gung12 v{__version__} · {gen_ts}
  </footer>

</main>
</body>
</html>"""


    @staticmethod
    def _escape(text: str) -> str:
        return _html.escape(text or "", quote=False)

    @staticmethod
    def _markdown_to_html(text: str) -> str:
        esc = _html.escape(text or "", quote=False)

        def inline(s: str) -> str:
            s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
            s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
            s = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", s)
            return s

        parts: list[str] = []
        list_type: Optional[str] = None

        def close_list() -> None:
            nonlocal list_type
            if list_type:
                parts.append(f"</{list_type}>")
                list_type = None

        for raw in esc.split("\n"):
            line = raw.strip()
            if not line:
                close_list()
                continue
            m = re.match(r"^(#{1,6})\s+(.*)$", line)
            if m:
                close_list()
                level = 3 if len(m.group(1)) <= 3 else 4
                parts.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
                continue
            m = re.match(r"^\d+\.\s+(.*)$", line)
            if m:
                if list_type != "ol":
                    close_list()
                    parts.append("<ol>")
                    list_type = "ol"
                parts.append(f"<li>{inline(m.group(1))}</li>")
                continue
            m = re.match(r"^[*\-]\s+(.*)$", line)
            if m:
                if list_type != "ul":
                    close_list()
                    parts.append("<ul>")
                    list_type = "ul"
                parts.append(f"<li>{inline(m.group(1))}</li>")
                continue
            close_list()
            parts.append(f"<p>{inline(line)}</p>")

        close_list()
        return "\n".join(parts)

    def _render_card(self, v, form=None) -> str:
        sev = self._severity_for(v.confidence)
        artifact = '<span class="tag tag-artifact" title="Posible artefacto de reflexión total — verificar manualmente">posible artefacto</span>' if v.reflection_artifact else ""
        payload_esc = self._escape(v.payload) if v.payload else ""
        evidence_esc = self._escape(v.evidence) if v.evidence else ""
        description_esc = self._escape(v.description)

        payload_block = ""
        if payload_esc and v.payload != "N/A - análisis estático":
            payload_block = (
                '<details class="block">'
                '<summary>Payload</summary>'
                f'<pre><code>{payload_esc}</code></pre>'
                '</details>'
            )

        request_block = ""
        if form is not None and v.payload != "N/A - análisis estático":
            req_lines = (
                f"{self._escape(form.method)} {self._escape(form.action)}\n"
                f"Campo inyectado: {self._escape(v.field_name)}\n"
                f"Tipo de cuerpo: {self._escape(getattr(form, 'body_type', 'form'))}"
            )
            request_block = (
                '<details class="block">'
                '<summary>Petición</summary>'
                f'<pre><code>{req_lines}</code></pre>'
                '</details>'
            )

        evidence_block = ""
        if evidence_esc:
            evidence_block = (
                '<details class="block">'
                '<summary>Evidencia</summary>'
                f'<pre><code>{evidence_esc}</code></pre>'
                '</details>'
            )

        return (
            f'<article class="finding finding-{sev}">'
            f'  <div class="finding-head">'
            f'    <span class="badge badge-{sev}">{sev.upper()}</span>'
            f'    <span class="vtype">{v.vuln_type.value.upper()}</span>'
            f'    <span class="vfield">en <code>{self._escape(v.field_name)}</code></span>'
            f'    {artifact}'
            f'  </div>'
            f'  <p class="vdesc">{description_esc}</p>'
            f'  {payload_block}'
            f'  {request_block}'
            f'  {evidence_block}'
            f'</article>'
        )

    @staticmethod
    def _stylesheet() -> str:
        return """
:root {
  --c-bg: #fafafa;
  --c-surface: #ffffff;
  --c-border: #e5e7eb;
  --c-border-strong: #d1d5db;
  --c-text: #111827;
  --c-text-muted: #6b7280;
  --c-text-soft: #9ca3af;

  --c-alta: #b91c1c;
  --c-alta-soft: #fef2f2;
  --c-media: #b45309;
  --c-media-soft: #fffbeb;
  --c-baja: #1d4ed8;
  --c-baja-soft: #eff6ff;

  --radius: 6px;
  --shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", "Roboto Mono", Menlo, Consolas, monospace;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
  background: var(--c-bg);
  color: var(--c-text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}

.container {
  max-width: 880px;
  margin: 0 auto;
  padding: 3rem 1.5rem 4rem;
}

/* ---- Header ---- */
.report-head {
  padding-bottom: 0.5rem;
  margin-bottom: 1.5rem;
}
.report-title {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
  margin-bottom: 1.25rem;
}
.report-title h1 {
  margin: 0;
  font-size: 1.65rem;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.report-kicker {
  color: var(--c-text-muted);
  font-size: 0.95rem;
}

.meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.85rem 1.5rem;
  margin: 0;
}
.meta > div { display: flex; flex-direction: column; gap: 0.15rem; }
.meta dt {
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--c-text-soft);
}
.meta dd {
  margin: 0;
  font-size: 0.9rem;
  color: var(--c-text);
  word-break: break-all;
  font-family: var(--mono);
}

/* ---- Summary line ---- */
.summary { margin: 1.5rem 0 1rem; }
.summary-line {
  margin: 0;
  font-size: 1rem;
  color: var(--c-text);
}
.pill {
  display: inline-block;
  padding: 0.1rem 0.55rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 600;
  letter-spacing: 0.02em;
  margin: 0 0.05rem;
}
.pill-alta { background: var(--c-alta-soft); color: var(--c-alta); }
.pill-media { background: var(--c-media-soft); color: var(--c-media); }
.pill-baja { background: var(--c-baja-soft); color: var(--c-baja); }

/* ---- Empty ---- */
.empty {
  margin-top: 1rem;
  padding: 1.25rem 1rem;
  border: 1px solid var(--c-border);
  border-radius: var(--radius);
  background: var(--c-surface);
  color: var(--c-text-muted);
  text-align: center;
  font-size: 0.95rem;
}
.empty p { margin: 0; }

/* ---- Findings ---- */
.findings { display: flex; flex-direction: column; gap: 0.75rem; }

.finding {
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-left: 4px solid var(--c-border-strong);
  border-radius: var(--radius);
  padding: 1rem 1.15rem;
  box-shadow: var(--shadow);
}
.finding-alta { border-left-color: var(--c-alta); }
.finding-media { border-left-color: var(--c-media); }
.finding-baja { border-left-color: var(--c-baja); }

.finding-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.55rem;
  margin-bottom: 0.5rem;
}

.badge {
  display: inline-block;
  padding: 0.15rem 0.55rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  color: #fff;
}
.badge-alta { background: var(--c-alta); }
.badge-media { background: var(--c-media); }
.badge-baja { background: var(--c-baja); }

.vtype {
  font-weight: 600;
  font-size: 0.95rem;
  letter-spacing: 0.02em;
}
.vfield {
  color: var(--c-text-muted);
  font-size: 0.92rem;
}
.vfield code {
  font-family: var(--mono);
  background: #f3f4f6;
  padding: 0.05rem 0.35rem;
  border-radius: 3px;
  font-size: 0.85rem;
  color: var(--c-text);
}

.tag {
  font-size: 0.7rem;
  padding: 0.1rem 0.45rem;
  border-radius: 3px;
  font-weight: 500;
  letter-spacing: 0.02em;
}
.tag-artifact { background: #f3f4f6; color: var(--c-text-muted); }

.vdesc {
  margin: 0.3rem 0 0.6rem;
  color: var(--c-text);
  font-size: 0.92rem;
}

.block {
  margin-top: 0.5rem;
  font-size: 0.85rem;
}
.block summary {
  cursor: pointer;
  color: var(--c-text-muted);
  font-weight: 500;
  padding: 0.15rem 0;
  user-select: none;
}
.block summary:hover { color: var(--c-text); }
.block[open] summary { margin-bottom: 0.4rem; }

.block pre {
  margin: 0;
  padding: 0.8rem 1rem;
  background: #f9fafb;
  border: 1px solid var(--c-border);
  border-radius: 4px;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: 0.92rem;
  line-height: 1.55;
  color: var(--c-text);
  white-space: pre-wrap;
  word-break: break-word;
}

/* ---- IA ---- */
.ai {
  margin-top: 2rem;
  padding: 1.25rem 1.25rem 1.4rem;
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--radius);
}
.ai h2 {
  margin: 0 0 0.75rem;
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  color: var(--c-text);
}
.ai-body {
  font-size: 0.9rem;
  color: var(--c-text);
  line-height: 1.65;
}
.ai-body h3 {
  font-size: 0.95rem;
  font-weight: 600;
  margin: 1.1rem 0 0.4rem;
  color: var(--c-text);
}
.ai-body h4 {
  font-size: 0.88rem;
  font-weight: 600;
  margin: 0.85rem 0 0.3rem;
  color: var(--c-text-muted);
}
.ai-body p { margin: 0.5rem 0; }
.ai-body ul, .ai-body ol {
  margin: 0.4rem 0 0.7rem 1.3rem;
  padding: 0;
}
.ai-body li { margin: 0.28rem 0; }
.ai-body strong { font-weight: 600; }
.ai-body code {
  font-family: var(--mono);
  font-size: 0.84em;
  background: var(--c-bg);
  border: 1px solid var(--c-border);
  border-radius: 4px;
  padding: 0.08em 0.34em;
}
.blocked {
  margin: 1.5rem 0;
  padding: 1rem 1.25rem;
  background: var(--c-media-soft);
  border: 1px solid var(--c-media);
  border-left: 4px solid var(--c-media);
  border-radius: var(--radius);
  color: var(--c-text);
}

/* ---- Footer ---- */
.report-foot {
  margin-top: 3rem;
  text-align: center;
  font-size: 0.78rem;
  color: var(--c-text-soft);
  letter-spacing: 0.02em;
}

/* ---- Responsive ---- */
@media (max-width: 600px) {
  .container { padding: 2rem 1rem 3rem; }
  .report-title h1 { font-size: 1.4rem; }
  .meta { grid-template-columns: 1fr; gap: 0.7rem; }
  .finding { padding: 0.85rem 1rem; }
}
"""
