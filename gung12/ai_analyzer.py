"""Módulo de análisis con IA.

Soporta dos proveedores de IA con API gratuita:
- Gemini (Google) — gemini-2.0-flash-lite con 500 RPD gratis
- Groq — modelos Llama/Mixtral con tier gratuito

La IA se usa para validar y priorizar las detecciones,
NO como motor de detección principal.
"""

import os
import json
from typing import Optional

from gung12.models import ScanResult


class AIAnalyzer:
    """Analiza resultados de escaneo usando IA como segunda opinión."""

    def __init__(self, provider: str = "gemini", api_key: Optional[str] = None):
        self.provider = provider.lower()
        self.api_key = api_key or self._get_api_key()

        if not self.api_key:
            raise ValueError(
                f"API key no proporcionada para '{provider}'. "
                f"Usa --ai-key o la variable de entorno correspondiente: "
                f"GEMINI_API_KEY, GROQ_API_KEY"
            )

    def _get_api_key(self) -> Optional[str]:
        """Busca API key en variables de entorno."""
        env_vars = {
            "gemini": "GEMINI_API_KEY",
            "groq": "GROQ_API_KEY",
        }
        var_name = env_vars.get(self.provider, "")
        return os.environ.get(var_name)

    def analyze_results(self, scan_result: ScanResult) -> str:
        """Envía los resultados a la IA para análisis experto."""
        prompt = self._build_prompt(scan_result)

        if self.provider == "gemini":
            return self._call_gemini(prompt)
        elif self.provider == "groq":
            return self._call_groq(prompt)
        else:
            raise ValueError(f"Proveedor no soportado: {self.provider}. Usa 'gemini' o 'groq'.")

    def _build_prompt(self, result: ScanResult) -> str:
        """Construye el prompt para la IA."""
        vulns_summary = []
        for v in result.vulnerabilities:
            vulns_summary.append({
                "tipo": v.vuln_type.value,
                "campo": v.field_name,
                "payload": v.payload[:100],
                "evidencia": v.evidence[:200],
                "confianza": f"{v.confidence:.0%}",
            })

        return f"""Eres un experto en ciberseguridad web. Analiza estos resultados de un escaneo
de vulnerabilidades en un formulario web y proporciona:

1. VALIDACIÓN: ¿Cuáles de estas detecciones son probablemente verdaderos positivos
   y cuáles podrían ser falsos positivos? Justifica brevemente.
2. RIESGO: Evalúa el riesgo global del formulario analizado.
3. RECOMENDACIONES: Lista 3-5 recomendaciones de mitigación priorizadas.

URL analizada: {result.url}
Método: {result.form.method}
Campos: {', '.join(f.name for f in result.form.fields)}
Modo de escaneo: {result.scan_mode}

Vulnerabilidades detectadas ({len(result.vulnerabilities)}):
{json.dumps(vulns_summary, indent=2, ensure_ascii=False)}

Responde en español, de forma concisa y técnica. Máximo 500 palabras."""

    def _call_gemini(self, prompt: str) -> str:
        """Llama a la API de Gemini."""
        import requests

        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key={self.api_key}",
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_groq(self, prompt: str) -> str:
        """Llama a la API de Groq."""
        import requests

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [
                    {"role": "system", "content": "Eres un experto en ciberseguridad web."},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 1024,
                "temperature": 0.3,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
