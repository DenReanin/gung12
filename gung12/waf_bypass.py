"""Técnicas de evasión de WAF para ampliar la cobertura en entornos protegidos.

Activado con el flag --waf-bypass. Genera variantes encoded de los payloads
para evadir filtros basados en firmas estáticas (ModSecurity, Cloudflare WAF).
"""

import urllib.parse


def _url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe='')


def _double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


def _case_variation(payload: str) -> str:
    """Alterna mayúsculas/minúsculas para evadir filtros case-sensitive."""
    result = []
    for i, c in enumerate(payload):
        result.append(c.upper() if c.isalpha() and i % 2 == 0 else c.lower() if c.isalpha() else c)
    return ''.join(result)


def _space_to_comment(payload: str) -> str:
    """Reemplaza espacios por /**/ para evadir filtros SQL."""
    return payload.replace(' ', '/**/')


def _null_byte(payload: str) -> str:
    return payload + '%00'


def _tag_case_xss(payload: str) -> str:
    """Variantes de etiquetas script/img con capitalización mixta."""
    return (payload
            .replace('<script>', '<ScRiPt>')
            .replace('</script>', '</ScRiPt>')
            .replace('<img ', '<ImG ')
            .replace('onerror=', 'oNeRrOr='))


def generate_bypass_variants(payload: str, vuln_type_value: str) -> list:
    """Genera variantes del payload con técnicas de evasión WAF según el tipo."""
    variants = []

    if vuln_type_value in ('xss', 'htmli'):
        variants.append(_url_encode(payload))
        variants.append(_double_url_encode(payload))
        if '<script' in payload.lower() or 'onerror' in payload.lower():
            variants.append(_tag_case_xss(payload))

    elif vuln_type_value in ('sqli', 'xpath', 'nosql'):
        variants.append(_space_to_comment(payload))
        variants.append(_url_encode(payload))
        variants.append(_case_variation(payload))

    elif vuln_type_value in ('cmdi', 'ssti', 'xxe'):
        variants.append(_url_encode(payload))
        variants.append(_null_byte(payload))

    else:
        variants.append(_url_encode(payload))

    # Eliminar duplicados y el payload original
    return list(dict.fromkeys(v for v in variants if v != payload))
