"""Registro de payloads por tipo de vulnerabilidad."""

from formvuln.payloads import (
    xss, sqli, ssti, ldap, cmdi,
    nosql, xxe, csrf, lfi,
    open_redirect, idor, logic,
)
from formvuln.models import VulnType

# Mapeo de VulnType a módulo de payloads
PAYLOAD_REGISTRY = {
    VulnType.XSS: xss,
    VulnType.SQLI: sqli,
    VulnType.SSTI: ssti,
    VulnType.LDAP: ldap,
    VulnType.CMDI: cmdi,
    VulnType.NOSQL: nosql,
    VulnType.XXE: xxe,
    VulnType.CSRF: csrf,
    VulnType.LFI: lfi,
    VulnType.OPEN_REDIRECT: open_redirect,
    VulnType.IDOR: idor,
    VulnType.LOGIC: logic,
}


def get_payloads(vuln_type: VulnType, full_mode: bool = False) -> list:
    """Obtiene payloads para un tipo de vulnerabilidad."""
    module = PAYLOAD_REGISTRY[vuln_type]
    if full_mode:
        return module.QUICK_PAYLOADS + module.FULL_PAYLOADS
    return module.QUICK_PAYLOADS
