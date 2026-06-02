
from gung12.payloads import (
    xss, sqli, ssti, xpath, cmdi,
    nosql, xxe, csrf, file_upload,
    open_redirect, htmli, logic,
)
from gung12.models import VulnType

PAYLOAD_REGISTRY = {
    VulnType.XSS: xss,
    VulnType.SQLI: sqli,
    VulnType.SSTI: ssti,
    VulnType.XPATH: xpath,
    VulnType.CMDI: cmdi,
    VulnType.NOSQL: nosql,
    VulnType.XXE: xxe,
    VulnType.CSRF: csrf,
    VulnType.FILE_UPLOAD: file_upload,
    VulnType.OPEN_REDIRECT: open_redirect,
    VulnType.HTMLI: htmli,
    VulnType.LOGIC: logic,
}


def get_payloads(vuln_type: VulnType, full_mode: bool = False) -> list:
    module = PAYLOAD_REGISTRY[vuln_type]
    if full_mode:
        return module.QUICK_PAYLOADS + module.FULL_PAYLOADS
    return module.QUICK_PAYLOADS
