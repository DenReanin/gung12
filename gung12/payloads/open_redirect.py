
QUICK_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "http://evil.com",
    "/\\evil.com",
    "https://evil.com/%2F..",
    "//evil.com/%2F..",
    "https://evil.com@trusted.com",
    "javascript:alert('redirect')",
    "data:text/html,<script>alert('redirect')</script>",
]

FULL_PAYLOADS = [
    "https://evil.com/",
    "https://evil.com/path",
    "//evil.com/path",
    "\\\\evil.com",
    "https:evil.com",
    "http:\\\\evil.com",
    "///\\;@evil.com",
    "https://trusted.com.evil.com",
    "https://evil.com#trusted.com",
    "https://evil.com?trusted.com",
    "%68%74%74%70%3a%2f%2fevil.com",
    "https://evil%E3%80%82com",
    "/redirect?url=https://evil.com",
    "//evil%00.com",
    "https://evil.com/trusted.com",
]

DETECTION_PATTERNS = [
    "evil.com",
]
