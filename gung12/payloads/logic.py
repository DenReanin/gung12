
QUICK_PAYLOADS = [
    "",
    " ",
    "-1",
    "0",
    "-999999",
    "999999999999",
    "aaa@",
    "test",
    "<>",
    "' \" \\ / & | ; :",
]

FULL_PAYLOADS = [
    "   ",
    "\t\n",
    "null",
    "undefined",
    "NaN",
    "Infinity",
    "-0",
    "1e308",
    "a" * 10000,
    "@@@.com",
    "test@",
    "test@.com",
    "12/13/2099",
    "00/00/0000",
    "-1.5",
]

DETECTION_PATTERNS = [
    "success",
    "accepted",
    "welcome",
    "created",
    "updated",
    "submitted",
]
