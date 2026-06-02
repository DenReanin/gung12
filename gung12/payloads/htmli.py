
QUICK_PAYLOADS = [
    "<h1>htmli-test</h1>",
    "<b>htmli-test</b>",
    '<img src=x alt="htmli-test">',
    '<a href="http://htmli.test">htmli-test</a>',
    "<marquee>htmli-test</marquee>",
    "<u>htmli-test</u>",
    "<s>htmli-test</s>",
]

FULL_PAYLOADS = [
    "<blockquote>htmli-test</blockquote>",
    "<details><summary>htmli-test</summary>htmli-body</details>",
    '<input type="text" value="htmli-test" readonly>',
    "<form action=http://htmli.test method=post>",
    "<meta http-equiv=refresh content=0;url=http://htmli.test>",
    "<link rel=stylesheet href=http://htmli.test>",
    "<iframe src=http://htmli.test width=0 height=0>",
    "<table><tr><td>htmli-test</td></tr></table>",
    "<p style=color:red>htmli-test</p>",
    '<button type=button onclick="">htmli-test</button>',
]

DETECTION_PATTERNS = [
    "<h1>htmli-test</h1>",
    "<b>htmli-test</b>",
    "<marquee>htmli-test</marquee>",
    "<u>htmli-test</u>",
    "<s>htmli-test</s>",
    "<blockquote>htmli-test</blockquote>",
    "<details>",
    "<iframe src=http://htmli.test",
]
