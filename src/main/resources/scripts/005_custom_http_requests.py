"""
Build HTTP Request with Burp Suite API

Build request from URL using Burp API, add custom headers, send request, add response to table.
Example: Creates GET request to URL with custom User-Agent header
"""


def queue_tasks():
    """Build HTTP request from URL with Burp Suite API and send."""
    url = "https://httpbin.org/anything"
    req = fuzz.http_request_from_url(url)
    req = req.withHeader("User-Agent", "CustomFuzzer/1.0")
    fuzz.http_request(req).queue()
    fuzz.done()
