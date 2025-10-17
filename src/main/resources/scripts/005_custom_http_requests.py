"""
Build HTTP Request with Burp Suite API

Build request from URL using Burp API, add custom headers, send request, add response to table.
Example: Creates GET request to URL with custom User-Agent header
"""


# Response Handler - Uncomment filters as needed
# @filter.contains("admin", "panel")
# @filter.interesting()
# @filter.length_range(min=1000, max=5000)
# @filter.matches(r"error|warning", ignore_case=True)
# @filter.status([200, 201, 202])
# @filter.status_not([404, 500])
def handle_response(req):
    """Add response to request table."""
    table.add(req)


def queue_tasks():
    """Build HTTP request from URL with Burp Suite API and send."""
    url = "https://httpbin.org/anything"
    req = utils.http_request_from_url(url)
    req = req.withHeader("User-Agent", "CustomFuzzer/1.0")
    fuzz.http_request(req).queue()
    fuzz.done()
