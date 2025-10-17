"""
Send All Context Menu Requests

Get all requests from context menu (right-click), send each one, add responses to table.
Example: Right-click 3 requests → Send To Fuzzer → Script sends all 3 requests
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
    """Get all requests from context menu templates and send each one."""
    for req_resp in templates.all():
        fuzz.http_request(req_resp.request()).queue()

    fuzz.done()
