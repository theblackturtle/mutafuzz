"""
Send All Context Menu Requests

Get all requests from context menu (right-click), send each one, add responses to table.
Example: Right-click 3 requests → Send To Fuzzer → Script sends all 3 requests
"""


def queue_tasks():
    """Get all requests from context menu templates and send each one."""
    for req_resp in templates.all():
        fuzz.http_request(req_resp.request()).queue()

    fuzz.done()
