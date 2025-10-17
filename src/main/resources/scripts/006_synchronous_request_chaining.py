"""
Synchronous Send Chaining

Send first request with .send(), wait for response, extract data, use in second .send().
Example: Get UUID from /uuid, then send it as X-Request-ID header to /headers
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
    """Send two requests synchronously: extract data from first, use in second."""
    import json

    base_url = "https://httpbin.org"

    # Step 1: Send first request and wait for response
    req1 = utils.http_request_from_url(base_url + "/uuid")
    resp1 = fuzz.http_request(req1).send()  # Blocks until response

    # Step 2: Extract data from first response
    data = json.loads(resp1.body)
    request_id = data.get("uuid", "fallback-id")

    # Step 3: Use extracted data in second request
    req2 = utils.http_request_from_url(base_url + "/headers")
    req2 = req2.withHeader("X-Request-ID", request_id)
    resp2 = fuzz.http_request(req2).send()  # Blocks until response

    # Step 4: Add to table if successful
    if resp2.status == 200:
        table.add(resp2)

    fuzz.done()
