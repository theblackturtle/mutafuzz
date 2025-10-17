"""
Simple URL Fuzzing

Get URLs from Wordlist Panel 1, request each URL, add responses to table.
Example: Wordlist Panel 1 = [https://example.com/admin, https://example.com/api]
"""


# Response Handler - Uncomment filters as needed
# @filter.contains("admin", "panel")
# @filter.interesting()
# @filter.length_range(min=1000, max=5000)
# @filter.matches(r"error|warning", ignore_case=True)
# @filter.status([200, 201, 202])
# @filter.status_not([404, 500])
def handle_response(req):
    """Add response to request table if it passes interesting filter."""
    table.add(req)


def queue_tasks():
    """Get URLs from Wordlist Panel 1 and request each one."""
    for url in payloads.wordlist(1):
        fuzz.url(url).queue()

    fuzz.done()
