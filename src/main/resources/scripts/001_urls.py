"""
Simple URL Fuzzing

Get URLs from Wordlist Panel 1, request each URL, add responses to table.
Example: Wordlist Panel 1 = [https://example.com/admin, https://example.com/api]
"""


def queue_tasks():
    """Get URLs from Wordlist Panel 1 and request each one."""
    for url in payloads.wordlist(1):
        fuzz.url(url).queue()

    fuzz.done()
