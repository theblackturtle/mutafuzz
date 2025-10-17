"""
Number Range Fuzzing

Generate number sequence from MIN to MAX, send as payloads, add responses to table.
Example: MIN=0, MAX=100, ZFILL=3 generates [000, 001, 002, ..., 099]
"""

MIN = 0
MAX = 100
STEP = 1
ZFILL = 0  # Zero-padding: ZFILL=3 converts 5 to "005"


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
    """Generate numbers from MIN to MAX with optional zero-padding."""
    for num in range(MIN, MAX, STEP):
        payload = str(num).zfill(ZFILL) if ZFILL > 0 else str(num)
        fuzz.payloads([payload]).queue()

    fuzz.done()
