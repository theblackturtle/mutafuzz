"""
Number Range Fuzzing

Generate number sequence from MIN to MAX, send as payloads, add responses to table.
Example: MIN=0, MAX=100, ZFILL=3 generates [000, 001, 002, ..., 099]
"""

MIN = 0
MAX = 100
STEP = 1
ZFILL = 0  # Zero-padding: ZFILL=3 converts 5 to "005"


def queue_tasks():
    """Generate numbers from MIN to MAX with optional zero-padding."""
    for num in range(MIN, MAX, STEP):
        payload = str(num).zfill(ZFILL) if ZFILL > 0 else str(num)
        fuzz.payloads([payload]).queue()

    fuzz.done()
