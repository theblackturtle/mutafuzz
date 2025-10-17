"""
Default Fuzzing Script - Advanced payload generation with learn mode

Supports battering ram mode, payload transformations, and automatic filtering
of duplicate/expected responses using learn mode.
"""

import time
from itertools import product

# Configuration options for payload generation
UPPERCASE = False
LOWERCASE = False
UPPER_FIRST_CHAR = False


# Response Handler - Uncomment filters as needed
# @filter.contains("admin", "panel")
# @filter.interesting()
# @filter.length_range(min=1000, max=5000)
# @filter.matches(r"error|warning", ignore_case=True)
# @filter.status([200, 201, 202])
# @filter.status_not([404, 500])
@filter.interesting()
def handle_response(req):
    """
    Process interesting HTTP responses and add them to results table.

    Args:
        req: RequestObject with Jython property access (req.status, req.interesting, etc.)
    """
    table.add(req)


def get_marker_count():
    """Count payload positions (%s) in current template."""
    template_req = utils.get_current_template()
    if template_req:
        return template_req.toString().count("%s")
    return 1  # Default: single position


def queue_tasks():
    """
    Queue fuzzing tasks with calibration and payload transformations.
    """
    # Collect configured wordlists
    wordlists = []
    if len(payloads.wordlist(1)) > 0:
        wordlists.append(payloads.wordlist(1))
    if len(payloads.wordlist(2)) > 0:
        wordlists.append(payloads.wordlist(2))
    if len(payloads.wordlist(3)) > 0:
        wordlists.append(payloads.wordlist(3))

    marker_count = get_marker_count()

    # Calibration phase (learn groups 1-5)
    # Learn mode automatically filters responses to show only interesting ones
    for i in range(6, 12, 3):
        # Learn group 1: random string
        payload = utils.randstr(length=i)
        fuzz.payloads([payload] * marker_count).learn_group(1).queue()

        # Learn group 2: random with trailing slash
        payload = utils.randstr(length=i) + "/"
        fuzz.payloads([payload] * marker_count).learn_group(2).queue()

        # Learn group 3: admin prefix
        payload = "admin" + utils.randstr(length=i)
        fuzz.payloads([payload] * marker_count).learn_group(3).queue()

        # Learn group 4: .htaccess prefix
        payload = ".htaccess" + utils.randstr(length=i)
        fuzz.payloads([payload] * marker_count).learn_group(4).queue()

        # Learn group 5: buffer overflow
        payload = "A" * (1000 + i)
        fuzz.payloads([payload] * marker_count).learn_group(5).queue()

    time.sleep(0.5)

    # Main fuzzing phase with payload transformations
    if marker_count > 1:
        # Battering ram mode: replicate each payload across all positions
        all_payloads = []
        for wordlist in wordlists:
            all_payloads.extend(wordlist)

        for payload in all_payloads:
            # Apply transformations
            if UPPERCASE:
                payload = payload.upper()
            elif LOWERCASE:
                payload = payload.lower()
            elif UPPER_FIRST_CHAR:
                payload = payload.capitalize()

            fuzz.payloads([payload] * marker_count).queue()
    else:
        # Normal mode: different payloads per position
        for combination in product(*wordlists):
            # Apply transformations
            if UPPERCASE:
                combination = [item.upper() for item in combination]
            elif LOWERCASE:
                combination = [item.lower() for item in combination]
            elif UPPER_FIRST_CHAR:
                combination = [item.capitalize() for item in combination]

            fuzz.payloads(list(combination)).queue()

    fuzz.done()
