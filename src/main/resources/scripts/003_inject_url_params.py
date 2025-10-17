"""
URL Parameter Polyglot Injection

Inject polyglot payload into each URL parameter, send requests, add responses to table.
Example: /page?id=1&name=test becomes /page?id=PAYLOAD&name=test (2 requests)
"""

from burp.api.montoya.http.message.params import HttpParameter, HttpParameterType

# Manual URL encoding required (Burp Suite limitation)
# https://github.com/PortSwigger/burp-extensions-montoya-api/issues/103
PAYLOAD = encode.url("xsstest'\"<>\\")


def queue_tasks():
    """Inject PAYLOAD into each URL parameter from context menu templates."""
    for req_resp in templates.all():
        request = req_resp.request()

        try:
            all_params = request.parameters()
            if not all_params:
                continue

            for param in all_params:
                if param.type() == HttpParameterType.URL:
                    modified_req = request.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), PAYLOAD, param.type())
                    )
                    fuzz.http_request(modified_req).queue()
        except:
            pass

    fuzz.done()


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
