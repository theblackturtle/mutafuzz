"""MutaFuzz Python Scripting Environment - Pythonic API for HTTP fuzzing with Burp Suite."""

import random
import re
import string

# Variables injected by Java PythonScriptExecutor at runtime:
# - burp_api: MontoyaApi instance
# - handler: PythonScriptBridge instance
# - _wordlist_1, _wordlist_2, _wordlist_3: Configured wordlists
# - _java_raw_http_list: HttpRequestResponse list (RAW_HTTP_LIST mode)

_should_stop = False


class filter:
    """Response filter decorators. Stack decorators for complex logic.

    @filter.status([200])
    @filter.interesting()
    def handle_response(req): table.add(req)
    """

    @staticmethod
    def status(codes):
        """Include only these status codes."""
        if not isinstance(codes, (list, tuple)):
            codes = [codes]

        def decorator(func):
            def wrapper(req):
                if req.status in codes:
                    return func(req)

            return wrapper

        return decorator

    @staticmethod
    def status_not(codes):
        """Exclude these status codes."""
        if not isinstance(codes, (list, tuple)):
            codes = [codes]

        def decorator(func):
            def wrapper(req):
                if req.status not in codes:
                    return func(req)

            return wrapper

        return decorator

    @staticmethod
    def interesting():
        """Include only responses marked interesting by learn mode."""

        def decorator(func):
            def wrapper(req):
                if req.interesting:
                    return func(req)

            return wrapper

        return decorator

    @staticmethod
    def length_range(min=None, max=None):
        """Filter by content length range (inclusive)."""

        def decorator(func):
            def wrapper(req):
                length = req.length
                if (min is None or length >= min) and (max is None or length <= max):
                    return func(req)

            return wrapper

        return decorator

    @staticmethod
    def contains(*keywords):
        """Include only if body contains all keywords (case-insensitive)."""

        def decorator(func):
            def wrapper(req):
                body_lower = req.text.lower() if req.text else ""
                if all(kw.lower() in body_lower for kw in keywords):
                    return func(req)

            return wrapper

        return decorator

    @staticmethod
    def matches(pattern, ignore_case=False):
        """Include only if body matches regex pattern."""

        def decorator(func):
            def wrapper(req):
                flags = re.IGNORECASE if ignore_case else 0
                body = req.text if req.text else ""
                if re.search(pattern, body, flags):
                    return func(req)

            return wrapper

        return decorator


class QueueBuilder:
    """Fluent builder for fuzzing requests. Chain methods then call .queue() or .send()."""

    def __init__(self, handler):
        self._handler = handler
        self._url = None
        self._template = None
        self._payloads = None
        self._learn_group = 0
        self._http_request = None

    def url(self, url):
        """Set target URL."""
        self._url = url
        return self

    def raw_request(self, template):
        """Set raw HTTP template with %s markers for payload injection."""
        self._template = template
        return self

    def payloads(self, payloads):
        """Set payloads to inject at %s markers."""
        self._payloads = payloads if isinstance(payloads, list) else [payloads]
        return self

    def learn_group(self, group_id):
        """Set learn group (>=1 enables learning, 0 disables)."""
        self._learn_group = group_id
        return self

    def http_request(self, request):
        """Set pre-built HttpRequest object (full Montoya API control)."""
        self._http_request = request
        return self

    def current_template(self):
        """Use request from template editor."""
        self._http_request = self._handler.getCurrentTemplateRequest()
        return self

    def queue(self):
        """Queue request for async execution."""
        if self._http_request:
            self._handler.queueHttpRequest(self._http_request, self._learn_group)
        elif self._template:
            self._handler.queueRawTemplate(
                self._url, self._template, self._payloads, self._learn_group
            )
        elif self._payloads:
            current_req = self._handler.getCurrentTemplateRequest()
            if current_req:
                template_str = current_req.toString()
                self._handler.queueRawTemplate(
                    None, template_str, self._payloads, self._learn_group
                )
            else:
                self._handler.queuePayloads(self._payloads, self._learn_group)
        elif self._url:
            self._handler.queueUrl(self._url, self._learn_group)
        return self

    def send(self):
        """Send request synchronously, return RequestObject immediately.

        Blocks until response received. No callback, no learn mode, not auto-added to table.
        For payloads, sends only FIRST payload.
        """
        if self._http_request:
            return self._handler.sendHttpRequest(self._http_request)
        elif self._template:
            if not self._payloads:
                raise ValueError("raw_request() requires payloads()")
            return self._handler.sendRawTemplate(
                self._url, self._template, self._payloads
            )
        elif self._payloads:
            return self._handler.sendPayloads(self._payloads)
        elif self._url:
            return self._handler.sendUrl(self._url)
        else:
            raise ValueError(
                "send() requires url(), payloads(), http_request(), or raw_request()"
            )


class FuzzerAPI:
    """Main fuzzing API. Access via global 'fuzz' object."""

    def __init__(self, handler):
        self.handler = handler

    def url(self, url):
        """Start building request with URL."""
        return QueueBuilder(self.handler).url(url)

    def payloads(self, payloads):
        """Start building request with payloads."""
        return QueueBuilder(self.handler).payloads(payloads)

    def raw_request(self, template):
        """Start building request with raw HTTP template."""
        return QueueBuilder(self.handler).raw_request(template)

    def http_request(self, request):
        """Start building request with HttpRequest object (full Montoya API control)."""
        return QueueBuilder(self.handler).http_request(request)

    def current_template(self):
        """Start building request from template editor."""
        return QueueBuilder(self.handler).current_template()

    def done(self):
        """Signal no more tasks will be queued (call at end of queue_tasks())."""
        self.handler.done()


fuzz = FuzzerAPI(handler)


class encode:
    """Encoding utilities."""

    @staticmethod
    def base64(s):
        return handler.base64Encode(s)

    @staticmethod
    def url(s):
        return handler.urlEncode(s)

    @staticmethod
    def html(s):
        return handler.htmlEncode(s)

    @staticmethod
    def json(s):
        return handler.jsonEscape(s)


class decode:
    """Decoding utilities."""

    @staticmethod
    def base64(s):
        return handler.base64Decode(s)

    @staticmethod
    def url(s):
        return handler.urlDecode(s)

    @staticmethod
    def html(s):
        return handler.htmlDecode(s)

    @staticmethod
    def json(s):
        return handler.jsonUnescape(s)


class hash:
    """Hashing utilities."""

    @staticmethod
    def md5(s):
        return handler.md5Hash(s)

    @staticmethod
    def sha256(s):
        return handler.sha256Hash(s)


class session:
    """Thread-safe state storage for multi-step workflows."""

    @staticmethod
    def set(key, value):
        handler.sessionSet(key, value)

    @staticmethod
    def get(key, default=None):
        return handler.sessionGet(key, default)

    @staticmethod
    def clear():
        handler.sessionClear()

    @staticmethod
    def increment(key):
        return handler.sessionIncrement(key)

    @staticmethod
    def contains(key):
        return handler.sessionContains(key)


class table:
    """Results table operations."""

    @staticmethod
    def add(req):
        """Add request/response to results table."""
        handler.addToTable(req)

    @staticmethod
    def add_if(req, condition):
        """Conditionally add to table. Condition is callable or boolean."""
        if callable(condition):
            if condition(req):
                table.add(req)
        elif condition:
            table.add(req)


class payloads:
    """Access to configured wordlists."""

    @staticmethod
    def wordlist(num):
        """Get wordlist 1, 2, or 3."""
        if num == 1:
            return payloads._get_payloads_1()
        elif num == 2:
            return payloads._get_payloads_2()
        elif num == 3:
            return payloads._get_payloads_3()
        return []

    @staticmethod
    def all():
        """Get all wordlists combined."""
        result = []
        result.extend(payloads._get_payloads_1())
        result.extend(payloads._get_payloads_2())
        result.extend(payloads._get_payloads_3())
        return result

    @staticmethod
    def _get_payloads_1():
        return _wordlist_1 if _wordlist_1 is not None else []

    @staticmethod
    def _get_payloads_2():
        return _wordlist_2 if _wordlist_2 is not None else []

    @staticmethod
    def _get_payloads_3():
        return _wordlist_3 if _wordlist_3 is not None else []


class templates:
    """Access to raw HTTP templates (RAW_HTTP_LIST mode only)."""

    @staticmethod
    def get(num):
        """Get HttpRequestResponse by 1-based index."""
        items = templates._get_raw_http_request_responses()
        if 1 <= num <= len(items):
            return items[num - 1]
        return None

    @staticmethod
    def all():
        """Get all HttpRequestResponse objects."""
        return templates._get_raw_http_request_responses()

    @staticmethod
    def count():
        """Get count of templates."""
        return len(templates._get_raw_http_request_responses())

    @staticmethod
    def _get_raw_http_request_responses():
        return _java_raw_http_list if _java_raw_http_list is not None else []


class utils:
    """General utilities."""

    @staticmethod
    def randstr(length=12, digits=True):
        """Generate random string."""
        candidates = string.ascii_lowercase
        if digits:
            candidates += string.digits
        return "".join(random.choice(candidates) for _ in range(length))

    @staticmethod
    def sleep(ms):
        """Sleep for milliseconds."""
        if ms is None or ms <= 0:
            return
        handler.sleep(ms)

    @staticmethod
    def chunked(iterable, size):
        """Split iterable into chunks of size."""
        items = list(iterable)
        for i in range(0, len(items), size):
            yield items[i : i + size]

    @staticmethod
    def http_request_from_url(url):
        """Create HttpRequest from URL (customizable with .withHeader(), etc)."""
        return handler.httpRequestFromUrl(url)

    @staticmethod
    def get_current_template():
        """Get current HttpRequest from template editor"""
        return handler.getCurrentTemplateRequest()


def shouldStop():
    """Check if script should stop."""
    return _should_stop


def onStop():
    """Override this in your script for cleanup."""
    pass


def print_log(message):
    """Print message to Burp Suite output (standard log).

    Args:
        message: Message to log (converted to string)

    Example:
        print_log("Fuzzing started with 100 payloads")
    """

    burp_api.logging().logToOutput(str(message))


def print_err(message):
    """Print error message to Burp Suite error output.

    Args:
        message: Error message to log (converted to string)

    Example:
        print_err("Failed to parse response: invalid JSON")
    """

    burp_api.logging().logToError(str(message))
