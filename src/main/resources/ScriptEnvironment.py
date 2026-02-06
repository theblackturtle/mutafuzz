"""MutaFuzz Python Scripting Environment - Pythonic API for HTTP fuzzing with Burp Suite."""

import hashlib
import random
import re
import string

# Variables injected by Java PythonScriptRunner at runtime:
# - burp_api: MontoyaApi instance
# - handler: PythonScriptRunner instance
# - wordlists: List of wordlists (access via payloads.wordlist(n))
# - _java_raw_http_list: HttpRequestResponse list (RAW_HTTP_LIST mode)

_should_stop = False


class filter(object):
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


class _QueueBuilder(object):
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


class FuzzerAPI(object):
    """Main fuzzing API. Access via global 'fuzz' object."""

    def __init__(self, handler):
        self._handler = handler

    def url(self, url):
        """Start building request with URL."""
        return _QueueBuilder(self._handler).url(url)

    def payloads(self, payloads):
        """Start building request with payloads."""
        return _QueueBuilder(self._handler).payloads(payloads)

    def raw_request(self, template):
        """Start building request with raw HTTP template."""
        return _QueueBuilder(self._handler).raw_request(template)

    def http_request(self, request):
        """Start building request with HttpRequest object (full Montoya API control)."""
        return _QueueBuilder(self._handler).http_request(request)

    def current_template(self):
        """Start building request from template editor."""
        return _QueueBuilder(self._handler).current_template()

    def http_request_from_url(self, url):
        """Create HttpRequest from URL (customizable with .withHeader(), etc)."""
        return self._handler.httpRequestFromUrl(url)

    @property
    def template(self):
        """Get current HttpRequest from template editor."""
        return self._handler.getCurrentTemplateRequest()

    @property
    def stopped(self):
        """Check if script should stop."""
        return _should_stop

    def done(self):
        """Signal no more tasks will be queued (call at end of queue_tasks())."""
        self._handler.done()


fuzz = FuzzerAPI(handler)


class encode(object):
    """Encoding utilities. Calls burp_api directly — no handler middleman."""

    @staticmethod
    def base64(s):
        if s is None:
            return ""
        return burp_api.utilities().base64Utils().encode(str(s)).toString()

    @staticmethod
    def url(s):
        if s is None:
            return ""
        return burp_api.utilities().urlUtils().encode(str(s))

    @staticmethod
    def html(s):
        if s is None:
            return ""
        return burp_api.utilities().htmlUtils().encode(str(s))

    @staticmethod
    def json(s):
        """JSON-escape a string (escapes quotes, backslashes, control chars)."""
        if s is None:
            return ""
        return (str(s)
                .replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\b", "\\b")
                .replace("\f", "\\f"))


class decode(object):
    """Decoding utilities. Calls burp_api directly — no handler middleman."""

    @staticmethod
    def base64(s):
        if s is None:
            return ""
        return burp_api.utilities().base64Utils().decode(str(s)).toString()

    @staticmethod
    def url(s):
        if s is None:
            return ""
        return burp_api.utilities().urlUtils().decode(str(s))

    @staticmethod
    def html(s):
        if s is None:
            return ""
        return burp_api.utilities().htmlUtils().decode(str(s))

    @staticmethod
    def json(s):
        """JSON-unescape a string."""
        if s is None:
            return ""
        return (str(s)
                .replace("\\f", "\f")
                .replace("\\b", "\b")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace("\\n", "\n")
                .replace('\\"', '"')
                .replace("\\\\", "\\"))


class hash(object):
    """Hashing utilities. Pure Python — no Java dependency."""

    @staticmethod
    def md5(s):
        if s is None:
            return ""
        data = s.encode("utf-8") if isinstance(s, unicode) else s
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def sha256(s):
        if s is None:
            return ""
        data = s.encode("utf-8") if isinstance(s, unicode) else s
        return hashlib.sha256(data).hexdigest()


class session(object):
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


class table(object):
    """Results table operations."""

    @staticmethod
    def add(req):
        """Add request/response to results table."""
        handler.addToTable(req)


class payloads(object):
    """Access to configured wordlists."""

    @staticmethod
    def wordlist(num):
        """Get wordlist by 1-based index. Returns empty list if out of bounds."""
        if wordlists is None:
            return []
        index = num - 1
        if 0 <= index < len(wordlists):
            return wordlists[index] if wordlists[index] is not None else []
        return []

    @staticmethod
    def count():
        """Get number of configured wordlists."""
        return len(wordlists) if wordlists is not None else 0

    @staticmethod
    def all():
        """Get all wordlists combined into single list."""
        result = []
        if wordlists is not None:
            for wl in wordlists:
                if wl is not None:
                    result.extend(wl)
        return result


class templates(object):
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


class utils(object):
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


# Default handle_response: add all responses to table.
# User scripts override this by defining their own handle_response.
def handle_response(req):
    table.add(req)


def onStop():
    """Override this in your script for cleanup."""
    pass


def print_log(message):
    """Print message to Burp Suite output (standard log)."""
    burp_api.logging().logToOutput(str(message))


def print_err(message):
    """Print error message to Burp Suite error output."""
    burp_api.logging().logToError(str(message))
