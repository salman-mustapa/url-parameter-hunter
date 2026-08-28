"""Vulnerability-specific semantic checks over captured controls and probes.

These checks never dispatch network requests. A status code, evidence-level label,
caller assertion or response length alone cannot produce a positive decision.
"""

import base64
import json
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from app.validation.validators.collected import (
    Decision,
    EvidenceValidator,
    private_content,
    repeated,
)


class SQLiValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("sqli")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        (negative,) = context.require("negative_repeat")
        responses = [e.json() for e in (baseline, control, test, repeat, negative)]
        checks = (
            "Generic errors rejected",
            "Echo-only differences rejected",
            "Two truth/falsehood pairs compared against baseline",
        )
        if not all(isinstance(r, dict) and isinstance(r.get("records"), list) for r in responses):
            return Decision("INCONCLUSIVE", "SQL-specific record differential unavailable", checks)
        b, c, t, r, n = (x["records"] for x in responses)
        inputs = [
            parse_qs(urlsplit(e.url).query).get(context.parameter, [""])[0]
            for e in (control, test, repeat, negative)
        ]
        if any(" AND " not in p.upper() for p in inputs) or inputs[1] == inputs[2]:
            return Decision("INCONCLUSIVE", "Independent SQL predicate controls missing", checks)
        if b and b == t == r and c == n == []:
            return Decision(
                "CONFIRMED",
                "Two independent SQL predicate pairs control retrieval of baseline records",
                checks,
            )
        if b == c == t == r == n or (not t and not r):
            return Decision(
                "NOT_VULNERABLE", "Tested predicates do not control record selection", checks
            )
        return Decision("INCONCLUSIVE", "Unstable or non-specific record differential", checks)


class _ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.inert = 0
        self.script = False
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"textarea", "template", "noscript", "title", "xmp"}:
            self.inert += 1
        attributes = dict(attrs)
        if tag == "script" and not self.inert:
            self.script = attributes.get("type", "").lower() in {
                "",
                "text/javascript",
                "application/javascript",
            }
            if self.script:
                self.scripts.append("")

    def handle_endtag(self, tag):
        if tag in {"textarea", "template", "noscript", "title", "xmp"}:
            self.inert = max(0, self.inert - 1)
        if tag == "script":
            self.script = False

    def handle_data(self, data):
        if self.script and not self.inert:
            self.scripts[-1] += data


class XSSValidator(EvidenceValidator):
    severity = "MEDIUM"

    def __init__(self):
        super().__init__("xss")

    def assess(self, context):
        baseline, _control, test, repeat = repeated(context)
        checks = (
            "MIME checked",
            "Inert HTML excluded",
            "CSP checked",
            "Reflection is not execution",
        )
        script = context.metadata.get("script", "")
        if not script or script in baseline.body:
            return Decision("INCONCLUSIVE", "Fresh script canary missing", checks)
        for response in (test, repeat):
            if response.header("content-type").split(";")[0].strip() != "text/html":
                return Decision(
                    "NOT_VULNERABLE", "Reflection uses a non-executable MIME type", checks
                )
            parser = _ScriptParser()
            parser.feed(response.body)
            if script not in parser.scripts:
                return Decision(
                    "NOT_VULNERABLE", "Canary is absent from an executable script element", checks
                )
            csp = response.header("content-security-policy").lower()
            if (
                csp
                and ("script-src" in csp or "default-src" in csp)
                and "'unsafe-inline'" not in csp
            ):
                return Decision(
                    "INCONCLUSIVE",
                    "Injected markup found but CSP/browser execution needs verification",
                    checks,
                )
        return Decision(
            "VALIDATED",
            "Repeated script-element injection; browser execution remains unconfirmed",
            checks,
        )


class RCEValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("rce")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        checks = (
            "HTTP errors are not execution",
            "Controls compared",
            "Independent computed canaries",
            "Echo excluded",
        )
        expected = context.metadata.get("expected")
        expected_repeat = context.metadata.get("expected_repeat")
        if not expected or not expected_repeat or expected == expected_repeat:
            return Decision("INCONCLUSIVE", "Two independent computed canaries required", checks)
        for exchange, output in ((test, expected), (repeat, expected_repeat)):
            result = exchange.json()
            if str(output) in unquote(exchange.url) + exchange.request_body:
                return Decision(
                    "INCONCLUSIVE", "Expected output is in the input and could be reflected", checks
                )
            if not isinstance(result, dict) or result.get("output") != str(output):
                return Decision(
                    "NOT_VULNERABLE", "Computed command canary was not observed", checks
                )
            if str(output) in baseline.body + control.body:
                return Decision("INCONCLUSIVE", "Canary occurs in a control response", checks)
        return Decision(
            "CONFIRMED", "Two benign computations returned outputs absent from the request", checks
        )


class SSRFValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("ssrf")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        (sink,) = context.require("receiver")
        checks = (
            "URL acceptance is not SSRF",
            "Receiver evidence correlated",
            "Independent response canary",
        )
        marker = context.metadata.get("receiver_marker", "")
        correlation = context.metadata.get("correlation", "")
        log = sink.json()
        if not marker or not correlation or not isinstance(log, dict):
            return Decision("INCONCLUSIVE", "Independent receiver observation missing", checks)
        if marker in baseline.body + control.body + test.url + test.request_body:
            return Decision(
                "INCONCLUSIVE", "Receiver marker is not independent of inputs/controls", checks
            )
        hits = [x for x in log.get("requests", []) if x.get("correlation") == correlation]
        if marker in test.body and marker in repeat.body and len(hits) >= 2:
            return Decision(
                "CONFIRMED",
                "Repeated probes caused correlated loopback receiver access and returned its private canary",
                checks,
            )
        return Decision("NOT_VULNERABLE", "No correlated server-side fetch demonstrated", checks)


class PathTraversalValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("path_traversal")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        checks = (
            "Status/error signatures insufficient",
            "Exact synthetic file canary",
            "Traversal input checked",
        )
        marker = context.metadata.get("file_marker", "")
        if not marker or marker in baseline.body + control.body:
            return Decision("INCONCLUSIVE", "Independent restricted-file marker missing", checks)
        if not all("../" in unquote(e.url) for e in (test, repeat)):
            return Decision(
                "INCONCLUSIVE", "Traversal component missing from captured requests", checks
            )
        if all(e.body == marker and marker not in e.url for e in (test, repeat)):
            return Decision(
                "CONFIRMED", "Traversal retrieved the exact restricted synthetic file twice", checks
            )
        return Decision("NOT_VULNERABLE", "Restricted synthetic file was not returned", checks)


class IDORValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("idor")

    def assess(self, context):
        from app.core.authentication_context import AuthorizationCase

        case = context.metadata.get("authorization_case")
        if not isinstance(case, AuthorizationCase):
            return Decision("INCONCLUSIVE", "Actor/resource ownership policy required", ())
        return case.evaluate(context)


class AuthorizationValidator(IDORValidator):
    def __init__(self):
        EvidenceValidator.__init__(self, "authorization")


class AuthBypassValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("auth_bypass")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        resource = context.metadata.get("resource", {})
        checks = (
            "Login pages are not protected data",
            "Denied anonymous/invalid controls",
            "Private resource identity",
            "Unauthenticated probe context",
        )
        if baseline.status not in {401, 403} or control.status not in {401, 403}:
            return Decision("INCONCLUSIVE", "Protection baseline has not been established", checks)
        if any(
            e.actor != "anonymous" or e.sent_header("cookie") or e.sent_header("authorization")
            for e in (baseline, control, test, repeat)
        ):
            return Decision(
                "INCONCLUSIVE",
                "Probe used credentials; authentication bypass not established",
                checks,
            )
        if private_content(test, resource) and private_content(repeat, resource):
            return Decision(
                "CONFIRMED",
                "Anonymous probes repeatedly returned the protected synthetic resource",
                checks,
            )
        return Decision("NOT_VULNERABLE", "Protected resource was not accessed anonymously", checks)


class FileUploadValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("file_upload")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        (upload,) = context.require("upload")
        checks = (
            "Acceptance alone insufficient",
            "Stored URL correlated",
            "Computed output distinct from upload",
            "Repeated retrieval",
        )
        expected = context.metadata.get("expected", "")
        uploaded = upload.json()
        if not isinstance(uploaded, dict) or not uploaded.get("url") or not expected:
            return Decision("INCONCLUSIVE", "Upload/storage evidence missing", checks)
        if test.url != uploaded["url"] or repeat.url != test.url:
            return Decision("INCONCLUSIVE", "Retrieved file differs from captured upload", checks)
        if str(expected) in upload.request_body + baseline.body + control.body:
            return Decision(
                "INCONCLUSIVE", "Canary explainable by reflection/static content", checks
            )
        if test.body == str(expected) and repeat.body == str(expected):
            return Decision(
                "CONFIRMED",
                "Uploaded template was stored and evaluated twice; OS command execution is not claimed",
                checks,
            )
        return Decision(
            "NOT_VULNERABLE", "Upload rejected or retrieved as non-executable data", checks
        )


class OpenRedirectValidator(EvidenceValidator):
    severity = "MEDIUM"

    def __init__(self):
        super().__init__("open_redirect")

    def assess(self, context):
        baseline, _control, test, repeat = repeated(context)
        checks = (
            "Exact destination compared",
            "Same-origin redirect excluded",
            "No redirects followed",
        )
        for exchange in (test, repeat):
            supplied = parse_qs(urlsplit(exchange.url).query).get(context.parameter, [""])[0]
            location = urljoin(exchange.url, exchange.header("location"))
            if not supplied or urlsplit(supplied).scheme not in {"http", "https"}:
                return Decision("INCONCLUSIVE", "Absolute redirect input missing", checks)
            if exchange.status not in {301, 302, 303, 307, 308} or location != supplied:
                return Decision(
                    "NOT_VULNERABLE", "Response does not redirect to supplied destination", checks
                )
            if urlsplit(location).netloc == urlsplit(context.target).netloc:
                return Decision("NOT_VULNERABLE", "Redirect stays on the same origin", checks)
            if location == urljoin(baseline.url, baseline.header("location")):
                return Decision("INCONCLUSIVE", "Redirect already present in baseline", checks)
        return Decision(
            "CONFIRMED",
            "Two captured redirects selected the exact supplied external origin",
            checks,
        )


class CORSValidator(EvidenceValidator):
    severity = "MEDIUM"

    def __init__(self):
        super().__init__("cors")

    def assess(self, context):
        _baseline, control, test, repeat = repeated(context)
        checks = (
            "Private resource checked",
            "Anonymous control denied",
            "Credentialed origin reflection",
        )
        resource = context.metadata.get("resource", {})
        if control.status not in {401, 403}:
            return Decision("INCONCLUSIVE", "Private endpoint baseline not established", checks)
        for e in (test, repeat):
            supplied = e.sent_header("origin")
            if not supplied or supplied in e.url:
                return Decision("INCONCLUSIVE", "Untrusted origin not supplied", checks)
            if (
                e.header("access-control-allow-origin") != supplied
                or e.header("access-control-allow-credentials").lower() != "true"
                or not private_content(e, resource)
            ):
                return Decision(
                    "NOT_VULNERABLE", "Credentialed private response not exposed", checks
                )
        return Decision(
            "VALIDATED",
            "Credentialed CORS headers expose private content; browser cookie policy still requires verification",
            checks,
        )


class CSRFValidator(EvidenceValidator):
    severity = "MEDIUM"

    def __init__(self):
        super().__init__("csrf")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        after, after_repeat, login = context.require("after", "after_repeat", "login")
        checks = (
            "Before/after state checked",
            "Anonymous control denied",
            "Cross-site navigation",
            "SameSite cookie eligibility",
        )
        if control.status not in {401, 403} or not isinstance(baseline.json(), dict):
            return Decision("INCONCLUSIVE", "State baseline/anonymous control missing", checks)
        if "samesite=lax" not in login.header("set-cookie").lower():
            return Decision(
                "INCONCLUSIVE", "Browser-sendable navigation cookie not captured", checks
            )
        for request, observed, key in (
            (test, after, "value"),
            (repeat, after_repeat, "value_repeat"),
        ):
            if (
                request.method != "GET"
                or request.sent_header("sec-fetch-site") != "cross-site"
                or request.sent_header("sec-fetch-mode") != "navigate"
                or not request.sent_header("cookie")
            ):
                return Decision(
                    "INCONCLUSIVE", "Cross-site top-level GET navigation context missing", checks
                )
            expected = context.metadata.get(key)
            if not expected or observed.json().get("value") != expected:
                return Decision(
                    "NOT_VULNERABLE",
                    "Cross-site request did not cause the intended state change",
                    checks,
                )
            if baseline.json().get("value") == expected:
                return Decision(
                    "INCONCLUSIVE", "Expected mutation already present before test", checks
                )
        return Decision(
            "CONFIRMED",
            "Two cross-site GET navigations changed synthetic state with a Lax session cookie",
            checks,
        )


class JWTValidator(EvidenceValidator):
    def __init__(self):
        super().__init__("jwt")

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        checks = (
            "Anonymous/invalid tokens denied",
            "Token structure inspected",
            "Protected resource checked",
        )
        resource = context.metadata.get("resource", {})
        if baseline.status not in {401, 403} or control.status not in {401, 403}:
            return Decision("INCONCLUSIVE", "Protected session controls missing", checks)
        for e in (test, repeat):
            parts = e.sent_header("authorization").removeprefix("Bearer ").split(".")
            if len(parts) != 3:
                return Decision("INCONCLUSIVE", "Captured JWT missing", checks)
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            except (ValueError, UnicodeError):
                return Decision("INCONCLUSIVE", "JWT header malformed", checks)
            if header.get("alg") != "none" or parts[2]:
                return Decision(
                    "INCONCLUSIVE", "This validator covers unsigned-token acceptance only", checks
                )
            if not private_content(e, resource):
                return Decision(
                    "NOT_VULNERABLE", "Unsigned token did not access protected resource", checks
                )
        return Decision(
            "CONFIRMED",
            "Unsigned tokens repeatedly accessed the protected synthetic resource",
            checks,
        )
