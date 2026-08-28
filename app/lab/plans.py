"""Explicit synthetic lab plans: no endpoint spraying or third-party payloads."""

import base64
import json
from dataclasses import asdict
from uuid import uuid4

from app.core.authentication_context import AuthorizationCase
from app.validation.engine import Probe, ValidationPlan


def lab_plan(state, base: str, family: str, variant="vuln", scenario="horizontal"):
    endpoint = f"{base}/{variant}/{family}"
    metadata = {}
    probes = []
    parameter = ""

    def get(phase, *, params=None, url=None, headers=None, actor="anonymous", **extra):
        return Probe(
            phase,
            url or endpoint,
            actor=actor,
            kwargs={"params": params or {}, "headers": headers or {}},
            **extra,
        )

    if family == "sqli":
        parameter = "id"
        probes = [
            get(p, params={parameter: v})
            for p, v in (
                ("baseline", "1"),
                ("control", "1 AND 7*7=50"),
                ("test", "1 AND 7*7=49"),
                ("repeat", "1 AND 13*13=169"),
                ("negative_repeat", "1 AND 13*13=170"),
            )
        ]
    elif family == "xss":
        parameter = "q"
        metadata["script"] = 'window.__lab_canary="' + uuid4().hex + '"'
        probes = [
            get(p, params={"q": q})
            for p, q in (
                ("baseline", "baseline"),
                ("control", "plain-text"),
                ("test", f"<script>{metadata['script']}</script>"),
                ("repeat", f"<script>{metadata['script']}</script>"),
            )
        ]
    elif family in {"idor", "authorization"}:
        resource_name = (
            "bob"
            if scenario in {"horizontal", "bola"}
            else "charlie"
            if scenario == "tenant"
            else "admin"
        )
        endpoint = f"{base}/{variant}/authorization/{resource_name}"
        case = AuthorizationCase(
            state.actors["alice"], state.actors[resource_name], state.resources[resource_name]
        )
        metadata["authorization_case"] = case
        owner_headers = {"Authorization": "Bearer " + state.tokens[resource_name]}
        actor_headers = {"Authorization": "Bearer " + state.tokens["alice"]}
        probes = [
            get(
                "owner_identity", url=base + "/identity", headers=owner_headers, actor=case.owner.id
            ),
            get(
                "actor_identity", url=base + "/identity", headers=actor_headers, actor=case.actor.id
            ),
            get("baseline", headers=owner_headers, actor=case.owner.id),
            get("control"),
            get("test", headers=actor_headers, actor=case.actor.id),
            get("repeat", headers=actor_headers, actor=case.actor.id),
        ]
    elif family == "auth_bypass":
        endpoint = f"{base}/{variant}/auth"
        metadata["resource"] = asdict(state.resources["alice"])
        probes = [
            get("baseline"),
            get("control", headers={"X-Lab-Bypass": "invalid"}),
            get("test", headers={"X-Lab-Bypass": "alice"}),
            get("repeat", headers={"X-Lab-Bypass": "alice"}),
        ]
    elif family == "jwt":

        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

        token = encode({"alg": "none"}) + "." + encode({"sub": "alice@test.local"}) + "."
        metadata["resource"] = asdict(state.resources["alice"])
        probes = [
            get("baseline"),
            get("control", headers={"Authorization": "Bearer invalid"}),
            get("test", headers={"Authorization": "Bearer " + token}),
            get("repeat", headers={"Authorization": "Bearer " + token}),
        ]
    elif family == "path_traversal":
        endpoint = f"{base}/{variant}/files"
        parameter = "path"
        metadata["file_marker"] = state.file_marker
        probes = [
            get(p, params={"path": path})
            for p, path in (
                ("baseline", "note.txt"),
                ("control", "missing.txt"),
                ("test", "../private.txt"),
                ("repeat", "../private.txt"),
            )
        ]
    elif family == "rce":
        endpoint = f"{base}/{variant}/command"
        parameter = "host"
        metadata.update(expected="27517", expected_repeat="30227")
        probes = [
            get(p, params={"host": value})
            for p, value in (
                ("baseline", "127.0.0.1"),
                ("control", "literal mul 113 239"),
                ("test", "127.0.0.1;mul 113 239"),
                ("repeat", "127.0.0.1;mul 127 238"),
            )
        ]
        metadata["expected"] = str(113 * 239)
        metadata["expected_repeat"] = str(127 * 238)
    elif family == "file_upload":
        endpoint = f"{base}/{variant}/upload"
        metadata["expected"] = str(127 * 239)
        probes = [
            get("baseline", url=base + "/safe/status/200"),
            get("control", url=base + "/safe/status/404"),
            Probe(
                "upload",
                endpoint,
                "POST",
                kwargs={"json": {"name": uuid4().hex + ".tmpl", "content": "{{127*239}}"}},
            ),
            get("test", url_from=("upload", "url")),
            get("repeat", url_from=("upload", "url")),
        ]
    elif family == "csrf":
        metadata.update(value="changed-" + uuid4().hex, value_repeat="repeated-" + uuid4().hex)
        actor = state.actors["alice"].id
        navigation = {
            "Origin": "https://external.test.invalid",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
        }
        probes = [
            Probe(
                "login",
                base + "/login",
                "POST",
                actor=actor,
                kwargs={"json": {"username": "alice", "password": "lab-only"}},
            ),
            get("baseline", url=base + "/state", actor=actor, cookie_from="login"),
            get("control", params={"value": "anonymous"}),
            get(
                "test",
                params={"value": metadata["value"]},
                actor=actor,
                cookie_from="login",
                headers=navigation,
            ),
            get("after", url=base + "/state", actor=actor, cookie_from="login"),
            get(
                "repeat",
                params={"value": metadata["value_repeat"]},
                actor=actor,
                cookie_from="login",
                headers=navigation,
            ),
            get("after_repeat", url=base + "/state", actor=actor, cookie_from="login"),
        ]
    elif family == "ssrf":
        endpoint = f"{base}/{variant}/fetch"
        parameter = "url"
        metadata.update(correlation=uuid4().hex, receiver_marker=state.receiver_marker)
        receiver = base + "/internal/" + metadata["correlation"]
        probes = [
            get("baseline"),
            get("control", params={"url": base + "/safe/status/200"}),
            get("test", params={"url": receiver}),
            get("repeat", params={"url": receiver}),
            get(
                "receiver",
                url=base + "/receiver-log",
                headers={"X-Lab-Receiver": state.receiver_key},
            ),
        ]
    else:
        raise ValueError("No lab plan for this vulnerability")
    return ValidationPlan(family, endpoint, tuple(probes), parameter, metadata)
