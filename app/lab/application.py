"""Intentionally vulnerable synthetic fixture with paired secure endpoints.

The command and upload fixtures accept only bounded arithmetic canaries. They are
not general-purpose shells or upload handlers. Traversal stays inside a temp tree;
the SSRF receiver is pinned to the same loopback server. No third-party data is used.
"""

import asyncio
import base64
import hashlib
import hmac
import html
import json
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from jinja2.sandbox import SandboxedEnvironment

from app.core.authentication_context import Actor, AuthorizationCase, Resource
from app.validation.context import ValidationContext
from app.validation.safety.executor import AuthorizedExecutor, AuthorizedScope, ExecutionLimits


class LabState:
    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hunter-synthetic-lab-")
        self.root = Path(self.directory.name)
        (self.root / "public").mkdir()
        (self.root / "uploads").mkdir()
        (self.root / "public" / "note.txt").write_text("Public synthetic note", encoding="utf-8")
        self.file_marker = "private-file-" + uuid4().hex
        (self.root / "private.txt").write_text(self.file_marker, encoding="utf-8")
        self.actors = {
            "alice": Actor("alice@test.local", "user", "red"),
            "bob": Actor("bob@test.local", "user", "red"),
            "admin": Actor("admin@test.local", "admin", "red"),
            "charlie": Actor("charlie@test.local", "user", "blue"),
        }
        self.tokens = {name: "lab-" + uuid4().hex for name in self.actors}
        self.resources = {
            name: Resource(
                name,
                actor.id,
                actor.tenant,
                "private-" + uuid4().hex,
                required_role="admin" if name == "admin" else "",
            )
            for name, actor in self.actors.items()
        }
        self.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.database.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
        self.database.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
        self.receiver_url = ""
        self.receiver_key = uuid4().hex
        self.receiver_marker = "receiver-" + uuid4().hex
        self.receiver_requests = []
        self.values = {name: "initial" for name in self.actors}
        self.jwt_key = uuid4().hex.encode()
        self.requests = 0

    def actor_name(self, request: Request):
        token = request.headers.get("authorization", "").removeprefix(
            "Bearer "
        ) or request.cookies.get("sid", "")
        return next(
            (name for name, known in self.tokens.items() if hmac.compare_digest(token, known)), None
        )

    def resource_body(self, name):
        resource = self.resources[name]
        return {
            "id": resource.id,
            "owner": resource.owner,
            "private_marker": resource.private_marker,
        }

    def close(self):
        self.database.close()
        self.directory.cleanup()


def create_lab_app():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    state = LabState()
    app.state.lab = state
    semaphore = asyncio.Semaphore(4)

    @app.middleware("http")
    async def lab_boundary(request: Request, call_next):
        if request.client and request.client.host not in {"127.0.0.1", "::1"}:
            return JSONResponse({"error": "Loopback clients only"}, status_code=403)
        state.requests += 1
        if state.requests > 500:
            return JSONResponse({"error": "Fixture request budget exceeded"}, status_code=429)
        if len(await request.body()) > 8192:
            return JSONResponse({"error": "Fixture payload limit"}, status_code=413)
        try:
            async with asyncio.timeout(2), semaphore:
                return await call_next(request)
        except TimeoutError:
            return JSONResponse({"error": "Fixture timeout"}, status_code=408)

    @app.get("/data")
    async def data():
        return {
            "email": "alice@test.local",
            "username": "alice",
            "id": "synthetic-1",
            "document": "Synthetic internal test document",
            "configuration": {"api_key": "fake-lab-secret"},
            "openapi": "3.1.0",
            "sources": ["synthetic.js"],
            "debug": "Synthetic debug metadata",
            "backup": "synthetic-backup.sql",
            "metadata": {"environment": "lab"},
        }

    @app.get("/identity")
    async def identity(request: Request):
        name = state.actor_name(request)
        if not name:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        actor = state.actors[name]
        return {"subject": actor.id, "role": actor.role, "tenant": actor.tenant}

    @app.post("/login")
    async def login(request: Request):
        body = await request.json()
        name = body.get("username")
        if name not in state.actors or body.get("password") != "lab-only":
            return JSONResponse({"error": "invalid synthetic credentials"}, status_code=401)
        response = JSONResponse({"subject": state.actors[name].id})
        response.set_cookie("sid", state.tokens[name], httponly=True, samesite="lax")
        return response

    @app.get("/safe/status/{code}")
    async def status(code: int):
        if code not in {200, 301, 302, 400, 403, 404, 500}:
            code = 400
        return PlainTextResponse(
            "Generic error page" if code >= 400 else "Normal response",
            status_code=code,
            headers={"Location": "/safe/status/200"} if code in {301, 302} else {},
        )

    @app.get("/safe/slow")
    async def slow():
        await asyncio.sleep(0.03)
        return {"ok": True}

    @app.get("/safe/reflect")
    async def reflect(q: str = "", mode: str = "escaped"):
        if mode == "json":
            return {"q": q}
        if mode == "inert":
            return HTMLResponse("<textarea>" + q + "</textarea>")
        if mode == "comment":
            return HTMLResponse("<!--" + q + "-->")
        if mode == "csp":
            return HTMLResponse(q, headers={"Content-Security-Policy": "script-src 'none'"})
        return HTMLResponse(html.escape(q))

    @app.get("/{variant}/sqli")
    async def sqli(variant: str, id: str = "1"):
        if len(id) > 128:
            return JSONResponse({"error": "input limit"}, status_code=400)
        try:
            if variant == "vuln":
                rows = state.database.execute(
                    "SELECT id, username FROM users WHERE id = " + id
                ).fetchall()
            else:
                rows = state.database.execute(
                    "SELECT id, username FROM users WHERE id = ?", (id,)
                ).fetchall()
            return {"records": [{"id": row[0], "username": row[1]} for row in rows]}
        except sqlite3.Error:
            return JSONResponse({"error": "query rejected"}, status_code=400)

    @app.get("/{variant}/xss")
    async def xss(variant: str, q: str = ""):
        return HTMLResponse("<div>" + (q if variant == "vuln" else html.escape(q)) + "</div>")

    @app.get("/{variant}/authorization/{resource_name}")
    async def authorization(variant: str, resource_name: str, request: Request):
        name = state.actor_name(request)
        if not name:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if resource_name not in state.resources:
            return JSONResponse({"error": "missing"}, status_code=404)
        case = AuthorizationCase(
            state.actors[name], state.actors[resource_name], state.resources[resource_name]
        )
        if variant != "vuln" and case.expected_result != "ALLOW":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return state.resource_body(resource_name)

    @app.get("/{variant}/auth")
    async def auth(variant: str, request: Request):
        if state.actor_name(request) or (
            variant == "vuln" and request.headers.get("x-lab-bypass") == "alice"
        ):
            return state.resource_body("alice")
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    @app.get("/{variant}/jwt")
    async def jwt(variant: str, request: Request):
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        try:
            head, body, signature = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
            claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            expected = (
                base64.urlsafe_b64encode(
                    hmac.new(state.jwt_key, f"{head}.{body}".encode(), hashlib.sha256).digest()
                )
                .decode()
                .rstrip("=")
            )
            if variant != "vuln" and (
                header.get("alg") != "HS256" or not hmac.compare_digest(expected, signature)
            ):
                raise ValueError("invalid signature")
            if claims.get("sub") != "alice@test.local":
                raise ValueError("invalid subject")
            return state.resource_body("alice")
        except (ValueError, TypeError, KeyError):
            return JSONResponse({"error": "unauthorized"}, status_code=401)

    @app.get("/{variant}/files")
    async def files(variant: str, path: str = "note.txt"):
        target = (state.root / "public" / path).resolve()
        allowed = state.root if variant == "vuln" else state.root / "public"
        if not target.is_relative_to(allowed.resolve()) or not target.is_file():
            return PlainTextResponse("missing", status_code=404)
        return PlainTextResponse(target.read_text(encoding="utf-8"))

    @app.post("/{variant}/upload")
    async def upload(variant: str, request: Request):
        body = await request.json()
        name = body.get("name", "")
        content = body.get("content", "")
        if not re.fullmatch(r"[a-z0-9_-]{1,60}\.tmpl", name) or not re.fullmatch(
            r"\{\{[0-9]{1,4}\*[0-9]{1,4}\}\}", content
        ):
            return JSONResponse(
                {"error": "Only bounded arithmetic templates accepted"}, status_code=400
            )
        (state.root / "uploads" / name).write_text(content, encoding="utf-8")
        return {"url": str(request.base_url).rstrip("/") + f"/{variant}/uploads/{name}"}

    @app.get("/{variant}/uploads/{name}")
    async def uploaded(variant: str, name: str):
        if not re.fullmatch(r"[a-z0-9_-]{1,60}\.tmpl", name):
            return PlainTextResponse("missing", status_code=404)
        path = state.root / "uploads" / name
        if not path.exists():
            return PlainTextResponse("missing", status_code=404)
        template = path.read_text(encoding="utf-8")
        return PlainTextResponse(
            SandboxedEnvironment().from_string(template).render()
            if variant == "vuln"
            else template,
            headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.get("/{variant}/command")
    async def command(variant: str, host: str = "127.0.0.1"):
        match = re.fullmatch(r"127\.0\.0\.1;mul ([0-9]{1,4}) ([0-9]{1,4})", host)
        if variant != "vuln" or not match:
            return {"output": "ok"}
        a, b = map(int, match.groups())
        # A bounded synthetic command interpreter; never execute supplied shell/code.
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-c",
            f"print({a}*{b})",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), 1)
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        return {"output": stdout.decode().strip()}

    @app.get("/state")
    async def current_state(request: Request):
        name = state.actor_name(request)
        if not name:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return {"value": state.values[name]}

    @app.get("/{variant}/csrf")
    async def csrf(variant: str, request: Request, value: str = ""):
        name = state.actor_name(request)
        if not name:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if variant != "vuln":
            return JSONResponse({"error": "GET cannot mutate state"}, status_code=403)
        state.values[name] = value[:100]
        return {"changed": True}

    @app.get("/internal/{correlation}")
    async def receiver(correlation: str, request: Request):
        if request.headers.get("x-lab-receiver") != state.receiver_key:
            return JSONResponse({"error": "private receiver"}, status_code=403)
        state.receiver_requests.append({"correlation": correlation, "id": uuid4().hex})
        return {"marker": state.receiver_marker}

    @app.get("/receiver-log")
    async def receiver_log(request: Request):
        if request.headers.get("x-lab-receiver") != state.receiver_key:
            return JSONResponse({"error": "unauthorized"}, status_code=403)
        return {"requests": state.receiver_requests}

    @app.get("/{variant}/fetch")
    async def fetch(variant: str, url: str = ""):
        if variant != "vuln" or not url.startswith(state.receiver_url + "/internal/"):
            return {"accepted": url}
        scope = AuthorizedScope((state.receiver_url,), "synthetic same-server receiver")
        async with AuthorizedExecutor(scope, ExecutionLimits(requests=1)) as executor:
            run = ValidationContext(url, "ssrf")
            response = await executor.request(
                run, "receiver", "GET", url, headers={"X-Lab-Receiver": state.receiver_key}
            )
            return JSONResponse(response.json(), status_code=response.status)

    return app
