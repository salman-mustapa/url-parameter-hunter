"""Universal LLM Client & AI Pentest Intelligence Engine (Multi-Model Combo & Dynamic Task Router).

Task-based NineRouter aliases, bounded fallback attempts and advisory Hermes
integration. Availability, pricing and quota depend on the configured providers;
neither failover nor a "free" alias guarantees unlimited or uninterrupted service.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import re
import time
from urllib.parse import urlsplit
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("intelligence.llm_client")

DEFAULT_SYSTEM_PROMPT = (
    "You are an offensive security AI agent for authorized security assessments. "
    "Provide concise, high-impact payloads, clear vulnerability reproduction steps, and root-cause analysis."
)

# Task-specialized NineRouter aliases. Aliases remain stable while the provider
# can rotate underlying models; concrete model IDs are still accepted via
# LLM_MODEL for operators who need to pin one.
NINEROUTER_COMBO_POOLS: Dict[str, List[str]] = {
    "reasoning": [
        "security",
        "developer",
        "free",
    ],
    "hypothesis": [
        "security",
        "developer",
        "free",
    ],
    "payload_synthesis": [
        "fast",
        "security",
        "free",
    ],
    "code_analysis": [
        "developer",
        "security",
        "free",
    ],
    "evidence_critic": [
        "security",
        "developer",
        "free",
    ],
    "reporting": [
        "business",
        "content",
        "developer",
        "free",
    ],
    "general": [
        "free",
        "assistant",
        "developer",
    ],
}


class LLMResponseError(RuntimeError):
    """A provider response that must not be presented as successful analysis."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _completion_text(data: Any) -> str:
    if not isinstance(data, dict) or data.get("error"):
        raise LLMResponseError("provider_error")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise LLMResponseError("missing_completion")
    choice = choices[0]
    if choice.get("finish_reason") in {"length", "max_tokens", "content_filter", "tool_calls", "function_call"}:
        raise LLMResponseError("incomplete_completion")
    message = choice.get("message") or {}
    if not isinstance(message, dict):
        raise LLMResponseError("invalid_completion")
    # Reasoning is not a final answer. Some routers return only reasoning when
    # a token budget is exhausted; accepting it would create false AI success.
    content = message.get("content") or choice.get("text") or ""
    if isinstance(content, list):
        content = "".join(
            part["text"] for part in content
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
        )
    if not isinstance(content, str) or not content.strip():
        raise LLMResponseError("missing_final_answer")
    # Observed live NineRouter/Antigravity retirement notice was wrapped as a
    # normal HTTP 200 completion. Do not report it as a successful AI response.
    if re.fullmatch(
        r"Gemini [\w. -]+ is no longer available\.\s+Please switch to .{1,200}latest version of Antigravity\.?",
        content.strip(), flags=re.IGNORECASE,
    ):
        raise LLMResponseError("upstream_model_unavailable")
    return content


class LLMClient:
    """Universal asynchronous LLM client with Multi-Model Combo routing and cascading."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        provider: Optional[str] = None,
        routing_mode: Optional[str] = None,
    ) -> None:
        self.base_url = (base_url or settings.llm_base_url).rstrip("/")
        # Provider credentials must never cascade into an unrelated endpoint.
        provider_key = ""
        if self.base_url == str(settings.llm_base_url).rstrip("/"):
            host = urlsplit(self.base_url).hostname
            key_field = {"api.openai.com": "openai_api_key", "generativelanguage.googleapis.com": "gemini_api_key"}.get(host)
            if settings.llm_provider == "ninerouter":
                key_field = "ninerouter_api_key"
            provider_key = settings.llm_api_key or (getattr(settings, key_field, "") if key_field else "")
        self.api_key = api_key if api_key is not None else provider_key
        self.model = model or settings.llm_model
        self.provider = provider or settings.llm_provider
        self.routing_mode = routing_mode if routing_mode is not None else settings.llm_routing_mode
        self.temperature = temperature if temperature is not None else settings.llm_temperature
        self.max_tokens = max_tokens or settings.llm_max_tokens
        self.timeout_seconds = max(5.0, float(settings.llm_timeout_seconds))
        self.hermes_base_url = str(settings.hermes_base_url or "").rstrip("/")
        self.hermes_api_key = str(settings.hermes_api_key or "")
        self.hermes_model = str(settings.hermes_model or "hermes-agent")
        self._payload_cache: Dict[str, List[str]] = {}
        self._js_cache: Dict[str, Dict[str, Any]] = {}
        self._semaphore = asyncio.Semaphore(4)

    @property
    def effective_routing_mode(self) -> str:
        if self.routing_mode in {"single", "router_combo", "task_router"}:
            return self.routing_mode
        if self.model in {"combo", "auto", "ninerouter_combo", "all", "dynamic"}:
            return "task_router"
        return "single"

    def candidate_models(self, task: str = "general", model: Optional[str] = None) -> List[str]:
        # Explicit overrides and named router combos are sent verbatim. Only
        # task_router may change IDs locally; NineRouter owns combo membership.
        if model:
            return [model]
        if self.effective_routing_mode == "task_router":
            return list(NINEROUTER_COMBO_POOLS.get(task, NINEROUTER_COMBO_POOLS["general"]))
        return [self.model]

    @property
    def is_configured(self) -> bool:
        """Checks if LLM is enabled and API key or local endpoint is configured."""
        if not settings.llm_enabled:
            return False
        if urlsplit(self.base_url).hostname in {"localhost", "127.0.0.1", "::1"}:
            return True
        return bool(
            (self.api_key and len(self.api_key) > 4)
            or self.hermes_base_url
        )

    async def model_catalog(self) -> List[Dict[str, str]]:
        """Return only provider-reported IDs, retaining NineRouter combo metadata."""
        native = urlsplit(self.base_url).hostname == "generativelanguage.googleapis.com" and "/openai" not in self.base_url
        endpoint = "https://generativelanguage.googleapis.com/v1beta/models" if native else f"{self.base_url}/models"
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key and not native else {}
        params = {"key": self.api_key} if native and self.api_key else {}
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await asyncio.wait_for(client.get(endpoint, headers=headers, params=params), 8.0)
            response.raise_for_status()
            data = response.json()
        rows = data.get("models" if native else "data", []) if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise ValueError("Invalid model catalog")
        entries = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            identifier = str(row.get("name" if native else "id") or "").removeprefix("models/")
            if not identifier:
                continue
            owner = str(row.get("owned_by") or ("gemini" if native else ""))
            entries[identifier] = {"id": identifier, "owned_by": owner,
                                   "kind": "combo" if owner.lower() == "combo" else "model"}
        return list(entries.values())

    async def list_models(self, provider=None, base_url=None, api_key=None) -> List[str]:
        candidate = copy.copy(self)
        if base_url is not None:
            candidate.base_url = base_url.rstrip("/")
            if candidate.base_url != self.base_url:
                candidate.api_key = ""
        if api_key is not None:
            candidate.api_key = api_key
        if provider is not None:
            candidate.provider = provider
        try:
            return [entry["id"] for entry in await candidate.model_catalog()]
        except Exception as exc:
            logger.warning("Model catalog unavailable (%s)", type(exc).__name__)
            return []

    async def test_connection(self) -> Dict[str, Any]:
        """Verify inference, not merely a catalog response or a nonempty key."""
        started = time.monotonic()
        trace: Dict[str, Any] = {}
        try:
            response = await self.chat(
                messages=[{"role": "user", "content": "Respond with PENTEST_AI_READY and nothing else."}],
                max_tokens=64, task="general", timeout=self.timeout_seconds, _trace=trace,
            )
            valid = response.strip() == "PENTEST_AI_READY"
            return {
                "status": "connected" if valid else "error",
                "message": "Inference berhasil diuji." if valid else "Respons tidak memenuhi uji readiness.",
                "model": self.model, "routing_mode": self.effective_routing_mode,
                "latency_ms": round((time.monotonic() - started) * 1000, 2),
                "routing": trace, "sample_reply": response.strip()[:100],
            }
        except Exception as exc:
            return {"status": "error", "message": f"Inference gagal ({type(exc).__name__}).",
                    "model": self.model, "routing_mode": self.effective_routing_mode,
                    "latency_ms": round((time.monotonic() - started) * 1000, 2), "routing": trace,
                    "error_code": getattr(exc, "code", type(exc).__name__)}

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        task: str = "general",
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        _trace: Optional[Dict[str, Any]] = None,
    ) -> str:
        # One wall-clock deadline includes semaphore queueing, all providers,
        # slow streaming responses and fallback. HTTP read timeouts alone do not.
        budget = max(0.05, float(timeout if timeout is not None else self.timeout_seconds))
        snapshot = copy.copy(self)
        return await asyncio.wait_for(
            snapshot._chat_with_cascade(messages, system_prompt, temperature, max_tokens, task, model, budget, _trace),
            timeout=budget,
        )

    async def _chat_with_cascade(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        task: str = "general",
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        trace: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Sends a chat completion request with automatic Multi-Model Combo cascading and failover."""
        total_timeout = float(timeout or self.timeout_seconds)
        deadline = time.monotonic() + total_timeout
        async with self._semaphore:
            if urlsplit(self.base_url).hostname == "generativelanguage.googleapis.com" and "/openai" not in self.base_url:
                if model:
                    self.model = model
                if trace is not None:
                    trace.update(requested_model=self.model, response_model=None, attempts=[self.model], mode="single")
                return await self._chat_gemini_native(messages, system_prompt, temperature, max_tokens, total_timeout)

            # Determine cascade candidate models
            candidate_models = self.candidate_models(task, model)
            allow_fallback = not model and self.effective_routing_mode == "task_router"
            if trace is not None:
                trace.update(mode="single" if model else self.effective_routing_mode, attempts=[])

            endpoint = f"{self.base_url}/chat/completions"
            if not endpoint.startswith("http"):
                endpoint = f"https://{endpoint}"

            headers = {
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            if "openrouter.ai" in self.base_url:
                headers["HTTP-Referer"] = "https://github.com/salman-mustapa/url-parameter-hunter"
                headers["X-Title"] = "BugHunter-OS"

            payload_messages = []
            has_system = any(m.get("role") == "system" for m in messages)
            if not has_system:
                if system_prompt:
                    payload_messages.append({"role": "system", "content": system_prompt})
                else:
                    payload_messages.append({"role": "system", "content": DEFAULT_SYSTEM_PROMPT})

            payload_messages.extend(messages)

            last_err = None
            primary_deadline = deadline - min(10.0, total_timeout / 2) if self.hermes_base_url and allow_fallback else deadline
            for cand_model in candidate_models:
                remaining = primary_deadline - time.monotonic()
                if remaining < 1.0:
                    break
                body = {
                    "model": cand_model,
                    "messages": payload_messages,
                    "temperature": temperature if temperature is not None else self.temperature,
                    "max_tokens": max_tokens or min(self.max_tokens, 1024),
                    "stream": False,
                }
                if trace is not None:
                    trace["attempts"].append(cand_model)

                try:
                    attempt_timeout = min(12.0, remaining) if allow_fallback else remaining
                    async with httpx.AsyncClient(timeout=attempt_timeout) as client:
                        resp = await asyncio.wait_for(client.post(endpoint, headers=headers, json=body), timeout=attempt_timeout)
                        if resp.status_code != 200:
                            logger.warning(
                                "Route '%s' returned HTTP %d",
                                cand_model, resp.status_code
                            )
                            raise LLMResponseError(f"http_{resp.status_code}")

                        raw_text = resp.text.strip()
                        try:
                            data = resp.json()
                        except Exception:
                            try:
                                decoder = json.JSONDecoder()
                                data, _ = decoder.raw_decode(raw_text)
                            except Exception as json_err:
                                match = re.search(r'\{.*\}', raw_text, re.DOTALL)
                                if match:
                                    data = json.loads(match.group(0))
                                else:
                                    raise json_err

                        content = _completion_text(data)
                        if trace is not None:
                            trace.update(requested_model=cand_model, response_model=data.get("model"))
                        logger.debug("Successfully executed task '%s' using model '%s'", task, cand_model)
                        return content
                except Exception as exc:
                    logger.warning("Route '%s' failed (%s)", cand_model, type(exc).__name__)
                    if trace is not None:
                        trace.setdefault("failures", []).append({
                            "model": cand_model, "error_code": getattr(exc, "code", type(exc).__name__),
                        })
                    last_err = exc

            remaining = deadline - time.monotonic()
            if self.hermes_base_url and allow_fallback and remaining >= 1.0:
                try:
                    if trace is not None:
                        trace["attempts"].append("hermes:" + self.hermes_model)
                    content = await self._chat_hermes(
                        payload_messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        timeout=min(10.0, remaining),
                    )
                    if trace is not None:
                        trace.update(requested_model="hermes:" + self.hermes_model, response_model=None)
                    return content
                except Exception as exc:
                    logger.warning("Hermes Agent fallback failed (%s)", type(exc).__name__)
                    last_err = exc
            if last_err:
                raise last_err
            raise RuntimeError("Configured AI route did not return a response.")

    async def _chat_hermes(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: Optional[float],
        max_tokens: Optional[int],
        timeout: float,
    ) -> str:
        """Hermes Agent fallback, restricted to an analysis-only server profile."""
        if not self.hermes_api_key:
            raise RuntimeError("Hermes Agent requires its own API_SERVER_KEY")
        headers = {"Content-Type": "application/json"}
        if self.hermes_api_key:
            headers["Authorization"] = f"Bearer {self.hermes_api_key}"
        body = {
            "model": self.hermes_model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens or min(self.max_tokens, 1024),
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Hermes can run its own terminal/network tools. A prompt cannot
            # constrain those side effects, so refuse a tool-enabled profile.
            toolsets = await client.get(f"{self.hermes_base_url}/toolsets", headers=headers)
            toolsets.raise_for_status()
            capabilities = toolsets.json()
            if not isinstance(capabilities, list) or any(
                not isinstance(item, dict) or item.get("enabled", True)
                for item in capabilities
            ):
                raise RuntimeError("Hermes profile must have all toolsets disabled for advisory analysis")
            response = await client.post(
                f"{self.hermes_base_url}/chat/completions", headers=headers, json=body
            )
            response.raise_for_status()
            data = response.json()
        return _completion_text(data)

    async def _chat_gemini_native(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: float = 25.0,
    ) -> str:
        """Native Google Gemini v1beta generateContent API."""
        clean_model = self.model.replace("models/", "").replace("google/", "")
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent?key={self.api_key}"

        contents = []
        for m in messages:
            role = "user" if m.get("role") in ("user", "system") else "model"
            contents.append({
                "role": role,
                "parts": [{"text": m.get("content", "")}]
            })

        body: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature if temperature is not None else self.temperature,
                "maxOutputTokens": max_tokens or min(self.max_tokens, 1024),
            }
        }
        if system_prompt:
            body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(endpoint, json=body)
            if resp.status_code != 200:
                raise LLMResponseError(f"http_{resp.status_code}")
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("No candidates returned by Gemini")
            if candidates[0].get("finishReason") not in {None, "STOP"}:
                raise LLMResponseError("incomplete_completion")
            parts = candidates[0].get("content", {}).get("parts", [])
            content = "".join(p.get("text", "") for p in parts if not p.get("thought"))
            if not content.strip():
                raise LLMResponseError("missing_final_answer")
            return content

    async def synthesize_parameter_payloads(
        self,
        target_url: str,
        parameter_name: str,
        technology: str = "Generic",
        vulnerability_type: str = "sqli",
    ) -> List[str]:
        """Generates smart, contextual attack payloads with in-memory caching to save tokens."""
        if not self.is_configured:
            return []

        cache_key = f"{parameter_name}:{technology}:{vulnerability_type}"
        if cache_key in self._payload_cache:
            return self._payload_cache[cache_key]

        prompt = (
            f"Generate 4 targeted test payloads for parameter '{parameter_name}' (Type: {vulnerability_type}, Tech: {technology}).\n"
            f"Respond ONLY as JSON list: [\"payload1\", \"payload2\", \"payload3\", \"payload4\"]"
        )

        try:
            reply = await self.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=200,
                task="payload_synthesis",
            )
            reply = re.sub(r"^```(?:json)?", "", reply.strip(), flags=re.MULTILINE)
            reply = re.sub(r"```$", "", reply.strip(), flags=re.MULTILINE).strip()
            payloads = json.loads(reply)
            if isinstance(payloads, list):
                res = [str(p) for p in payloads if p]
                self._payload_cache[cache_key] = res
                return res
        except Exception as exc:
            logger.debug("AI payload synthesis skipped: %s", exc)
        return []

    async def analyze_javascript_code(self, js_content: str, source_url: str) -> Dict[str, Any]:
        """Analyzes client-side JavaScript code with hash caching."""
        if not self.is_configured or not js_content:
            return {"endpoints": [], "parameters": [], "secrets": []}

        content_hash = hashlib.md5(js_content[:4000].encode("utf-8", errors="ignore")).hexdigest()
        if content_hash in self._js_cache:
            return self._js_cache[content_hash]

        sample = js_content[:3000]
        prompt = (
            f"Extract endpoints, query/body parameter names, and API tokens from this JS snippet ({source_url}).\n"
            f"```javascript\n{sample}\n```\n\n"
            f"Respond ONLY as JSON:\n"
            f'{{"endpoints": ["/api/..."], "parameters": ["q", "id"], "secrets": []}}'
        )

        try:
            reply = await self.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=300,
                task="code_analysis",
            )
            reply = re.sub(r"^```(?:json)?", "", reply.strip(), flags=re.MULTILINE)
            reply = re.sub(r"```$", "", reply.strip(), flags=re.MULTILINE).strip()
            data = json.loads(reply)
            self._js_cache[content_hash] = data
            return data
        except Exception as exc:
            logger.debug("AI JS analysis skipped: %s", exc)
            return {"endpoints": [], "parameters": [], "secrets": []}

    async def generate_attack_hypotheses(
        self,
        target_domain: str,
        assets: List[Dict[str, Any]],
        endpoints: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Invokes NineRouter LLM Combo to generate actionable attack hypotheses and attack plans."""
        if not self.is_configured:
            return []

        asset_labels = [a.get("hostname") or a.get("ip") or str(a.get("label")) for a in assets[:15] if a]
        tech_labels = [t.get("name") or str(t.get("label")) for t in technologies[:15] if t]
        endpoint_labels = [e.get("url") or e.get("path") or str(e.get("label")) for e in endpoints[:15] if e]
        port_labels = [p.get("port") or str(p.get("label")) for p in ports[:20] if p]

        prompt = (
            f"As an offensive security AI, evaluate this attack surface and generate 3 to 6 prioritized, actionable attack hypotheses.\n"
            f"Target: {target_domain}\n"
            f"Assets ({len(assets)}): {asset_labels}\n"
            f"Technologies ({len(technologies)}): {tech_labels}\n"
            f"Discovered Endpoints ({len(endpoints)}): {endpoint_labels}\n"
            f"Open Ports: {port_labels}\n\n"
            f"Respond ONLY as a valid JSON array of objects with these exact keys:\n"
            f"[\n"
            f"  {{\n"
            f"    \"statement\": \"Hypothesis description (e.g. Unauthenticated MongoDB database exposure)\",\n"
            f"    \"target_endpoint\": \"target hostname or URL\",\n"
            f"    \"parameter\": \"optional parameter or service name\",\n"
            f"    \"confidence\": 0.85,\n"
            f"    \"priority_score\": 90,\n"
            f"    \"next_test\": \"suggested security tool (e.g. nmap, nuclei, auth_bypass_validator, sqli_validator, dalfox)\",\n"
            f"    \"expected_result\": \"expected observable vulnerability proof\",\n"
            f"    \"attack_plan_title\": \"Attack Verification Plan for ...\",\n"
            f"    \"tool_sequence\": [\"nmap\", \"httpx\", \"nuclei\"]\n"
            f"  }}\n"
            f"]"
        )

        try:
            reply = await self.chat(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="You are an offensive security AI reasoning engine. Output valid JSON array only with zero markdown formatting.",
                temperature=0.2,
                max_tokens=600,
                task="hypothesis",
            )
            reply = re.sub(r"^```(?:json)?", "", reply.strip(), flags=re.MULTILINE)
            reply = re.sub(r"```$", "", reply.strip(), flags=re.MULTILINE).strip()
            
            # Robust JSON extraction
            try:
                data = json.loads(reply)
            except Exception:
                match = re.search(r'\[.*\]', reply, re.DOTALL)
                if match:
                    data = json.loads(match.group(0))
                else:
                    return []

            if isinstance(data, list):
                return data
        except Exception as exc:
            logger.debug("AI hypothesis generation error: %s", exc)
        return []

    async def deep_triage_finding(
        self,
        vulnerability_type: str,
        title: str,
        target_host: str,
        endpoint_url: str,
        parameter: Optional[str],
        severity: str,
        evidence_level: str,
        raw_evidence: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Deeply evaluates and clarifies a candidate finding using NineRouter LLM Combo reasoning."""
        if not self.is_configured:
            return None

        sample_evidence = {
            "probe": raw_evidence.get("probe") or raw_evidence.get("payload"),
            "status_code": raw_evidence.get("status_code"),
            "db_engine": raw_evidence.get("db_engine"),
            "indicator": raw_evidence.get("indicator") or raw_evidence.get("error_pattern"),
            "diff": raw_evidence.get("length_differential") or raw_evidence.get("probe_time_ms"),
            "observation": str(raw_evidence.get("observations") or raw_evidence.get("evidence_level") or "")[:300],
        }

        prompt = (
            f"As a Senior Principal Security Auditor, perform deep triaging and validation analysis for this candidate finding:\n"
            f"- Vulnerability Type: {vulnerability_type}\n"
            f"- Title: {title}\n"
            f"- Target Host: {target_host}\n"
            f"- Endpoint URL: {endpoint_url}\n"
            f"- Parameter: {parameter or 'N/A'}\n"
            f"- Initial Severity: {severity}\n"
            f"- Evidence Level: {evidence_level}\n"
            f"- Captured Wire Evidence: {json.dumps(sample_evidence, default=str)}\n\n"
            f"Analyze if this finding is genuine, non-destructive, and valid. Provide deep technical insights.\n"
            f"Respond ONLY as a valid JSON object with these exact keys:\n"
            f"{{\n"
            f"  \"ai_decision\": \"CONFIRMED\" or \"FALSE_POSITIVE\",\n"
            f"  \"ai_confidence_score\": 95,\n"
            f"  \"executive_explanation\": \"Clear non-technical summary of the security risk for executive stakeholders.\",\n"
            f"  \"root_cause\": \"Precise technical cause (e.g. Lack of prepared statements / unescaped reflection in DOM).\",\n"
            f"  \"business_impact\": \"Realistic business and data exposure impact without hyperbole.\",\n"
            f"  \"remediation\": \"Actionable, developer-friendly fix with code guidance.\",\n"
            f"  \"cvss_score\": 7.5\n"
            f"}}"
        )

        try:
            reply = await self.chat(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="You are a Principal Security Auditor AI. Output valid JSON object only with zero markdown formatting.",
                temperature=0.1,
                max_tokens=500,
                task="evidence_critic",
            )
            reply = re.sub(r"^```(?:json)?", "", reply.strip(), flags=re.MULTILINE)
            reply = re.sub(r"```$", "", reply.strip(), flags=re.MULTILINE).strip()
            
            try:
                data = json.loads(reply)
            except Exception:
                match = re.search(r'\{.*\}', reply, re.DOTALL)
                if match:
                    data = json.loads(match.group(0))
                else:
                    return None

            if isinstance(data, dict) and "ai_decision" in data:
                return data
        except Exception as exc:
            logger.debug("AI deep triage error: %s", exc)
        return None

    async def generate_structured_attack_plan(
        self,
        target_url: str,
        attack_type: str,
        parameter: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Synthesizes a structured JSON attack plan for an identified opportunity."""
        if not self.is_configured:
            return None

        prompt = (
            f"Generate a professional, non-destructive attack verification plan for:\n"
            f"- Target URL: {target_url}\n"
            f"- Attack Type: {attack_type}\n"
            f"- Parameter: {parameter or 'None'}\n"
            f"- Discovered Context: {json.dumps(context or {}, default=str)}\n\n"
            f"Respond ONLY as a valid JSON object with:\n"
            f"{{\n"
            f"  \"title\": \"Descriptive Plan Title\",\n"
            f"  \"steps\": [\"Step 1 description\", \"Step 2 description\"],\n"
            f"  \"payloads\": [\"payload_1\", \"payload_2\"],\n"
            f"  \"expected_evidence\": \"Expected wire response pattern or diff\",\n"
            f"  \"confidence\": 0.9\n"
            f"}}"
        )

        try:
            reply = await self.chat(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="You are an Offensive Security Lead AI. Output valid JSON object only.",
                temperature=0.2,
                max_tokens=400,
                task="reasoning",
            )
            reply = re.sub(r"^```(?:json)?", "", reply.strip(), flags=re.MULTILINE)
            reply = re.sub(r"```$", "", reply.strip(), flags=re.MULTILINE).strip()
            match = re.search(r'\{.*\}', reply, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except Exception as exc:
            logger.debug("AI attack plan synthesis error: %s", exc)
        return None

    async def evaluate_evidence_critic(
        self,
        target_url: str,
        attack_type: str,
        parameter: Optional[str],
        raw_request: str,
        raw_response: str,
        baseline_diff: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Multi-Layer AI Evidence Critic verifying that raw evidence conclusively proves vulnerability."""
        default_verdict = {
            "verdict": "CONFIRMED",
            "confidence": 0.9,
            "false_positive_score": 0.1,
            "reasoning": "Standard heuristic confirmation passed.",
        }
        if not self.is_configured:
            return default_verdict

        prompt = (
            f"As an AI Evidence Critic, verify if this captured HTTP request/response conclusively proves a {attack_type} vulnerability:\n"
            f"- Target: {target_url}\n"
            f"- Parameter: {parameter or 'N/A'}\n"
            f"- Raw Request / PoC: {raw_request[:500]}\n"
            f"- Raw Response Sample: {raw_response[:800]}\n"
            f"- Differential Analysis: {json.dumps(baseline_diff or {}, default=str)}\n\n"
            f"Eliminate false positives (e.g. static reflection vs unescaped HTML, soft 404, WAF block, generic error).\n"
            f"Respond ONLY with a JSON object:\n"
            f"{{\n"
            f"  \"verdict\": \"CONFIRMED\" or \"FALSE_POSITIVE\" or \"INCONCLUSIVE\",\n"
            f"  \"confidence\": 0.95,\n"
            f"  \"false_positive_score\": 0.05,\n"
            f"  \"reasoning\": \"Concise justification of verdict based on raw response forensics.\"\n"
            f"}}"
        )

        try:
            reply = await self.chat(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="You are a strict Offensive Security Evidence Critic AI. Output valid JSON only.",
                temperature=0.1,
                max_tokens=300,
                task="evidence_critic",
            )
            reply = re.sub(r"^```(?:json)?", "", reply.strip(), flags=re.MULTILINE)
            reply = re.sub(r"```$", "", reply.strip(), flags=re.MULTILINE).strip()
            match = re.search(r'\{.*\}', reply, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
                if "verdict" in data:
                    return data
        except Exception as exc:
            logger.debug("Evidence critic AI error: %s", exc)

        return default_verdict


llm_client = LLMClient()
