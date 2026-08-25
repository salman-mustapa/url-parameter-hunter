"""Universal LLM Client & AI Pentest Intelligence Engine (Multi-Model Combo & Dynamic Task Router).

Features:
1. Multi-Model Intelligent Combo Ensemble:
   - Reasoning & Hypotheses: ag/gemini-3.7-flash-high, ag/gemini-3.7-flash-medium, developer, ag/claude-sonnet-4-6
   - High-Throughput Payload Fuzzing: gemini/gemini-3.5-flash-lite, fast, developer
   - Code & JavaScript Reverse Engineering: developer, ag/gemini-3.7-flash-high, ag/gemini-3.7-flash-medium
   - Evidence Critic & Triaging: ag/gemini-3.7-flash-high, developer, assistant
   - Executive Reporting: ag/gemini-3.7-flash-high, developer, assistant
2. Automatic Cascading & Zero-Downtime Failover:
   - If the primary model for any task encounters a rate limit (429), times out, or fails,
     the client seamlessly cascades to the next best model in the pool in real time.
3. In-memory LRU cache for synthesized payloads (Zero tokens wasted on duplicate parameters).
4. Concurrency bounding with asyncio.Semaphore.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("intelligence.llm_client")

DEFAULT_SYSTEM_PROMPT = (
    "You are an offensive security AI agent for authorized security assessments. "
    "Provide concise, high-impact payloads, clear vulnerability reproduction steps, and root-cause analysis."
)

# Task-specialized multi-model cascade pools for NineRouter / OpenAI-Compatible endpoints
NINEROUTER_COMBO_POOLS: Dict[str, List[str]] = {
    "reasoning": [
        "gemini/gemini-3.5-flash-lite",
        "ag/gemini-3.7-flash-medium",
        "fast",
        "ag/claude-sonnet-4-6",
        "developer",
        "free",
    ],
    "hypothesis": [
        "gemini/gemini-3.5-flash-lite",
        "ag/gemini-3.7-flash-medium",
        "fast",
        "ag/claude-sonnet-4-6",
        "developer",
        "free",
    ],
    "payload_synthesis": [
        "gemini/gemini-3.5-flash-lite",
        "fast",
        "ag/gemini-3.7-flash-medium",
        "developer",
        "free",
    ],
    "code_analysis": [
        "developer",
        "gemini/gemini-3.5-flash-lite",
        "ag/gemini-3.7-flash-medium",
        "ag/claude-sonnet-4-6",
        "free",
    ],
    "evidence_critic": [
        "gemini/gemini-3.5-flash-lite",
        "ag/gemini-3.7-flash-medium",
        "ag/claude-sonnet-4-6",
        "developer",
        "free",
    ],
    "reporting": [
        "gemini/gemini-3.5-flash-lite",
        "ag/gemini-3.7-flash-medium",
        "ag/claude-sonnet-4-6",
        "developer",
        "free",
    ],
    "general": [
        "gemini/gemini-3.5-flash-lite",
        "fast",
        "ag/gemini-3.7-flash-medium",
        "ag/claude-sonnet-4-6",
        "developer",
        "free",
    ],
}


class LLMClient:
    """Universal asynchronous LLM client with Multi-Model Combo routing and cascading."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> None:
        self.base_url = (base_url or settings.llm_base_url).rstrip("/")
        self.api_key = (
            api_key
            or getattr(settings, "llm_api_key", "")
            or getattr(settings, "gemini_api_key", "")
            or getattr(settings, "openai_api_key", "")
            or getattr(settings, "ninerouter_api_key", "")
            or os.getenv("LLM_API_KEY", "")
            or os.getenv("GEMINI_API_KEY", "")
            or os.getenv("OPENAI_API_KEY", "")
            or os.getenv("NINEROUTER_API_KEY", "")
        )
        self.model = model or settings.llm_model
        self.temperature = temperature if temperature is not None else settings.llm_temperature
        self.max_tokens = max_tokens or settings.llm_max_tokens
        self._payload_cache: Dict[str, List[str]] = {}
        self._js_cache: Dict[str, Dict[str, Any]] = {}
        self._semaphore = asyncio.Semaphore(4)

    @property
    def is_configured(self) -> bool:
        """Checks if API key or local endpoint is configured."""
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key and len(self.api_key) > 4)

    async def test_connection(self) -> Dict[str, Any]:
        """Tests connection and verifies the active multi-model combo ensemble."""
        if not self.is_configured:
            return {
                "status": "unconfigured",
                "message": "AI Provider belum dikonfigurasi di .env",
                "provider": settings.llm_provider,
                "model": self.model,
            }

        try:
            resp_text = await self.chat(
                messages=[{"role": "user", "content": "Respond with 'PENTEST_AI_READY' and nothing else."}],
                max_tokens=64,
                task="general",
                timeout=8.0,
            )
            active_models = NINEROUTER_COMBO_POOLS["general"]
            return {
                "status": "connected",
                "mode": "Multi-Model Combo Ensemble (Auto-Cascade & Task Routing)",
                "message": f"Koneksi AI Combo Aktif & Siap ({len(active_models)} Model Pool)",
                "model": self.model,
                "base_url": self.base_url,
                "combo_pool": active_models,
                "task_routing": {
                    "reasoning": NINEROUTER_COMBO_POOLS["reasoning"][0],
                    "payload_synthesis": NINEROUTER_COMBO_POOLS["payload_synthesis"][0],
                    "code_analysis": NINEROUTER_COMBO_POOLS["code_analysis"][0],
                    "evidence_critic": NINEROUTER_COMBO_POOLS["evidence_critic"][0],
                    "reporting": NINEROUTER_COMBO_POOLS["reporting"][0],
                },
                "sample_reply": resp_text.strip()[:100],
            }
        except Exception as exc:
            return {
                "status": "error",
                "message": f"Gagal terhubung ke AI provider: {str(exc)}",
                "model": self.model,
                "base_url": self.base_url,
            }

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        task: str = "general",
        model: Optional[str] = None,
        timeout: float = 12.0,
    ) -> str:
        """Sends a chat completion request with automatic Multi-Model Combo cascading and failover."""
        async with self._semaphore:
            if "generativelanguage.googleapis.com" in self.base_url or (
                settings.llm_provider == "gemini" and not self.base_url.endswith("/v1")
            ):
                return await self._chat_gemini_native(messages, system_prompt, temperature, max_tokens, timeout)

            # Determine cascade candidate models
            if model:
                candidate_models = [model]
            elif self.model in ("combo", "auto", "ninerouter_combo", "all", "dynamic", "developer"):
                # Use specialized pool for the task with graceful fallback
                candidate_models = NINEROUTER_COMBO_POOLS.get(task, NINEROUTER_COMBO_POOLS["general"])
            else:
                # If specific model is configured, try it first, then fallback to combo pool
                candidate_models = [self.model] + [
                    m for m in NINEROUTER_COMBO_POOLS.get(task, NINEROUTER_COMBO_POOLS["general"])
                    if m != self.model
                ]

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
            if system_prompt:
                payload_messages.append({"role": "system", "content": system_prompt})
            else:
                payload_messages.append({"role": "system", "content": DEFAULT_SYSTEM_PROMPT})

            payload_messages.extend(messages)

            last_err = None
            for cand_model in candidate_models:
                body = {
                    "model": cand_model,
                    "messages": payload_messages,
                    "temperature": temperature if temperature is not None else self.temperature,
                    "max_tokens": max_tokens or min(self.max_tokens, 1024),
                    "stream": False,
                }

                try:
                    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                        resp = await client.post(endpoint, headers=headers, json=body)
                        if resp.status_code != 200:
                            err_body = resp.text[:150]
                            logger.warning(
                                "Model '%s' returned HTTP %d: %s. Cascading to next combo model...",
                                cand_model, resp.status_code, err_body
                            )
                            last_err = RuntimeError(f"HTTP {resp.status_code}: {err_body}")
                            continue

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

                        choices = data.get("choices", [])
                        if not choices:
                            logger.warning("Model '%s' returned empty choices. Cascading...", cand_model)
                            continue

                        msg = choices[0].get("message", {})
                        content = msg.get("content") or msg.get("reasoning") or choices[0].get("text") or ""
                        if content and content.strip():
                            logger.debug("Successfully executed task '%s' using model '%s'", task, cand_model)
                            return content
                except Exception as exc:
                    logger.warning("Model '%s' failed (%s). Cascading to next combo model...", cand_model, exc)
                    last_err = exc

            if last_err:
                raise last_err
            raise RuntimeError("All models in combo pool failed to respond.")

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

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.post(endpoint, json=body)
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API Error [{resp.status_code}]: {resp.text[:300]}")
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("No candidates returned by Gemini")
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts)

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


llm_client = LLMClient()
