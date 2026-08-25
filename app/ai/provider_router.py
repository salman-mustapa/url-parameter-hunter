"""AI Provider Router & Model Categorization (V12 §28, §29).

Decouples task categories from hardcoded AI models:
- QUICK, GENERAL, DEEP_REASONING, SECURITY_RESEARCH, CODE_ANALYSIS, VISION, REPORTING, PLANNING, LOCAL_PRIVATE.
- Dynamic provider failover: If a cloud provider is unavailable or ratelimited, falls back to the deterministic local heuristic engine.
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Any, Dict, Optional

from app.ai.gateway import (
    BaseLLMProvider,
    GeminiProvider,
    GroqProvider,
    OpenRouterLLMProvider,
    ZeroResourceHeuristicProvider,
    ai_gateway,
)

logger = logging.getLogger("ai.provider_router")


class ModelCategory(str, Enum):
    QUICK = "quick"                      # Ultra-fast triage (<50ms)
    GENERAL = "general"                  # Standard assessment reasoning
    DEEP_REASONING = "deep_reasoning"    # Complex attack-path / chained exploit logic
    SECURITY_RESEARCH = "security_research" # CVE matching, KEV correlation
    CODE_ANALYSIS = "code_analysis"      # JS bundle decompilation & AST analysis
    VISION = "vision"                    # Screenshot & visual evidence verification
    REPORTING = "reporting"              # Executive & technical report drafting
    PLANNING = "planning"                # Dynamic investigation planning
    LOCAL_PRIVATE = "local_private"      # Strict zero-cloud privacy (local AST heuristics)


class AIProviderRouter:
    """Routes AI task categories to appropriate providers with automatic fallback."""

    def __init__(self) -> None:
        self.heuristic_fallback = ZeroResourceHeuristicProvider()

    def route_request(
        self,
        category: ModelCategory,
        privacy_strict: bool = False,
    ) -> BaseLLMProvider:
        """Selects the best available AI provider based on category and privacy requirements."""
        if privacy_strict or category == ModelCategory.LOCAL_PRIVATE:
            return self.heuristic_fallback

        # Check configured cloud providers
        active_provider = ai_gateway.active_provider

        # If cloud provider is available and not disabled
        if active_provider and active_provider.is_available():
            return active_provider

        # Fallback to zero-resource heuristic engine
        return self.heuristic_fallback

    async def execute_task(
        self,
        category: ModelCategory,
        prompt: str,
        system: Optional[str] = None,
        json_mode: bool = False,
        privacy_strict: bool = False,
    ) -> Dict[str, Any]:
        """Executes task with automatic graceful fallback on exception or ratelimit."""
        provider = self.route_request(category, privacy_strict=privacy_strict)
        try:
            res = await provider.complete(prompt, system=system, json_mode=json_mode)
            return res
        except Exception as exc:
            logger.warning("Primary AI Provider (%s) failed: %s. Engaging heuristic fallback.", type(provider).__name__, exc)
            fallback_res = await self.heuristic_fallback.complete(prompt, system=system, json_mode=json_mode)
            fallback_res["fallback_triggered"] = True
            fallback_res["original_error"] = str(exc)
            return fallback_res


ai_provider_router = AIProviderRouter()
