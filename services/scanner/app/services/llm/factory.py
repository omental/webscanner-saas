"""Factory for obtaining an LLM provider instance."""

from __future__ import annotations

from app.services.llm.base import BaseLLMProvider
from app.services.llm.openrouter_provider import OpenRouterProvider

# Currently only OpenRouter is supported.  When more backends are added,
# extend this factory to inspect settings and return the right provider.

_instance: BaseLLMProvider | None = None


def get_llm_provider() -> BaseLLMProvider:
    """Return a singleton LLM provider.

    Raises ``RuntimeError`` if the provider cannot be initialised
    (e.g. missing API key).
    """
    global _instance  # noqa: PLW0603
    if _instance is None:
        _instance = OpenRouterProvider()
    return _instance
