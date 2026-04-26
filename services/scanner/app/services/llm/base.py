"""Abstract base for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """Contract every LLM back-end must satisfy."""

    @abstractmethod
    async def generate_report(self, scan_data: dict) -> str:
        """Accept structured scan data and return a Markdown report string.

        The implementation must never invent findings that are not present in
        *scan_data*.  Secrets, tokens, cookies, and raw payloads must be
        stripped before sending to the model.
        """
