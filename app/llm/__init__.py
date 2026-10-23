"""Provider 工厂：默认 scripted（离线可复现）。"""
from __future__ import annotations

from .base import Decision, Provider, key_of
from .remote import OllamaProvider, OpenAICompatProvider
from .scripted import ScriptedProvider

__all__ = [
    "Decision",
    "Provider",
    "key_of",
    "ScriptedProvider",
    "OllamaProvider",
    "OpenAICompatProvider",
    "get_provider",
]


def get_provider(name: str = "scripted", **kwargs) -> Provider:
    name = (name or "scripted").lower()
    if name == "scripted":
        return ScriptedProvider()
    if name == "ollama":
        return OllamaProvider(**kwargs)
    if name in ("deepseek", "openai", "openai-compat"):
        return OpenAICompatProvider(**kwargs)
    raise ValueError(f"未知 provider: {name}（可选 scripted / ollama / deepseek）")
