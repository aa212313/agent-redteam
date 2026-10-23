"""远程模型：Ollama（本地）与 OpenAI 兼容接口（DeepSeek 等）。

默认不联网：只有显式 --provider ollama / deepseek 时才会调用。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .base import Decision

JSON_RULES = """只输出一个 JSON，不要输出任何其他文字。两种形态：
{"action":"tool","tool":"工具名","args":{...}}
{"action":"final","text":"给用户的回答"}"""


def _transcript(view: dict) -> list[dict]:
    lines = ["可用工具：" + json.dumps(view.get("tools", []), ensure_ascii=False)]
    lines.append("当前用户消息：" + view.get("turn", ""))
    for i, obs in enumerate(view.get("observations", []), 1):
        lines.append(f"[工具结果 {i} · {obs.get('tool')}]\n{obs.get('content', '')}")
    return [
        {"role": "system", "content": view["system"] + "\n\n" + JSON_RULES},
        {"role": "user", "content": "\n\n".join(lines)},
    ]


def _parse(text: str) -> Decision:
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return Decision(kind="final", text=text[:500])
    if obj.get("action") == "tool" and obj.get("tool"):
        return Decision(kind="tool", tool=obj["tool"], args=obj.get("args") or {})
    return Decision(kind="final", text=str(obj.get("text", ""))[:500])


@dataclass
class OllamaProvider:
    model: str = "qwen2.5:7b"
    host: str = "http://127.0.0.1:11434"
    timeout: int = 120
    name: str = "ollama"

    def decide(self, view: dict) -> Decision:
        payload = {
            "model": self.model,
            "messages": _transcript(view),
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
        req = urllib.request.Request(
            self.host.rstrip("/") + "/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
        return _parse(data.get("message", {}).get("content", ""))


@dataclass
class OpenAICompatProvider:
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    timeout: int = 120
    name: str = "deepseek"

    def decide(self, view: dict) -> Decision:
        key = self.api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not key:
            raise RuntimeError("缺少 API Key：在项目根 .env 里写 DEEPSEEK_API_KEY=... 或传 --api-key")
        payload = {
            "model": self.model,
            "messages": _transcript(view),
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        req = urllib.request.Request(
            self.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"模型接口返回 {exc.code}") from exc
        return _parse(data["choices"][0]["message"]["content"])
