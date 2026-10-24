"""远程模型：Ollama（本地）与 OpenAI 兼容接口。

默认不联网：只有显式 --provider ollama / deepseek 时才会调用。
针对小参数/中转模型做了三处加固：
- JSON 解析失败自动重试一次（附「只输出 JSON」的纠正提示）
- 中转不支持 response_format 时自动去掉该字段重试
- 统计调用次数与 token，供报告核算成本
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

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


def _parse_json(text: str) -> Decision | None:
    text = (text or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    if obj.get("action") == "tool" and obj.get("tool"):
        args = obj.get("args")
        return Decision(kind="tool", tool=str(obj["tool"]), args=args if isinstance(args, dict) else {})
    if obj.get("action") == "final":
        return Decision(kind="final", text=str(obj.get("text", ""))[:600])
    if "tool" in obj and "args" in obj:  # 宽松兜底
        return Decision(kind="tool", tool=str(obj["tool"]), args=obj["args"] if isinstance(obj["args"], dict) else {})
    if "text" in obj:
        return Decision(kind="final", text=str(obj["text"])[:600])
    return None


@dataclass
class OllamaProvider:
    model: str = "qwen2.5:7b"
    host: str = "http://127.0.0.1:11434"
    timeout: int = 120
    name: str = "ollama"
    usage: dict = field(default_factory=lambda: {"calls": 0, "prompt": 0, "completion": 0, "retries": 0})

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
        self.usage["calls"] += 1
        return _parse_json(data.get("message", {}).get("content", "")) or Decision(
            kind="final", text="（模型输出无法解析）"
        )


@dataclass
class OpenAICompatProvider:
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    timeout: int = 120
    name: str = "deepseek"
    retries: int = 6
    max_tokens: int = 700
    usage: dict = field(default_factory=lambda: {"calls": 0, "prompt": 0, "completion": 0, "retries": 0})
    _json_mode: bool = True

    def _post(self, messages: list[dict]) -> str:
        key = self.api_key or os.environ.get("DEEPSEEK_API_KEY", "") or os.environ.get("LLM_API_KEY", "")
        if not key:
            raise RuntimeError("缺少 API Key：在项目根 .env 里写 LLM_API_KEY=... ")

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(
                self.base_url.rstrip("/") + "/chat/completions",
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode())
                usage = data.get("usage") or {}
                self.usage["calls"] += 1
                self.usage["prompt"] += int(usage.get("prompt_tokens") or 0)
                self.usage["completion"] += int(usage.get("completion_tokens") or 0)
                return data["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as exc:
                body = exc.read()[:300].decode("utf-8", "replace")
                # 中转不支持 response_format：去掉后重试一次
                if exc.code == 400 and "response_format" in body and self._json_mode:
                    self._json_mode = False
                    payload.pop("response_format", None)
                    self.usage["retries"] += 1
                    continue
                last_error = RuntimeError(f"HTTP {exc.code}: {body[:160]}")
                if exc.code in (401, 403):
                    # 中转把「频率超限」也报成 401，等久一点再试
                    time.sleep(12 + 6 * attempt)
                    self.usage["retries"] += 1
                    continue
            except Exception as exc:  # noqa: BLE001 网络抖动 / 超时
                last_error = exc
            time.sleep(0.8 + 0.6 * attempt)
            self.usage["retries"] += 1
        raise RuntimeError(f"模型调用失败：{last_error}")

    def decide(self, view: dict) -> Decision:
        messages = _transcript(view)
        raw = self._post(messages)
        parsed = _parse_json(raw)
        if parsed is not None:
            return parsed
        # 解析失败：给一次纠正机会（小模型偶发输出多余文字）
        self.usage["retries"] += 1
        repair = messages + [
            {"role": "assistant", "content": raw[:400]},
            {"role": "user", "content": "上面的输出不是合法 JSON。请只输出一个 JSON 对象，不要任何解释。"},
        ]
        raw2 = self._post(repair)
        parsed = _parse_json(raw2)
        if parsed is not None:
            return parsed
        return Decision(kind="final", text=(raw2 or raw)[:400])
