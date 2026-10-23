"""配置加载：conf/*.yaml + 项目根 .env，全部相对路径解析。

约定：
- 所有 yaml 里的相对路径都以项目根为基准；
- 密钥只从环境变量或 .env 读取，不写进 yaml、不进仓库。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.common.paths import CONF_DIR, ROOT


def load_dotenv(path: Path | None = None) -> None:
    """极简 .env 读取（不覆盖已存在的环境变量）。"""
    env_file = path or (ROOT / ".env")
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@dataclass
class DefenseConfig:
    layers: dict[str, bool]
    contacts: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    allowed_tables: set[str] = field(default_factory=set)
    max_body_chars: int = 2000


@dataclass
class EvalConfig:
    max_steps: int
    benign_path: Path
    matrix: dict[str, dict[str, bool]]
    reports_dir: Path
    db_path: Path
    web_data: Path


@dataclass
class AppConfig:
    provider: str
    max_steps: int
    ollama: dict
    deepseek: dict
    defense: DefenseConfig
    evaluation: EvalConfig
    api_key: str = ""

    def provider_kwargs(self) -> dict:
        if self.provider == "ollama":
            return {
                "model": self.ollama.get("model", "qwen2.5:7b"),
                "host": self.ollama.get("host", "http://127.0.0.1:11434"),
                "timeout": int(self.ollama.get("timeout", 120)),
            }
        if self.provider in ("deepseek", "openai", "openai-compat"):
            return {
                "model": self.deepseek.get("model", "deepseek-chat"),
                "base_url": self.deepseek.get("base_url", "https://api.deepseek.com/v1"),
                "api_key": self.api_key,
                "timeout": int(self.deepseek.get("timeout", 120)),
            }
        return {}


def _read_yaml(name: str) -> dict:
    path = CONF_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"缺少配置文件：{path}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (ROOT / path)


def load_config() -> AppConfig:
    load_dotenv()
    agent_cfg = _read_yaml("agent.yaml")
    defense_cfg = _read_yaml("defense.yaml")
    eval_cfg = _read_yaml("evaluation.yaml")

    layers = {key: bool(val) for key, val in (defense_cfg.get("layers") or {}).items()}
    defense = DefenseConfig(
        layers=layers,
        contacts=set(defense_cfg.get("contacts") or []),
        hosts=set(defense_cfg.get("hosts") or []),
        allowed_tables={t.lower() for t in (defense_cfg.get("allowed_tables") or [])},
        max_body_chars=int(defense_cfg.get("max_body_chars", 2000)),
    )

    outputs = eval_cfg.get("outputs") or {}
    evaluation = EvalConfig(
        max_steps=int(eval_cfg.get("max_steps", agent_cfg.get("max_steps", 6))),
        benign_path=_resolve(eval_cfg.get("benign_task", "cases/benign.yaml")),
        matrix=eval_cfg.get("matrix") or {},
        reports_dir=_resolve(outputs.get("reports", "reports")),
        db_path=_resolve(outputs.get("db", "reports/runs.db")),
        web_data=_resolve(outputs.get("web_data", "web/data.js")),
    )

    deepseek_cfg = agent_cfg.get("deepseek") or {}
    api_key = os.environ.get(deepseek_cfg.get("api_key_env", "DEEPSEEK_API_KEY"), "")

    return AppConfig(
        provider=agent_cfg.get("provider", "scripted"),
        max_steps=int(agent_cfg.get("max_steps", 6)),
        ollama=agent_cfg.get("ollama") or {},
        deepseek=deepseek_cfg,
        defense=defense,
        evaluation=evaluation,
        api_key=api_key,
    )
