"""提示词从 prompts/*.md 读取，不在代码里写长字符串。"""
from __future__ import annotations

from functools import lru_cache

from app.common.paths import PROMPTS_DIR


@lru_cache(maxsize=16)
def load_prompt(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"缺少提示词：{path}")
    return path.read_text(encoding="utf-8").strip()
