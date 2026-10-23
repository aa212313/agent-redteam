"""模型接口：实现 decide() 即可替换底层模型。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Decision:
    kind: str                      # "tool" | "final"
    tool: str | None = None
    args: dict = field(default_factory=dict)
    text: str = ""


class Provider(Protocol):
    name: str

    def decide(self, view: dict) -> Decision:  # pragma: no cover
        ...


def key_of(tool: str, args: dict) -> str:
    """同一个调用只执行一次，避免模型原地打转。"""
    return f"{tool}:{sorted(args.items())}"
