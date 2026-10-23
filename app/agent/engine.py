"""单次运行编排：给 runner 一个干净的入口，屏蔽 LangGraph / 线性两种执行方式。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.agent import tools
from app.agent.workflow import Ctx, act, build_graph, decide, initial_state
from app.defense.layers import DefenseStack
from app.llm.base import Provider


@dataclass
class RunResult:
    case_id: str
    case_type: str
    title: str
    config_name: str
    provider: str
    engine: str
    steps: list = field(default_factory=list)
    answer: str = ""
    outbox: list = field(default_factory=list)
    blocks: list = field(default_factory=list)
    masked: int = 0
    elapsed_ms: float = 0.0
    iterations: int = 0

    def as_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "title": self.title,
            "config": self.config_name,
            "provider": self.provider,
            "engine": self.engine,
            "steps": self.steps,
            "answer": self.answer,
            "outbox": self.outbox,
            "blocks": self.blocks,
            "masked": self.masked,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "iterations": self.iterations,
        }


def run_case(
    case: dict,
    stack: DefenseStack,
    provider: Provider,
    system: str,
    max_steps: int = 6,
    config_name: str = "custom",
    engine: str = "auto",
) -> RunResult:
    tools.reset_session()
    stack.blocks.clear()

    ctx = Ctx(case=case, stack=stack, provider=provider, system=system, max_steps=max_steps)
    state = initial_state()
    started = time.perf_counter()
    used = "linear"

    if engine in ("auto", "langgraph"):
        compiled = build_graph(ctx)
        if compiled is not None:
            used = "langgraph"
            limit = max(30, max_steps * (len(case["turns"]) + 1) * 2 + 10)
            state = compiled.invoke(state, {"recursion_limit": limit})

    if used == "linear":
        guard = max_steps * len(case["turns"]) + 5
        for _ in range(guard):
            state = {**state, **decide(state, ctx)}
            state = {**state, **act(state, ctx)}
            if state.get("done") or state.get("step", 0) >= max_steps:
                break

    elapsed = (time.perf_counter() - started) * 1000
    return RunResult(
        case_id=case.get("id", "?"),
        case_type=case.get("type", "unknown"),
        title=case.get("title", ""),
        config_name=config_name,
        provider=getattr(provider, "name", "unknown"),
        engine=used,
        steps=list(state.get("steps", [])),
        answer=state.get("answer", ""),
        outbox=list(tools.OUTBOX),
        blocks=list(stack.blocks),
        masked=int(state.get("masked", 0)),
        elapsed_ms=elapsed,
        iterations=int(state.get("iterations", 0)),
    )
