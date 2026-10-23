"""Agent 主链路：LangGraph 状态机（decide → act → 条件边）。

为什么不用自由 Agent 循环：
业务链路是固定的「想 → 做 → 看结果 → 再想」，把它固化成状态机之后，
每一次失败都能重放到具体节点与具体参数；评测才能归因到「哪一步被绕过」。

LangGraph 不可用时退化为等价线性循环（tests 会同时验证两条路径结果一致）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypedDict

from app.agent import tools
from app.agent.tools import TOOL_SPECS
from app.defense.layers import DefenseStack
from app.llm.base import key_of

try:  # 可选依赖
    from langgraph.graph import END, StateGraph

    HAS_LANGGRAPH = True
except Exception:  # noqa: BLE001
    END = "__end__"
    HAS_LANGGRAPH = False


class RunState(TypedDict, total=False):
    turn_index: int
    step: int
    iterations: int
    masked: int
    observations: list
    executed: list
    steps: list
    pending: dict
    answer: str
    done: bool
    sent_targets: list


@dataclass
class Ctx:
    case: dict
    stack: DefenseStack
    provider: Any
    system: str
    max_steps: int


def initial_state() -> RunState:
    return {
        "turn_index": 0,
        "step": 0,
        "iterations": 0,
        "masked": 0,
        "observations": [],
        "executed": [],
        "steps": [],
        "pending": {},
        "answer": "",
        "done": False,
        "sent_targets": [],
    }


def decide(state: RunState, ctx: Ctx) -> dict:
    """模型决策节点：组装它可见的上下文（含防御层 ① 的改写），拿到一个动作。"""
    turns = ctx.case["turns"]
    view = {
        "system": ctx.system,
        "turn": turns[min(state.get("turn_index", 0), len(turns) - 1)],
        "task": ctx.case.get("task") or {},
        "observations": state.get("observations", []),
        "executed": state.get("executed", []),
        "sent_targets": state.get("sent_targets", []),
        "tools": TOOL_SPECS,
    }
    ctx.stack.prepare_view(view)
    decision = ctx.provider.decide(view)
    return {
        "pending": {
            "kind": decision.kind,
            "tool": decision.tool,
            "args": decision.args,
            "text": decision.text,
        },
        "iterations": state.get("iterations", 0) + 1,
    }


def act(state: RunState, ctx: Ctx) -> dict:
    """执行节点：过防御栈 → 调工具 → 把结果包回观察里。"""
    pending = state.get("pending") or {}
    steps = list(state.get("steps", []))
    observations = list(state.get("observations", []))
    executed = list(state.get("executed", []))
    masked = state.get("masked", 0)

    if pending.get("kind") == "final":
        text = pending.get("text", "")
        steps.append({"kind": "final", "text": text})
        updates: dict = {"steps": steps, "answer": text}
        turn_index = state.get("turn_index", 0)
        if turn_index + 1 < len(ctx.case["turns"]):
            updates.update({"turn_index": turn_index + 1, "step": 0, "pending": {}, "sent_targets": []})
        else:
            updates["done"] = True
        return updates

    tool = pending.get("tool") or ""
    args = dict(pending.get("args") or {})
    block, args, call_ctx = ctx.stack.before_call(
        tool, args, {"task": ctx.case.get("task") or {}, "confirmed": False}
    )
    masked += call_ctx.get("masked", 0)

    if block:
        steps.append(
            {
                "kind": "tool",
                "tool": tool,
                "args": args,
                "ok": False,
                "blocked_by": block.layer,
                "reason": block.reason,
            }
        )
        observations.append(
            {"tool": tool, "content": f"[blocked:{block.layer}] {block.reason}", "wrapped": True, "ok": False}
        )
    else:
        result = tools.call(tool, args)
        content = result.content if result.ok else (result.error or "")
        wrapped_content, wrapped = ctx.stack.post_tool(content)
        steps.append(
            {
                "kind": "tool",
                "tool": tool,
                "args": args,
                "ok": result.ok,
                "error": result.error,
                "preview": content[:300],
                "wrapped": wrapped,
            }
        )
        observations.append({"tool": tool, "content": wrapped_content, "wrapped": wrapped, "ok": result.ok})

    executed.append(key_of(tool, args))
    sent_targets = list(state.get("sent_targets", []))
    if tool == "send_message":
        sent_targets.append(str(args.get("to", "")))
    return {
        "steps": steps,
        "observations": observations,
        "executed": executed,
        "step": state.get("step", 0) + 1,
        "masked": masked,
        "sent_targets": sent_targets,
    }


def _router(ctx: Ctx):
    def route(state: RunState) -> str:
        if state.get("done"):
            return "end"
        if state.get("step", 0) >= ctx.max_steps:
            return "end"
        return "decide"

    return route


def build_graph(ctx: Ctx):
    """编译 LangGraph；不可用时返回 None。"""
    if not HAS_LANGGRAPH:
        return None
    graph = StateGraph(RunState)
    graph.add_node("decide", lambda state: decide(state, ctx))
    graph.add_node("act", lambda state: act(state, ctx))
    graph.set_entry_point("decide")
    graph.add_edge("decide", "act")
    graph.add_conditional_edges("act", _router(ctx), {"decide": "decide", "end": END})
    return graph.compile()
