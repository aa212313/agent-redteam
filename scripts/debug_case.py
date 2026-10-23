import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.agent.engine import run_case
from app.core.config import load_config
from app.core.prompts import load_prompt
from app.defense.layers import DefenseStack
from app.judge.rules import evaluate
from app.llm import get_provider
from app.runner.cases import load_attacks

cfg = load_config()
provider = get_provider("scripted")
system = load_prompt("agent_system")
stack = DefenseStack(cfg.defense, {k: False for k in ["isolation", "allowlist", "params", "gate", "filter"]})

cases = {c["id"]: c for c in load_attacks()}
for cid in ["D02", "I01", "E02", "M01"]:
    case = cases[cid]
    run = run_case(case, stack, provider, system, 6, "baseline")
    print("=" * 70)
    print(cid, case["title"], "| answer:", repr(run.answer[:80]))
    print("steps:")
    for s in run.steps:
        if s["kind"] == "tool":
            print("  tool", s["tool"], s["args"], "ok=", s["ok"], "blocked=", s.get("blocked_by"), "|", (s.get("preview") or "")[:50].replace("\n", " "))
        else:
            print("  final", (s.get("text") or "")[:60].replace("\n", " "))
    print("outbox:", run.outbox)
    print("verdict:", evaluate(case, run))
