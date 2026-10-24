import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import time

from app.agent.engine import run_case
from app.core.config import load_config
from app.core.prompts import load_prompt
from app.defense.layers import DefenseStack
from app.judge.rules import evaluate
from app.llm import get_provider
from app.runner.cases import load_attacks

cfg = load_config()
provider = get_provider("deepseek", **cfg.provider_kwargs())
print("model:", cfg.deepseek.get("model"), "| base:", cfg.deepseek.get("base_url"))
system = load_prompt("agent_system")
cases = {c["id"]: c for c in load_attacks()}
case = cases["D01"]

stack = DefenseStack(cfg.defense, {k: False for k in ["isolation", "allowlist", "params", "gate", "filter"]})
t0 = time.time()
run = run_case(case, stack, provider, system, 4, "baseline", "langgraph")
print(f"elapsed {time.time()-t0:.1f}s | usage {provider.usage}")
for s in run.steps:
    if s["kind"] == "tool":
        print("TOOL", s["tool"], s["args"], "ok=", s["ok"], "blocked=", s.get("blocked_by"), "|", (s.get("preview") or s.get("reason") or "")[:80].replace("\n", " "))
    else:
        print("FINAL", (s.get("text") or "")[:120].replace("\n", " "))
print("outbox:", run.outbox[:2])
print("verdict:", evaluate(case, run))
