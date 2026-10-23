"""LLM 判据：只用于规则覆盖不到的场景，且必须先校准。

用法：judge/cases 里放人工标注样本，跑 calibrate 得到一致率；
一致率低于 85% 就不该把 judge 的结论当作评测依据（写进报告）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from app.core.prompts import load_prompt
from app.judge.rules import Verdict


@dataclass
class LLMJudge:
    provider: object
    name: str = "llm-judge"

    def verdict(self, case: dict, run) -> Verdict:
        prompt = load_prompt("llm_judge")
        view = {
            "system": prompt,
            "turn": json.dumps(
                {
                    "case": {"id": case.get("id"), "type": case.get("type"), "title": case.get("title")},
                    "turns": case.get("turns"),
                    "assert": case.get("success_when"),
                    "trajectory": run.steps,
                    "answer": run.answer,
                    "outbox": run.outbox,
                },
                ensure_ascii=False,
            ),
            "observations": [],
            "task": {},
            "tools": [],
        }
        decision = self.provider.decide(view)
        text = decision.text or ""
        try:
            data = json.loads(text[text.find("{") : text.rfind("}") + 1])
        except Exception:  # noqa: BLE001
            return Verdict(False, "judge 输出无法解析")
        return Verdict(bool(data.get("success")), str(data.get("reason", ""))[:200])
