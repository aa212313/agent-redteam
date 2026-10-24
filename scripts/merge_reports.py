"""把「脚本模型完整矩阵」与「真实模型对照」合并成一份报告与看板数据。

    python scripts/merge_reports.py

输入：reports/summary-scripted.json（7 配置全量）、reports/summary-real.json（真实模型 baseline/hardened）
输出：reports/summary.json、reports/bench.md、web/data.js
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.common.paths import REPORTS_DIR, WEB_DIR, rel
from app.runner.metrics import ATTACK_TYPES, LAYERS, LAYER_NAMES


def load(name: str) -> dict | None:
    path = REPORTS_DIR / name
    if not path.is_file():
        print(f"跳过：缺少 {path.name}")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    scripted = load("summary-scripted.json") or load("summary.json")
    real = load("summary-real.json")
    if scripted is None:
        raise SystemExit("缺少脚本模型结果，先跑：python -m app.runner.evaluate")

    payload = dict(scripted)
    payload["meta"]["scripted_provider"] = "scripted"
    if real:
        payload["real"] = {
            "meta": real["meta"],
            "configs": real["configs"],
            "cases": real.get("cases", []),
        }

    (REPORTS_DIR / "summary.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (WEB_DIR / "data.js").write_text("window.DATA = " + json.dumps(payload, ensure_ascii=False) + ";\n", encoding="utf-8")
    (REPORTS_DIR / "bench.md").write_text(render(payload), encoding="utf-8")
    print(f"合并完成：{rel(REPORTS_DIR / 'bench.md')} · {rel(WEB_DIR / 'data.js')}")


def render(payload: dict) -> str:
    meta = payload["meta"]
    s = payload["configs"]
    real = payload.get("real")
    lines = [
        "# 评测基线（bench.md）",
        "",
        f"> 由 `python -m app.runner.evaluate` + `scripts/merge_reports.py` 生成，**禁止手填**。生成时间：{meta['generated_at']}",
        "",
        "本报告分两部分：",
        "",
        "- **一、真实模型对照**：真实大模型（DeepSeek-v4.1-flash）在防御全关/全开两种配置下的全量结果，回答「模型本身顶不顶得住」。",
        "- **二、脚本模型矩阵**：确定性的脚本模型跑完 7 种防御配置，用于验证评测链路与**每一层防御的贡献**（逐层边际）。",
        "",
        "脚本模型不是真模型，它把 7B 级模型的常见失效方式写成规则；两部分数字不能混着引用。",
        "",
    ]

    if real:
        rmeta, rc = real["meta"], real["configs"]
        lines += [
            "## 一、真实模型对照",
            "",
            f"- 模型：`deepseek-v4.1-flash`（provider=`{rmeta['provider']}`）",
            f"- 用例：攻击 {rmeta['attack_cases']} 条 + 正常任务 {rmeta['benign_cases']} 条，配置：{', '.join(rc.keys())}",
            f"- 总耗时：{rmeta['wall_seconds']}s",
            "",
            "| 配置 | 攻击成功率 ASR | 正常任务通过率 | 平均单条耗时 |",
            "| --- | --- | --- | --- |",
        ]
        for name, d in rc.items():
            lines.append(
                f"| `{name}` | **{d['asr']}%** ({d['attack_success']}/{d['attack_total']}) | "
                f"{d['benign_pass_rate']}% ({d['benign_passed']}/{d['benign_total']}) | {d['avg_ms']} ms |"
            )
        base = rc.get("baseline", {})
        hard = rc.get("hardened", {})
        if base and hard:
            lines += [
                "",
                f"降幅：**{base['asr']}% → {hard['asr']}%**（-{round(base['asr'] - hard['asr'], 1)} pp）。",
                "",
                "| 攻击类型 | 全关 ASR | 全开 ASR |",
                "| --- | --- | --- |",
            ]
            for t in ATTACK_TYPES:
                b = (base.get("per_type") or {}).get(t)
                h = (hard.get("per_type") or {}).get(t)
                if b and h:
                    lines.append(f"| {t} | {b['asr']}% ({b['success']}/{b['total']}) | {h['asr']}% ({h['success']}/{h['total']}) |")

    lines += [
        "",
        "## 二、脚本模型矩阵（防御逐层贡献）",
        "",
        f"> provider=`scripted` · 攻击 {meta['attack_cases']} 条 / 正常 {meta['benign_cases']} 条 · 总耗时 {meta['wall_seconds']}s",
        "",
        "| 配置 | 攻击成功率 ASR | 正常任务通过率 | 拦截次数 | 出站脱敏 | 平均耗时 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name, d in s.items():
        lines.append(
            f"| `{name}` | **{d['asr']}%** ({d['attack_success']}/{d['attack_total']}) | "
            f"{d['benign_pass_rate']}% ({d['benign_passed']}/{d['benign_total']}) | "
            f"{sum(d['blocks'].values())} | {d['masked']} | {d['avg_ms']} ms |"
        )

    lines += ["", "### 分类型 ASR", "", "| 类型 | 全关 | 全开 | 降幅 |", "| --- | --- | --- | --- |"]
    base = s.get("baseline", {}).get("per_type", {})
    hard = s.get("hardened", {}).get("per_type", {})
    for t in ATTACK_TYPES:
        if t in base and t in hard:
            lines.append(
                f"| {t} | {base[t]['asr']}% ({base[t]['success']}/{base[t]['total']}) | "
                f"{hard[t]['asr']}% ({hard[t]['success']}/{hard[t]['total']}) | "
                f"-{round(base[t]['asr'] - hard[t]['asr'], 1)} pp |"
            )

    lines += ["", "### 逐层边际（去掉该层后 ASR 上升多少）", "", "| 防御层 | 全开 ASR | 去掉后 ASR | 边际 | 去掉后误杀率 |", "| --- | --- | --- | --- | --- |"]
    for row in payload.get("marginal", []):
        lines.append(
            f"| {row['name']} | {row['asr_with']}% | {row['asr_without']}% | **+{row['delta']} pp** | "
            f"{100 - row['benign_without']:.0f}% |"
        )

    lines += ["", "### 全开防御下仍然成功的用例（漏网）", ""]
    if payload.get("leaked"):
        lines += ["| 用例 | 类型 | 标题 |", "| --- | --- | --- |"]
        for row in payload["leaked"]:
            lines.append(f"| {row['case_id']} | {row['type']} | {row['title']} |")
    else:
        lines.append("无。")

    lines += [
        "",
        "## 三、口径说明",
        "",
        "- **ASR**：命中断言的攻击用例 / 该配置下的攻击用例总数，断言见 `cases/*.yaml` 的 `success_when`。",
        "- **正常任务通过率**：20 条不含攻击的任务里，良性调用成功且有回答的比例；1 − 通过率即误杀率。",
        "- **逐层边际**：ASR(去掉该层) − ASR(全开)。正值说明该层确实拦住了东西。",
        "- **真实模型与脚本模型分表**：前者说明模型本身的安全水位，后者说明防御层的贡献，两者不能相加或互相替代。",
        "",
        "## 四、已知局限",
        "",
        "- 真实模型只跑了 baseline / hardened 两种配置（网关有频率限制），逐层边际来自脚本模型。",
        "- 判据以规则为主，语义级判定仍需 LLM judge 校准（接口已留）。",
        "- ⑤ 只覆盖外发通道，回答本身的泄露没有兜底。",
        "- 用例集为合成载荷，未覆盖多模态、附件、编码混淆。",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
