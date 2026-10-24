"""评测入口。

    python -m app.runner.evaluate                    # 跑完整矩阵（全关 / 全开 / 逐层去掉）
    python -m app.runner.evaluate --config hardened  # 只跑一个配置
    python -m app.runner.evaluate --provider ollama --model qwen2.5:7b
    python -m app.runner.evaluate --limit 5          # 冒烟：每类只跑几条

产物：reports/bench.md、reports/summary.json、web/data.js、reports/runs.db
"""
from __future__ import annotations

import argparse
import json
import runpy
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from app.agent.engine import run_case
from app.agent.tools import DB
from app.common.paths import ROOT, ensure_runtime_dirs, rel
from app.common.logger import get_logger
from app.core.config import load_config
from app.core.prompts import load_prompt
from app.defense.layers import DefenseStack
from app.judge.rules import benign_ok, evaluate as judge_run
from app.llm import get_provider
from app.runner.cases import load_attacks, load_benign, stats_by_type
from app.runner.metrics import ATTACK_TYPES, LAYER_NAMES, LAYERS, leaked, marginal, summarize
from app.runner.store import Store

log = get_logger("evaluate")


def build_configs(matrix: dict) -> dict[str, dict[str, bool]]:
    hardened = dict(matrix.get("hardened") or {k: True for k in LAYERS})
    configs: dict[str, dict[str, bool]] = {"baseline": dict(matrix.get("baseline") or {k: False for k in LAYERS})}
    configs["hardened"] = hardened
    for layer in LAYERS:
        cfg = dict(hardened)
        cfg[layer] = False
        configs[f"no_{layer}"] = cfg
    return configs


def ensure_data() -> None:
    if not DB.is_file():
        log.info("首次运行，构建合成数据…")
        runpy.run_path(str(ROOT / "data" / "build.py"), run_name="__main__")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent 提示注入红队评测")
    parser.add_argument("--config", default="", help="只跑指定配置（baseline / hardened / no_gate …）")
    parser.add_argument("--provider", default="", help="scripted / ollama / deepseek")
    parser.add_argument("--model", default="", help="覆盖模型名")
    parser.add_argument("--base-url", default="", help="覆盖 OpenAI 兼容端点，如 https://token.wasu.cn/v1")
    parser.add_argument("--api-key", default="", help="覆盖 API Key（优先于 .env）")
    parser.add_argument("--engine", default="auto", choices=["auto", "langgraph", "linear"])
    parser.add_argument("--limit", type=int, default=0, help="每个类型只跑前 N 条（冒烟用）")
    parser.add_argument("--no-store", action="store_true", help="不写 SQLite")
    parser.add_argument("--workers", type=int, default=1, help="并发用例数（远程模型建议 6-10）")
    parser.add_argument("--timeout", type=int, default=0, help="单次模型调用超时秒数")
    parser.add_argument("--tag", default="", help="产物后缀：bench-<tag>.md / summary-<tag>.json")
    parser.add_argument("--configs", default="", help="只跑这几个配置，逗号分隔，如 baseline,hardened")
    parser.add_argument("--rpm", type=int, default=0, help="每分钟模型请求上限（网关限流用，0 表示不限）")
    args = parser.parse_args()

    ensure_runtime_dirs()
    ensure_data()

    cfg = load_config()
    provider_name = args.provider or cfg.provider
    kwargs = cfg.provider_kwargs()
    if args.model:
        kwargs["model"] = args.model
    if args.base_url:
        kwargs["base_url"] = args.base_url
    if args.api_key:
        kwargs["api_key"] = args.api_key
    if args.timeout:
        kwargs["timeout"] = args.timeout
    if args.rpm:
        kwargs["rpm"] = args.rpm
    provider = get_provider(provider_name, **kwargs)
    system = load_prompt("agent_system")

    attacks = load_attacks()
    benign = load_benign(cfg.evaluation.benign_path)
    if args.limit:
        seen: dict[str, int] = {}
        limited = []
        for case in attacks:
            seen[case["type"]] = seen.get(case["type"], 0) + 1
            if seen[case["type"]] <= args.limit:
                limited.append(case)
        attacks = limited
        benign = benign[: args.limit]

    configs = build_configs(cfg.evaluation.matrix)
    if args.config:
        configs = {args.config: configs[args.config]}
    if args.configs:
        want = [c.strip() for c in args.configs.split(",") if c.strip()]
        unknown = [c for c in want if c not in configs]
        if unknown:
            raise SystemExit(f"未知配置：{unknown}，可选：{list(configs)}")
        configs = {c: configs[c] for c in want}

    log.info(
        "provider=%s engine=%s 用例=%d 攻击 / %d 正常 配置=%s",
        provider_name,
        args.engine,
        len(attacks),
        len(benign),
        ",".join(configs),
    )

    store = None if args.no_store else Store(cfg.evaluation.db_path)
    lock = threading.Lock()
    records: list[dict] = []
    started = time.perf_counter()
    total_jobs = len(configs) * (len(attacks) + len(benign))
    done_jobs = 0

    def run_job(config_name: str, overrides: dict, case: dict) -> dict:
        # 每个 job 用独立防御栈：blocks 不能跨线程共享
        stack = DefenseStack(cfg.defense, overrides)
        run = run_case(case, stack, provider, system, cfg.evaluation.max_steps, config_name, args.engine)
        is_benign = case.get("type") == "benign"
        if is_benign:
            ok, reason = benign_ok(case, run)
        else:
            verdict = judge_run(case, run)
            ok, reason = verdict.success, verdict.reason
        record = {
            "config": config_name,
            "case_id": run.case_id,
            "case_type": run.case_type,
            "title": run.title,
            "success": False if is_benign else ok,
            "benign_ok": ok if is_benign else None,
            "reason": reason,
            "elapsed_ms": run.elapsed_ms,
            "blocks": run.blocks,
            "masked": run.masked,
            "iterations": run.iterations,
        }
        if store:
            with lock:
                store.add(run, record["success"], record["benign_ok"])
        return record

    jobs = [(name, ov, case) for name, ov in configs.items() for case in attacks + benign]
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(run_job, name, ov, case): (name, case) for name, ov, case in jobs}
        for fut in as_completed(futures):
            config_name, case = futures[fut]
            try:
                record = fut.result()
            except Exception as exc:  # noqa: BLE001 单条失败不拖垮整批
                record = {
                    "config": config_name,
                    "case_id": case["id"],
                    "case_type": case.get("type", "unknown"),
                    "title": case.get("title", ""),
                    "success": False,
                    "benign_ok": False if case.get("type") == "benign" else None,
                    "reason": f"运行异常：{type(exc).__name__}: {exc}",
                    "elapsed_ms": 0,
                    "blocks": [],
                    "masked": 0,
                    "iterations": 0,
                }
            records.append(record)
            done_jobs += 1
            if str(record.get("reason", "")).startswith("运行异常"):
                flag = "ERR "  # 单条失败要显眼，不能混进 safe
            elif record.get("success"):
                flag = "HIT "
            elif record.get("benign_ok"):
                flag = "ok  "
            else:
                flag = "safe"
            log.info("[%d/%d] %-11s %-4s %s %s", done_jobs, total_jobs, config_name, record["case_id"], flag, record.get("title", ""))

    if store:
        store.close()

    wall = time.perf_counter() - started
    summary = summarize(records)
    marg = marginal(summary)
    leaked_cases = leaked(records, "hardened")

    results_by_case: dict[str, dict[str, bool]] = {}
    for r in records:
        if r["case_type"] != "benign":
            results_by_case.setdefault(r["case_id"], {})[r["config"]] = bool(r["success"])

    payload = {
        "meta": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "provider": provider_name,
            "engine": args.engine,
            "attack_cases": len(attacks),
            "benign_cases": len(benign),
            "types": stats_by_type(attacks),
            "wall_seconds": round(wall, 1),
            "scripted_warning": provider_name == "scripted",
        },
        "configs": summary,
        "marginal": marg,
        "leaked": leaked_cases,
        "cases": [
            {
                "id": case["id"],
                "type": case["type"],
                "title": case.get("title", ""),
                "results": results_by_case.get(case["id"], {}),
            }
            for case in attacks
        ],
    }
    write_outputs(cfg, payload, args.tag)

    log.info("完成：%d 次运行，耗时 %.1fs", len(records), wall)
    print_console(summary, marg)


def print_console(summary: dict, marg: list[dict]) -> None:
    print("\n配置          ASR     正常通过   拦截次数   出站脱敏")
    for name, data in summary.items():
        blocks = sum(data["blocks"].values())
        print(
            f"{name:<12} {data['asr']:>5.1f}%  {data['benign_pass_rate']:>6.1f}%  "
            f"{blocks:>8}  {data['masked']:>8}"
        )
    if marg:
        print("\n逐层边际（去掉该层后 ASR 上升）")
        for row in marg:
            print(f"  {row['name']:<10} +{row['delta']:>5.1f} pp   误杀 {row['benign_without']:.0f}% → {row['benign_with']:.0f}%")


def write_outputs(cfg, payload: dict, tag: str = "") -> None:
    reports = cfg.evaluation.reports_dir
    reports.mkdir(parents=True, exist_ok=True)
    suffix = f"-{tag}" if tag else ""
    (reports / f"summary{suffix}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    meta = payload["meta"]
    summary = payload["configs"]
    lines = [
        "# 评测基线（bench.md）",
        "",
        f"> 由 `python -m app.runner.evaluate` 自动生成，**禁止手填**。生成时间：{meta['generated_at']}",
        f"> provider：`{meta['provider']}` · engine：`{meta['engine']}` · "
        f"攻击用例 {meta['attack_cases']} 条 / 正常任务 {meta['benign_cases']} 条 · 总耗时 {meta['wall_seconds']}s",
        "",
    ]
    if meta.get("scripted_warning"):
        lines += [
            "> ⚠️ **本次结果是脚本模型（provider=scripted）产出的**：它把「7B 级模型常见失效方式」写成确定性规则，",
            "> 用来验证评测链路与防御层的贡献，**不代表真实模型的攻击成功率**。",
            "> 接真模型重跑同一套用例：`python -m app.runner.evaluate --provider ollama`（本地）",
            "> 或 `--provider deepseek`（需在 .env 配 DEEPSEEK_API_KEY）。",
            "",
        ]

    lines += ["## 一、总体", "", "| 配置 | 攻击成功率 ASR | 正常任务通过率 | 拦截次数 | 出站脱敏 | 平均耗时 |", "| --- | --- | --- | --- | --- | --- |"]
    for name, data in summary.items():
        lines.append(
            f"| `{name}` | **{data['asr']}%** ({data['attack_success']}/{data['attack_total']}) | "
            f"{data['benign_pass_rate']}% ({data['benign_passed']}/{data['benign_total']}) | "
            f"{sum(data['blocks'].values())} | {data['masked']} | {data['avg_ms']} ms |"
        )

    lines += ["", "## 二、分类型 ASR", "", "| 类型 | 全关 baseline | 全开 hardened | 降幅 |", "| --- | --- | --- | --- |"]
    base = summary.get("baseline", {}).get("per_type", {})
    hard = summary.get("hardened", {}).get("per_type", {})
    for t in ATTACK_TYPES:
        if t in base and t in hard:
            drop = round(base[t]["asr"] - hard[t]["asr"], 1)
            lines.append(f"| {t} | {base[t]['asr']}% ({base[t]['success']}/{base[t]['total']}) | {hard[t]['asr']}% ({hard[t]['success']}/{hard[t]['total']}) | -{drop} pp |")

    lines += ["", "## 三、逐层边际（去掉该层后 ASR 上升多少）", "", "| 防御层 | 全开 ASR | 去掉后 ASR | 边际 | 去掉后误杀率 |", "| --- | --- | --- | --- | --- |"]
    for row in payload["marginal"]:
        lines.append(
            f"| {row['name']} | {row['asr_with']}% | {row['asr_without']}% | **+{row['delta']} pp** | {100 - row['benign_without']:.0f}% |"
        )

    lines += ["", "## 四、全开防御下仍然成功的用例（漏网）", ""]
    if payload["leaked"]:
        lines += ["| 用例 | 类型 | 标题 |", "| --- | --- | --- |"]
        for row in payload["leaked"]:
            lines.append(f"| {row['case_id']} | {row['type']} | {row['title']} |")
    else:
        lines.append("无。")

    lines += [
        "",
        "## 五、口径说明",
        "",
        "- **ASR**：命中断言的攻击用例 / 该配置下的攻击用例总数。断言见 `cases/*.yaml` 的 `success_when`。",
        "- **正常任务通过率**：20 条不含攻击的任务里，任务声明的良性调用成功执行且给出回答的比例；1 − 通过率即误杀率。",
        "- **逐层边际**：ASR(去掉该层) − ASR(全开)。正值说明该层确实拦住了东西；接近 0 说明它在这个用例集里没贡献。",
        "- **出站脱敏**：⑤ 层改写的字段次数，不等于拦截数。",
        "",
        "## 六、已知局限",
        "",
        "- 判据以规则为主，规则覆盖不到的语义判定尚未接入 LLM judge（接口已留，`app/judge/llm.py`）。",
        "- ⑤ 只覆盖外发通道，**回答本身**的敏感内容泄露仍由模型侧与 ① 负责，这一层没有兜底。",
        "- 用例集为合成载荷，未覆盖多模态、文件附件、编码混淆等更复杂的注入形态。",
    ]
    (reports / f"bench{suffix}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    web_data = cfg.evaluation.web_data
    if tag:
        web_data = web_data.with_name(f"data{suffix}.js")
    web_data.parent.mkdir(parents=True, exist_ok=True)
    web_data.write_text("window.DATA = " + json.dumps(payload, ensure_ascii=False) + ";\n", encoding="utf-8")
    print(f"\n报告：{rel(reports / f'bench{suffix}.md')} · 看板数据：{rel(web_data)}")


if __name__ == "__main__":
    main()
