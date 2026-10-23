"""用例加载与校验：用例通过 task 模板引用，避免重复配置。"""
from __future__ import annotations

from pathlib import Path

import yaml

from app.common.paths import CASES_DIR

ATTACK_FILES = [
    "attack_direct.yaml",
    "attack_indirect.yaml",
    "attack_tool_abuse.yaml",
    "attack_exfil.yaml",
    "attack_multistep.yaml",
]


class CaseError(ValueError):
    """用例格式错误，早失败早发现。"""


def load_tasks() -> dict:
    path = CASES_DIR / "tasks.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _resolve_task(case: dict, tasks: dict) -> dict:
    task = case.get("task")
    if isinstance(task, str):
        if task not in tasks:
            raise CaseError(f"{case.get('id')}: 未定义的任务模板 {task}")
        return tasks[task]
    if isinstance(task, dict):
        return task
    raise CaseError(f"{case.get('id')}: 缺少 task")


def _validate(case: dict) -> None:
    cid = case.get("id", "?")
    if not case.get("turns"):
        raise CaseError(f"{cid}: 缺少 turns")
    if not isinstance(case["turns"], list):
        raise CaseError(f"{cid}: turns 必须是列表")
    if case.get("type") != "benign" and not case.get("success_when"):
        raise CaseError(f"{cid}: 攻击用例必须给出 success_when")


def _load_file(path: Path, tasks: dict) -> list[dict]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out = []
    for case in raw:
        _validate(case)
        case["task"] = _resolve_task(case, tasks)
        out.append(case)
    return out


def load_attacks(directory: Path | None = None) -> list[dict]:
    tasks = load_tasks()
    cases: list[dict] = []
    for name in ATTACK_FILES:
        path = (directory or CASES_DIR) / name
        if not path.is_file():
            raise CaseError(f"缺少用例文件：{path}")
        cases.extend(_load_file(path, tasks))
    return cases


def load_benign(path: Path) -> list[dict]:
    tasks = load_tasks()
    return _load_file(path, tasks)


def stats_by_type(cases: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for case in cases:
        out[case["type"]] = out.get(case["type"], 0) + 1
    return out
