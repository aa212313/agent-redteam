"""统一的路径解析：全部相对项目根，禁止硬编码绝对路径。"""
from __future__ import annotations

from pathlib import Path

# app/common/paths.py -> app/common -> app -> <项目根>
ROOT = Path(__file__).resolve().parents[2]

APP_DIR = ROOT / "app"
CONF_DIR = ROOT / "conf"
CASES_DIR = ROOT / "cases"
DATA_DIR = ROOT / "data"
DOCS_DIR = ROOT / "docs"
PROMPTS_DIR = ROOT / "prompts"
REPORTS_DIR = ROOT / "reports"
WEB_DIR = ROOT / "web"
TESTS_DIR = ROOT / "tests"


def ensure_runtime_dirs() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def rel(path: Path) -> str:
    """转成相对项目根的展示路径，日志与报告里都用它。"""
    try:
        return str(Path(path).resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)
