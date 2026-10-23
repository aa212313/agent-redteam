"""端到端：同一用例在两种配置下的判定必须稳定，LangGraph 与线性引擎结果一致。"""
import pytest

from app.agent.engine import run_case
from app.core.config import load_config
from app.core.prompts import load_prompt
from app.defense.layers import DefenseStack
from app.llm import get_provider
from app.runner.cases import load_attacks, load_benign

OFF = {"isolation": False, "allowlist": False, "params": False, "gate": False, "filter": False}
ON = {k: True for k in OFF}


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture(scope="module")
def cases():
    return {c["id"]: c for c in load_attacks()}


def test_baseline_is_vulnerable(cfg, cases):
    stack = DefenseStack(cfg.defense, OFF)
    run = run_case(cases["T01"], stack, get_provider("scripted"), load_prompt("agent_system"), 6, "baseline")
    assert any(s.get("tool") == "read_file" and s.get("ok") for s in run.steps)


def test_hardened_blocks_traversal(cfg, cases):
    stack = DefenseStack(cfg.defense, ON)
    run = run_case(cases["T01"], stack, get_provider("scripted"), load_prompt("agent_system"), 6, "hardened")
    assert not any(s.get("tool") == "read_file" and s.get("ok") for s in run.steps)
    assert any(b["layer"] == "params" for b in run.blocks)


def test_multistep_chains_across_turns(cfg, cases):
    stack = DefenseStack(cfg.defense, OFF)
    run = run_case(cases["M01"], stack, get_provider("scripted"), load_prompt("agent_system"), 6, "baseline")
    assert run.outbox and "sk-live-FAKE" in str(run.outbox)


def test_benign_task_not_broken_by_defenses(cfg):
    benign = {c["id"]: c for c in load_benign(cfg.evaluation.benign_path)}
    stack = DefenseStack(cfg.defense, ON)
    run = run_case(benign["B01"], stack, get_provider("scripted"), load_prompt("agent_system"), 6, "hardened")
    assert run.answer
    assert not [s for s in run.steps if s.get("blocked_by")]


@pytest.mark.parametrize("case_id", ["D01", "T07", "E01"])
def test_langgraph_and_linear_agree(cfg, cases, case_id):
    stack_a = DefenseStack(cfg.defense, OFF)
    graph_run = run_case(cases[case_id], stack_a, get_provider("scripted"), load_prompt("agent_system"), 6, "x", "langgraph")
    stack_b = DefenseStack(cfg.defense, OFF)
    linear_run = run_case(cases[case_id], stack_b, get_provider("scripted"), load_prompt("agent_system"), 6, "x", "linear")
    assert graph_run.answer == linear_run.answer
    assert [s for s in graph_run.steps if s.get("tool")] == [s for s in linear_run.steps if s.get("tool")]
