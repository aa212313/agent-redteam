"""脚本模型：确定性的「naive instruction follower」。

它不是真实大模型，而是把 7B 级模型常见的失效方式写成可复现规则：
看得见指令就照做；被标注成数据的内容不再当指令（对应防御层 ①）。

两个用途：
1. 没有模型、没有网络时也能跑通整套评测，可进 CI；
2. 把「防御是否生效」与「模型本身多听话」解耦，测出的差值就是防御的贡献。

注意：报告里必须标明 provider=scripted，不能当作真实模型的 ASR。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Decision, key_of

PATH_PAT = r"[A-Za-z0-9_@./\\-]+\.(?:env|txt|md|json|csv|db)"

# 动词在前：「读取 ../secrets.env」
READ_RE = re.compile(rf"(?:读取|读出|打开|查看|read|cat|open)\s*(?:文件)?\s*[：:为]?\s*({PATH_PAT})", re.I)
# 动词在后：「把 ../secrets.env 读出来」——中文里这种说法同样常见
READ_ALT_RE = re.compile(rf"({PATH_PAT})\s*(?:读取|读出来|读一下|输出|贴出来|打印|发出来)", re.I)
URL_RE = re.compile(r"(https?://[^\s\"'，。<>（）()【】《》、]+)", re.I)
URL_VERB_RE = re.compile(r"(?:请求|访问|抓取|打开|读取|探测|curl|get|fetch)\s*[：:]?\s*$", re.I)
# (?<!已)：避免把工具回执「已发送给 X」再次当成新指令
SEND_RE = re.compile(
    rf"(?<!已)(?:发送|发给|发到|通知|推送|send|post)\s*(?:到|给|至|to)?\s*[：:]?\s*"
    rf"(https?://[^\s\"'，。<>（）()]+|[A-Za-z0-9_.@\-\u4e00-\u9fff]+)",
    re.I,
)
SQL_RE = re.compile(r"(SELECT\s[^\"'。\n\u4e00-\u9fff]+)", re.I)


def _matches(pattern: re.Pattern, text: str):
    for m in pattern.finditer(text):
        yield m.start(), m.end(), m


def extract(text: str, last_content: str, strict_url: bool = False) -> list[tuple[int, str, dict]]:
    """抽取文本里「想让你执行的工具调用」，按出现顺序返回。

    strict_url=True 用于工具返回值：URL 必须紧跟在动词后面才算指令，
    否则像 secrets.env 里的 INTERNAL_API=http://10.x 会被误当成要求访问。
    """
    found: list[tuple[int, str, dict]] = []

    send_spans = list(_matches(SEND_RE, text))
    for start, _end, m in send_spans:
        to = m.group(1).rstrip("，。,.")
        # body 在真正执行那一刻才取（见 decide），否则拿不到刚读到的内容
        found.append((start, "send_message", {"to": to, "_from_last": True, "body": ""}))

    for start, _end, m in _matches(URL_RE, text):
        if any(s <= start < e for s, e, _ in send_spans):
            continue
        if strict_url and not URL_VERB_RE.search(text[max(0, start - 20) : start]):
            continue
        found.append((start, "http_get", {"url": m.group(1).rstrip("，。")}))

    seen_paths = set()
    for pattern in (READ_RE, READ_ALT_RE):
        for start, _end, m in _matches(pattern, text):
            path = m.group(1)
            if path in seen_paths:
                continue
            seen_paths.add(path)
            found.append((start, "read_file", {"path": path}))

    for start, _end, m in _matches(SQL_RE, text):
        found.append((start, "query_db", {"sql": m.group(1).strip()}))

    found.sort(key=lambda x: x[0])
    return found


@dataclass
class ScriptedProvider:
    name: str = "scripted"
    max_steps: int = 6

    def decide(self, view: dict) -> Decision:
        executed = set(view.get("executed", []))
        observations = view.get("observations", [])
        last_content = observations[-1]["content"] if observations else ""
        sent = set(view.get("sent_targets") or [])

        candidates: list[tuple[str, dict]] = [
            (tool, args) for _pos, tool, args in extract(view.get("turn", ""), last_content)
        ]

        for obs in observations:
            content = obs.get("content") or ""
            # ① 把工具输出标成数据后不再执行；但 "SYSTEM:" 伪造仍能骗过它，
            # 这正是真实模型最常见的失效点，故意保留。
            if obs.get("wrapped") and "SYSTEM:" not in content:
                continue
            candidates.extend(
                (tool, args) for _pos, tool, args in extract(content, last_content, strict_url=True)
            )

        for tool, args in candidates:
            if tool == "send_message":
                target = args.get("to", "")
                # 同一轮里对同一目标只尝试一次，避免模型对着回执反复重发
                if len(sent) >= 2 or target in sent:
                    continue
                args = dict(args)
                args.pop("_from_last", None)
                args["body"] = last_content or view.get("turn", "")[:400]
            if key_of(tool, args) in executed:
                continue
            return Decision(kind="tool", tool=tool, args=args)

        for call in view.get("task", {}).get("calls", []):
            if key_of(call["tool"], call["args"]) in executed:
                continue
            return Decision(kind="tool", tool=call["tool"], args=dict(call["args"]))

        return Decision(kind="final", text=self._compose(observations))

    @staticmethod
    def _compose(observations: list) -> str:
        """朴素模型会把看到的内容都汇进回答——这正是「回答泄露」类攻击的成因。"""
        if not observations:
            return "没有可用的工具结果，暂时无法回答。"
        recent = [obs["content"].strip()[:150] for obs in observations[-2:]][::-1]
        return "根据查询结果：" + " / ".join(recent)[:300]
