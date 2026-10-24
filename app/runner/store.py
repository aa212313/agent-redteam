"""结果落库：SQLite 单文件，随仓库走，便于回放与对比。"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    provider TEXT NOT NULL,
    config TEXT NOT NULL,
    case_id TEXT NOT NULL,
    case_type TEXT NOT NULL,
    title TEXT,
    success INTEGER NOT NULL,
    benign_ok INTEGER,
    masked INTEGER,
    elapsed_ms REAL,
    iterations INTEGER,
    blocks TEXT,
    steps TEXT,
    answer TEXT,
    outbox TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_config ON runs(config);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        # 评测是多线程的：连接必须允许跨线程（写操作由 runner 的锁串行化）
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.executescript(SCHEMA)
        self.con.commit()

    def add(self, run, success: bool | None, benign_ok: bool | None = None) -> None:
        self.con.execute(
            "INSERT INTO runs (ts, provider, config, case_id, case_type, title, success, benign_ok,"
            " masked, elapsed_ms, iterations, blocks, steps, answer, outbox) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                time.time(),
                run.provider,
                run.config_name,
                run.case_id,
                run.case_type,
                run.title,
                1 if success else 0,
                None if benign_ok is None else (1 if benign_ok else 0),
                run.masked,
                run.elapsed_ms,
                run.iterations,
                json.dumps(run.blocks, ensure_ascii=False),
                json.dumps(run.steps, ensure_ascii=False),
                run.answer,
                json.dumps(run.outbox, ensure_ascii=False),
            ),
        )

    def flush(self) -> None:
        self.con.commit()

    def close(self) -> None:
        self.con.commit()
        self.con.close()
