"""HTTP 服务：给看板提供接口，同时能当单端口服务跑起来。

    python -m app.main            # 默认 127.0.0.1:8000
    PORT=8080 python -m app.main  # 平台部署时注入 PORT
"""
from __future__ import annotations

import json
import os

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.common.paths import REPORTS_DIR, WEB_DIR

app = FastAPI(title="Agent 安全靶场", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/api/summary")
def summary():
    path = REPORTS_DIR / "summary.json"
    if not path.is_file():
        return JSONResponse({"error": "还没有评测结果，先运行 python -m app.runner.evaluate"}, status_code=404)
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def run() -> None:
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    run()
