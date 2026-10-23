@echo off
rem 一条命令：跑矩阵评测 -> 生成报告 -> 起看板
rem 用法： run.bat            本地脚本模型（离线、可复现）
rem        run.bat ollama     接本地 Ollama 模型
rem        run.bat deepseek   接 DeepSeek（需在 .env 配 DEEPSEEK_API_KEY）
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  call setup.bat
  if errorlevel 1 exit /b 1
)

set PY=.venv\Scripts\python.exe
set PROVIDER=%1
if "%PROVIDER%"=="" (
  "%PY%" -m app.runner.evaluate
) else (
  "%PY%" -m app.runner.evaluate --provider %PROVIDER%
)

echo.
echo 看板： http://127.0.0.1:8000  （Ctrl+C 结束）
"%PY%" -m app.main
