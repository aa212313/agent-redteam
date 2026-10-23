@echo off
rem 建环境：只用相对路径，换机器直接跑
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [x] 未找到 python，请先安装 Python 3.10+
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/2] 创建虚拟环境 .venv ...
  python -m venv .venv
  if errorlevel 1 exit /b 1
)

echo [2/2] 安装依赖 ...
".venv\Scripts\python.exe" -m pip install -q --upgrade pip -i https://mirrors.cloud.tencent.com/pypi/simple/
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt -i https://mirrors.cloud.tencent.com/pypi/simple/
if errorlevel 1 exit /b 1

echo.
echo 环境就绪。下一步： run.bat
