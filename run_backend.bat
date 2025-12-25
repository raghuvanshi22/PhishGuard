@echo off
set "VENV_PYTHON=..\.venv\Scripts\python.exe"
set "GLOBAL_PYTHON=python"

if exist "%VENV_PYTHON%" (
    echo [INFO] Using Virtual Environment Python
    set "PYTHON_EXE=%VENV_PYTHON%"
) else (
    echo [INFO] Using Global Python (No .venv found)
    set "PYTHON_EXE=%GLOBAL_PYTHON%"
)

cd backend
set PYTHONUTF8=1
"%PYTHON_EXE%" -m uvicorn phishguard.api.app:app --reload
pause
