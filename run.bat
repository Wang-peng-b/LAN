@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

REM 1) Python Launcher for Windows
where py >nul 2>nul
if not errorlevel 1 (
  py -3 server.py --no-prompt --open-browser
  goto end
)

REM 2) python / python3 already in PATH
where python >nul 2>nul
if not errorlevel 1 (
  python server.py --no-prompt --open-browser
  goto end
)
where python3 >nul 2>nul
if not errorlevel 1 (
  python3 server.py --no-prompt --open-browser
  goto end
)

REM 3) WorkBuddy portable Python (default env)
if exist "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" (
  "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" server.py --no-prompt --open-browser
  goto end
)
REM 3b) WorkBuddy other python versions
for /d %%G in ("%USERPROFILE%\.workbuddy\binaries\python\versions\*") do (
  if exist "%%G\python.exe" (
    "%%G\python.exe" server.py --no-prompt --open-browser
    goto end
  )
)

REM 4) Common install locations (other PCs)
for %%P in (
  "%LocalAppData%\Programs\Python\Python313\python.exe"
  "%LocalAppData%\Programs\Python\Python312\python.exe"
  "%LocalAppData%\Programs\Python\Python311\python.exe"
  "%LocalAppData%\Programs\Python\Python310\python.exe"
  "%LocalAppData%\Programs\Python\Python39\python.exe"
  "%ProgramFiles%\Python313\python.exe"
  "%ProgramFiles%\Python312\python.exe"
  "%ProgramFiles%\Python311\python.exe"
  "%ProgramFiles%\Python310\python.exe"
  "%ProgramFiles%\Python39\python.exe"
) do (
  if exist %%P (
    %%P server.py --no-prompt --open-browser
    goto end
  )
)

echo =============================================================
echo   未找到 Python 3.9+，无法启动服务。
echo   请安装 Python，并勾选 "Add python.exe to PATH"。
echo   下载地址：https://www.python.org/downloads/
echo =============================================================

:end
echo.
pause
endlocal
