@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set "LAN_TRANSFER_SERVER=%~dp0server.py"
set "LAN_TRANSFER_BUNDLED_PYTHON=%~dp0python\python.exe"
set "LAN_TRANSFER_RUN_BAT=%~f0"
set "LAN_TRANSFER_WORKING_DIR=%~dp0"
set "LAN_TRANSFER_STARTUP_LINK=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\LAN Transfer.lnk"
set "OPEN_BROWSER=--open-browser"
if /i "%~1"=="--autostart" (
  set "OPEN_BROWSER="
  goto check_running
)

REM Register this portable folder for the current Windows user at sign-in.
powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; $shell = New-Object -ComObject WScript.Shell; $shortcut = $shell.CreateShortcut($env:LAN_TRANSFER_STARTUP_LINK); $shortcut.TargetPath = $env:ComSpec; $quote = [string][char]34; $shortcut.Arguments = '/d /c ' + $quote + $quote + $env:LAN_TRANSFER_RUN_BAT + $quote + ' --autostart' + $quote; $shortcut.WorkingDirectory = $env:LAN_TRANSFER_WORKING_DIR; $shortcut.WindowStyle = 7; $shortcut.Description = 'LAN Transfer'; $shortcut.Save()" >nul
if errorlevel 1 echo 无法配置开机自启动，请检查当前用户的 Startup 文件夹权限。

:check_running
REM Avoid starting a second copy when the startup shortcut and run.bat overlap.
powershell.exe -NoProfile -Command "$script = [regex]::Escape($env:LAN_TRANSFER_SERVER); $running = Get-CimInstance Win32_Process -Filter 'Name LIKE ''python%%.exe''' | Where-Object { $_.CommandLine -match ('(?:^|\s)(?:\x22' + $script + '\x22|' + $script + ')(?:\s|$)') -or ($_.ExecutablePath -eq $env:LAN_TRANSFER_BUNDLED_PYTHON -and $_.CommandLine -match '(?:^|\s)\x22?server\.py\x22?(?:\s|$)') }; if ($running) { exit 10 }" >nul
if "%ERRORLEVEL%"=="10" (
  echo 局域网传输服务已经在运行。
  goto finish
)

REM 0) Bundled embeddable Python (portable zip layout)
if exist "%~dp0python\python.exe" (
  "%~dp0python\python.exe" "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
  goto end
)

REM 1) Python Launcher for Windows
where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
  goto end
)

REM 2) python / python3 already in PATH
where python >nul 2>nul
if not errorlevel 1 (
  python "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
  goto end
)
where python3 >nul 2>nul
if not errorlevel 1 (
  python3 "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
  goto end
)

REM 3) WorkBuddy portable Python (default env)
if exist "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" (
  "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
  goto end
)
REM 3b) WorkBuddy other python versions
for /d %%G in ("%USERPROFILE%\.workbuddy\binaries\python\versions\*") do (
  if exist "%%G\python.exe" (
    "%%G\python.exe" "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
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
    %%P "%LAN_TRANSFER_SERVER%" --no-prompt %OPEN_BROWSER%
    goto end
  )
)

echo =============================================================
echo   未找到 Python 3.9+，无法启动服务。
echo   若本包应含便携解释器：请确认同级有 python\python.exe。
echo   或安装系统 Python，并勾选 "Add python.exe to PATH"。
echo   下载地址：https://www.python.org/downloads/
echo   无 Python 机器请改用「便携嵌入包」lan-transfer-portable-win64.zip。
echo =============================================================
if /i not "%~1"=="--autostart" pause
exit /b 1

:end
set "RUN_EXIT=%ERRORLEVEL%"
if /i "%~1"=="--autostart" exit /b %RUN_EXIT%
echo.
pause
exit /b %RUN_EXIT%

:finish
exit /b 0
