@echo off
setlocal
cd /d "%~dp0"

py -3 --version >nul 2>nul
if errorlevel 1 goto try_python
py -3 server.py --open-browser
goto finished

:try_python
python --version >nul 2>nul
if errorlevel 1 goto no_python
python server.py --open-browser
goto finished

:no_python
echo Python 3.9 or newer was not found. Install Python and add it to PATH.
pause
endlocal
exit /b 1

:finished
set "server_exit_code=%errorlevel%"
endlocal & exit /b %server_exit_code%
