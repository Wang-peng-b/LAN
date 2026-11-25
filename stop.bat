@echo off
setlocal
chcp 65001 >nul

set "LAN_TRANSFER_ROOT=%~dp0"
set "LAN_TRANSFER_STARTUP_LINK=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\LAN Transfer.lnk"

powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; $root = $env:LAN_TRANSFER_ROOT; $server = [regex]::Escape((Join-Path $root 'server.py')); $bundled = Join-Path $root 'python\python.exe'; $link = $env:LAN_TRANSFER_STARTUP_LINK; if (Test-Path -LiteralPath $link) { $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($link); $run = Join-Path $root 'run.bat'; if ($shortcut.Arguments.IndexOf(([char]34 + $run + [char]34), [StringComparison]::OrdinalIgnoreCase) -ge 0) { Remove-Item -LiteralPath $link -Force; Write-Output '已移除开机自启动。' } }; $processes = @(Get-CimInstance Win32_Process -Filter 'Name LIKE ''python%%.exe''' | Where-Object { $_.CommandLine -match ('(?:^|\s)(?:\x22' + $server + '\x22|' + $server + ')(?:\s|$)') -or ($_.ExecutablePath -eq $bundled -and $_.CommandLine -match '(?:^|\s)\x22?server\.py\x22?(?:\s|$)') }); foreach ($process in $processes) { Stop-Process -Id $process.ProcessId -Force }; if ($processes.Count) { Write-Output ('已停止局域网传输服务，共停止 ' + $processes.Count + ' 个进程。') } else { Write-Output '未发现正在运行的局域网传输服务。' }"
set "STOP_EXIT=%ERRORLEVEL%"
if not "%STOP_EXIT%"=="0" echo 停止服务或移除启动项时发生错误，请查看上方信息。
echo.
pause
exit /b %STOP_EXIT%
