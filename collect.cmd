@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo Node.js not found on PATH. Install LTS from https://nodejs.org/
  exit /b 1
)

if not exist "node_modules\playwright" (
  echo Running npm install...
  call npm install
  if errorlevel 1 exit /b 1
)

echo.
echo Entra Collect
echo   mode       auto  ^(Azure CLI / Graph PowerShell, else browser^)
echo   passkeys   login-edge.cmd
echo              node collect.js --auth browser --cdp http://127.0.0.1:9222 --tenant ^<guid^>
echo   help       node collect.js --help
echo.

node collect.js --auth auto %*
set ERR=%ERRORLEVEL%
echo.
if %ERR% neq 0 (
  echo Collector exited with code %ERR%
  exit /b %ERR%
)
echo Done.
echo   report     output_*\00_REPORT.html
echo   workbook   output_*\00_Remediation_Plan.xlsx
echo   rebuild    node report.js output_YYYY-MM-DD_HHMM
echo   resume     node collect.js --resume output_YYYY-MM-DD_HHMM
exit /b 0
