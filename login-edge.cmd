@echo off
REM Launch Microsoft Edge for Entra Collect CDP attach (Windows).
REM Use a NON-default --user-data-dir so --remote-debugging-port is honored (Edge 136+).
setlocal EnableExtensions EnableDelayedExpansion

set "PORT=%~1"
if "%PORT%"=="" set "PORT=9222"
set "URL=%~2"
if "%URL%"=="" set "URL=https://entra.microsoft.com"

set "ROOT=%~dp0"
REM Profile holds live portal session cookies for the target tenant — keep it
REM out of the tool folder so it never lands in an engagement archive.
if defined ENTRA_COLLECT_PROFILE_DIR (
  set "PROFILE=%ENTRA_COLLECT_PROFILE_DIR%\msedge-cdp"
) else (
  set "PROFILE=%LOCALAPPDATA%\entra-collect\profiles\msedge-cdp"
)
set "EDGE="

if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "EDGE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"

if "%EDGE%"=="" (
  echo Microsoft Edge not found under Program Files.
  exit /b 1
)

if not exist "%PROFILE%" mkdir "%PROFILE%" 2>nul

curl -sf "http://127.0.0.1:%PORT%/json/version" >nul 2>&1
if not errorlevel 1 (
  echo Entra Collect — CDP already listening on port %PORT%.
  call :next
  exit /b 0
)

echo Entra Collect — opening Edge
echo   profile    %PROFILE%
echo   CDP        http://127.0.0.1:%PORT%
echo   sign-in    dedicated profile — sign in again in this window
echo.

REM No --remote-allow-origins: Playwright attaches without an Origin header, and the
REM flag would let any web page talk to the debugging socket of an admin session.
start "" "%EDGE%" --remote-debugging-port=%PORT% --user-data-dir="%PROFILE%" --no-first-run --no-default-browser-check "%URL%"

echo Waiting for CDP on port %PORT%...
for /L %%i in (1,1,60) do (
  curl -sf "http://127.0.0.1:%PORT%/json/version" >nul 2>&1
  if not errorlevel 1 goto :ok
  timeout /t 1 /nobreak >nul
)

echo ERROR: CDP not listening after ~60s.
echo   Confirm Edge started with --remote-debugging-port=%PORT%
echo   Or enable remote debugging in edge://inspect
exit /b 1

:ok
echo CDP OK.
call :next
exit /b 0

:next
echo.
echo Entra Collect — browser ready
echo   CDP        http://127.0.0.1:%PORT%
echo.
echo Sign in in that window, then from this folder:
echo   cd /d "%ROOT%"
echo   node collect.js --auth browser --cdp http://127.0.0.1:%PORT% --tenant ^<guid^>
echo.
echo Without --tenant the tool asks you to confirm the organisation name
echo before it writes anything.
echo.
echo When the run finishes:
echo   output_*\00_REPORT.html
echo   output_*\00_Remediation_Plan.xlsx
echo.
echo If a step failed:
echo   node collect.js --resume output_YYYY-MM-DD_HHMM
exit /b 0
