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
  echo Entra Collect — CDP already up on port %PORT%.
  echo   cd /d "%ROOT%"
  echo   node collect.js --auth browser --cdp http://127.0.0.1:%PORT%
  exit /b 0
)

echo Entra Collect — starting Edge ^(dedicated CDP profile^)...
echo   profile: %PROFILE%
echo   CDP:     http://127.0.0.1:%PORT%
echo.
echo Sign in in that Edge window ^(Authenticator / Windows Hello / QR^), then:
echo   node collect.js --auth browser --cdp http://127.0.0.1:%PORT%
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
echo CDP OK — ready for Entra Collect.
echo.
echo   cd /d "%ROOT%"
echo   node collect.js --auth browser --cdp http://127.0.0.1:%PORT%
echo   Help: node collect.js --help
exit /b 0
