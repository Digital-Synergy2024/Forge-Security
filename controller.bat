@echo off
REM ============================================================================
REM  FORGE/DB - controller.bat   (BUILD-ONLY orchestration)
REM  Digital-Synergy LLC
REM ----------------------------------------------------------------------------
REM  Pipeline:
REM    1. Verify Python + pip
REM    2. Create / reuse a local virtual environment (.venv)
REM    3. Install dependencies FROM requirements.txt ONLY  (hard-fail if missing)
REM    4. Smoke-check the app (dependency doctor)
REM    5. Clean previous build artifacts
REM    6. Build the onefile windowed EXE with PyInstaller
REM    7. Verify dist\FORGE-DB.exe exists and report a summary
REM
REM  This script does NOT deploy anything. It only builds the executable locally.
REM ============================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "APPNAME=FORGE-DB"
set "ENTRY=forge_vps_security.py"
set "SPEC=forge_vps_security.spec"
set "REQ=requirements.txt"
set "VENV=.venv"
set "EXE=dist\%APPNAME%.exe"

echo.
echo ============================================================
echo   FORGE/DB build controller
echo ============================================================
echo.

REM --- [1/7] Python + pip ----------------------------------------------------
echo [1/7] Checking Python...
set "BOOTPY="

REM Prefer the official 'py' launcher (avoids the Windows Store alias stub).
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "BOOTPY=py -3"
) else (
    REM Fall back to 'python', but make sure it is a REAL interpreter and
    REM not the Microsoft Store execution-alias stub.
    python --version >nul 2>&1
    if not errorlevel 1 (
        for /f "delims=" %%V in ('python --version 2^>^&1') do set "PYVER=%%V"
        echo !PYVER! | findstr /i /c:"Python" >nul 2>&1
        if not errorlevel 1 set "BOOTPY=python"
    )
)

if not defined BOOTPY (
    echo   ERROR: No working Python interpreter was found.
    echo   Install Python 3.10+ from https://www.python.org/ ^(check "Add to PATH"^),
    echo   or disable the Windows Store alias: Settings ^> Apps ^> Advanced app
    echo   settings ^> App execution aliases ^> turn OFF python.exe / python3.exe.
    goto :fail
)

%BOOTPY% --version
%BOOTPY% -m pip --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: pip is not available for this Python install.
    echo   Try: %BOOTPY% -m ensurepip --upgrade
    goto :fail
)

REM --- enforce requirements.txt-only policy ----------------------------------
if not exist "%REQ%" (
    echo   ERROR: %REQ% not found.
    echo   controller.bat installs dependencies from %REQ% ONLY and cannot continue without it.
    goto :fail
)

REM --- [2/7] Virtual environment ---------------------------------------------
echo.
echo [2/7] Preparing virtual environment (%VENV%)...
if not exist "%VENV%\Scripts\python.exe" (
    %BOOTPY% -m venv "%VENV%"
    if errorlevel 1 (
        echo   ERROR: failed to create virtual environment.
        goto :fail
    )
    echo   Created %VENV%.
) else (
    echo   Reusing existing %VENV%.
)
set "PY=%VENV%\Scripts\python.exe"

REM --- [3/7] Install dependencies FROM requirements.txt ONLY -----------------
echo.
echo [3/7] Installing dependencies from %REQ%...
REM NOTE: do NOT self-upgrade pip here. On Windows the running pip.exe locks
REM its own files and the upgrade can corrupt the freshly created venv.
"%PY%" -m pip install --no-input -r "%REQ%"
if errorlevel 1 (
    echo   ERROR: dependency installation failed.
    echo   If the venv looks corrupted, delete the %VENV% folder and re-run.
    goto :fail
)

REM --- [4/7] Smoke check ------------------------------------------------------
echo.
echo [4/7] Running dependency doctor...
"%PY%" "%ENTRY%" doctor
if errorlevel 1 (
    echo   ERROR: dependency doctor reported missing required libraries.
    goto :fail
)

REM --- [5/7] Clean previous artifacts ----------------------------------------
echo.
echo [5/7] Cleaning previous build artifacts...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
echo   Clean.

REM --- [6/7] Build with PyInstaller ------------------------------------------
echo.
echo [6/7] Building %APPNAME%.exe with PyInstaller...
if exist "%SPEC%" (
    "%PY%" -m PyInstaller --noconfirm "%SPEC%"
) else (
    "%PY%" -m PyInstaller --noconfirm --onefile --windowed --name "%APPNAME%" ^
        --collect-all customtkinter ^
        --hidden-import pymysql --hidden-import pymysql.cursors ^
        --add-data "assets;assets" --icon "assets\img\icon.ico" "%ENTRY%"
)
if errorlevel 1 (
    echo   ERROR: PyInstaller build failed.
    goto :fail
)

REM --- [7/7] Verify output ----------------------------------------------------
echo.
echo [7/7] Verifying build output...
if not exist "%EXE%" (
    echo   ERROR: expected artifact not found: %EXE%
    goto :fail
)

for %%I in ("%EXE%") do set "EXESIZE=%%~zI"
echo.
echo ============================================================
echo   BUILD SUCCEEDED
echo   Artifact : %CD%\%EXE%
echo   Size     : !EXESIZE! bytes
echo ============================================================
echo.
echo   Reminder: keep the .exe OUTSIDE C:\xampp\htdocs and run it only over RDP.
echo.
echo Press any key to close this window...
pause >nul
endlocal
exit /b 0

:fail
echo.
echo ============================================================
echo   BUILD FAILED - see the error above.
echo ============================================================
echo.
echo Press any key to close this window...
pause >nul
endlocal
exit /b 1
