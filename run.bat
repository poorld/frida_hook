@echo off
setlocal enabledelayedexpansion

REM Get the directory of the batch script, which is the project root
set "PROJECT_ROOT=%~dp0"

REM --- Configuration ---
set "SRC_DIR=%PROJECT_ROOT%src\entries"
set "DIST_DIR=%PROJECT_ROOT%dist"

REM --- Argument Parsing ---
set "SPAWN_MODE=false"
if /i "%1"=="-f" (
    set "SPAWN_MODE=true"
    shift /1
)

set "SCRIPT_NAME=%1"
set "TARGET=%2"

REM --- Validate Script Name ---
if not defined SCRIPT_NAME (
    echo [ERROR] No script name provided.
    echo.
    echo Usage: run.bat [-f] [script_name] [process_or_package_name]
    echo.
    echo   -f : Spawn the application instead of attaching.
    echo.
    echo Available scripts:
    for /f "tokens=*" %%f in ('dir /b "%SRC_DIR%\*.js"') do (
        echo   - %%~nf
    )
    goto :eof
)

REM --- Validate Target ---
if not defined TARGET (
    echo [ERROR] No target process or package name provided.
    echo.
    echo Usage: run.bat %SCRIPT_NAME% [process_name_or_pid]
    echo   or:  run.bat -f %SCRIPT_NAME% [package_name]
    goto :eof
)

set "SCRIPT_PATH=%SRC_DIR%\%SCRIPT_NAME%.js"
set "BUNDLE_PATH=%DIST_DIR%\%SCRIPT_NAME%.bundle.js"

REM --- Check if source script exists ---
if not exist "%SCRIPT_PATH%" (
    echo [ERROR] Source script not found: %SCRIPT_PATH%
    goto :eof
)

REM --- Create dist directory if it doesn't exist ---
if not exist "%DIST_DIR%" (
    echo [INFO] Creating build directory: %DIST_DIR%
    mkdir "%DIST_DIR%"
)

echo.
echo [1/3] Script:      %SCRIPT_NAME%
echo [2/3] Compiling:   %SCRIPT_PATH%
if "%SPAWN_MODE%"=="true" (
    echo [3/3] Spawning:    %TARGET%
) else (
    echo [3/3] Attaching to:  %TARGET%
)
echo.

call frida-compile "%SCRIPT_PATH%" -o "%BUNDLE_PATH%"

if %errorlevel% neq 0 (
    echo [ERROR] Script compilation failed! See messages above.
    pause
    goto :eof
)

echo [SUCCESS] Compilation successful: %BUNDLE_PATH%
echo.

REM --- Frida Execution ---
if "%SPAWN_MODE%"=="true" (
    echo [INFO] Spawning and attaching...
    call frida -U -f "%TARGET%" -l "%BUNDLE_PATH%"
) else (
    echo [INFO] Attaching to existing process...
    call frida -U -l "%BUNDLE_PATH%" "%TARGET%"
)

if %errorlevel% neq 0 (
    echo [ERROR] Frida command failed. See messages above.
    pause
    goto :eof
)

echo.
echo [SUCCESS] Script execution finished.
endlocal