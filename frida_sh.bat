@echo off
setlocal

set SCRIPT_NAME=test.js
set BUNDLE_NAME=test.bundle.js

REM --- Check if a command-line argument was provided ---
if not "%1"=="" (
    REM If an argument exists, use it as the target process
    set TARGET_PROCESS=%1
    echo [INFO] Using target process from command-line argument: %TARGET_PROCESS%
) else (
    REM If no argument, fall back to prompting the user
    echo [INFO] No command-line argument found.
    set /p TARGET_PROCESS="Enter the process name or PID to attach: "
)

REM --- Validate that we have a target process name ---
if "%TARGET_PROCESS%"=="" (
    echo [ERROR] No process name or PID was provided.
    pause
    exit /b 1
)

if not exist "%SCRIPT_NAME%" (
    echo [ERROR] Source file not found: %SCRIPT_NAME%
    pause
    exit /b 1
)

echo.
echo [1/2] Compiling script: %SCRIPT_NAME% ...
call frida-compile %SCRIPT_NAME% -o %BUNDLE_NAME%

if %errorlevel% neq 0 (
    echo [ERROR] Script compilation failed! See the message above for details.
    pause
    exit /b 1
)

echo Compilation successful: %BUNDLE_NAME%
echo.
echo [2/2] Attaching to process: %TARGET_PROCESS% ...
call frida -U -l %BUNDLE_NAME% %TARGET_PROCESS%

if %errorlevel% neq 0 (
    echo [ERROR] Frida attach failed. Check device connection and process name/PID.
    pause
    exit /b 1
)

echo.
echo Script execution finished.
pause
endlocal