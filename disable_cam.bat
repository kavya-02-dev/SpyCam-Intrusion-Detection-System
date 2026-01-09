@echo off
REM --- Log file path is guaranteed to be in the Windows TEMP folder ---
set LOGFILE=%TEMP%\reg_log_disable.txt

echo [--- BATCH EXECUTION START ---] > %LOGFILE%
echo Current Directory: %CD% >> %LOGFILE%
echo Attempting to ADD/SET registry value to disable camera... >> %LOGFILE%

REM Attempt to disable the camera (Value=0) and redirect all output (2>&1) to the log
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_DWORD /d 0 /f 2>&1 >> %LOGFILE%

REM Check the exit code of the REG command
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: REGISTRY DISABLING FAILED. Error code: %ERRORLEVEL% >> %LOGFILE%
) else (
    echo SUCCESS: REGISTRY DISABLING SUCCESSFUL. >> %LOGFILE%
)
echo [--- BATCH EXECUTION END ---] >> %LOGFILE%
