@echo off
set LOGFILE=%TEMP%\reg_log_enable.txt

echo [--- BATCH EXECUTION START ---] > %LOGFILE%
echo Current Directory: %CD% >> %LOGFILE%
echo Attempting to DELETE registry value to enable camera... >> %LOGFILE%

REM Attempt to enable the camera by DELETING the 'Value' key and redirect all output (2>&1) to the log
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /f 2>&1 >> %LOGFILE%

REM Check the exit code of the REG command
REM Error code 1 is often returned if the key didn't exist, which is fine for 'enabling'.
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: REGISTRY ENABLING FAILED. Error code: %ERRORLEVEL%. >> %LOGFILE%
) else (
    echo SUCCESS: REGISTRY ENABLING SUCCESSFUL. >> %LOGFILE%
)
echo [--- BATCH EXECUTION END ---] >> %LOGFILE%
