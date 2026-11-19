@echo off
setlocal
chcp 65001 >nul
pushd "%~dp0"
call mvnw.cmd -B -ntp verify
if errorlevel 1 goto failed
java -Dfile.encoding=UTF-8 -jar target/secure-chat.jar demo
if errorlevel 1 goto failed
popd
echo.
echo Demo completed. Press any key to close.
pause >nul
exit /b 0
:failed
popd
echo.
echo Could not complete demo. See the error above.
pause
exit /b 1
