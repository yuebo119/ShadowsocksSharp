@echo off
REM Shadowsocks Sharp - Proxy Test Script
REM Run this script to test if the proxy is working correctly

echo ===========================================
echo   Shadowsocks Sharp - Proxy Test Script
echo ===========================================
echo.

set PROXY_HOST=127.0.0.1
set PROXY_PORT=1080

REM Check if curl is available
where curl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: curl is not installed or not in PATH
    echo Please install curl or use the built-in test: ShadowsocksSharp.exe --test
    pause
    exit /b 1
)

echo Testing HTTP Proxy at %PROXY_HOST%:%PROXY_PORT%
echo.

echo 1. Testing HTTP proxy (GET request)...
curl -x http://%PROXY_HOST%:%PROXY_PORT% http://httpbin.org/ip -s -o nul -w "   Status: %%{http_code}, Time: %%{time_total}s\n"
if %ERRORLEVEL% neq 0 (
    echo    FAILED - HTTP proxy test failed
    goto :error
)
echo    PASSED

echo.
echo 2. Testing HTTPS proxy (CONNECT tunnel)...
curl -x http://%PROXY_HOST%:%PROXY_PORT% https://api.ipify.org?format=json -s
echo.
if %ERRORLEVEL% neq 0 (
    echo    FAILED - HTTPS proxy test failed
    goto :error
)
echo    PASSED

echo.
echo 3. Testing SOCKS5 proxy...
curl --socks5-hostname %PROXY_HOST%:%PROXY_PORT% https://httpbin.org/ip -s
echo.
if %ERRORLEVEL% neq 0 (
    echo    FAILED - SOCKS5 proxy test failed
    goto :error
)
echo    PASSED

echo.
echo ===========================================
echo   All proxy tests PASSED!
echo ===========================================
echo.
echo Your proxy is working correctly.
echo.
goto :end

:error
echo.
echo ===========================================
echo   Some tests FAILED
echo ===========================================
echo.
echo Please check:
echo   1. Is the proxy server running? (ShadowsocksSharp.exe)
echo   2. Is the SS server accessible?
echo   3. Are the credentials correct?
echo.

:end
pause
