::RUn this script on gateway's system
@echo off
echo Generating self-signed certificate for gateway...

:: Get the local IP address (first non-loopback IPv4)
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /r "IPv4.*[0-9][0-9]*\.[0-9]"') do (
    set GATEWAY_IP=%%a
    goto :found
)

:found
:: Trim leading space
set GATEWAY_IP=%GATEWAY_IP: =%

echo Using IP: %GATEWAY_IP%

openssl req -x509 -newkey rsa:4096 -nodes ^
    -keyout gateway.key ^
    -out gateway.crt ^
    -days 365 ^
    -subj "/CN=%GATEWAY_IP%" ^
    -addext "subjectAltName=IP:%GATEWAY_IP%"

echo.
echo Done! Files created:
echo   gateway.crt  (share this with edge devices)
echo   gateway.key  (keep this on the gateway only, never share)
echo.
pause