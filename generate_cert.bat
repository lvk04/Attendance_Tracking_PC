:: generate_cert.bat — run on each machine with appropriate hostname
:: Usage: generate_cert.bat <hostname.local>
:: Example: generate_cert.bat gateway.local
@echo off
set HOSTNAME=%~1
if "%HOSTNAME%"=="" (
    echo Usage: generate_cert.bat ^<hostname.local^>
    echo Example: generate_cert.bat gateway.local
    exit /b 1
)

echo Generating self-signed certificate for %HOSTNAME%...

openssl req -x509 -newkey rsa:4096 -nodes ^
    -keyout gateway.key ^
    -out gateway.crt ^
    -days 3650 ^
    -subj "/CN=%HOSTNAME%" ^
    -addext "subjectAltName=DNS:%HOSTNAME%,DNS:localhost,IP:127.0.0.1"

echo.
echo Done! Files created:
echo   gateway.crt  (share this with edge devices)
echo   gateway.key  (keep this on the gateway only, never share)
echo.
pause