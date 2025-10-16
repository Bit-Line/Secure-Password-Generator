@echo off
pushd "%~dp0"
start "Generate-SecurePassword" "%windir%\system32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Sta -ExecutionPolicy Bypass -File "%~dp0Generate-SecurePassword.ps1"
popd