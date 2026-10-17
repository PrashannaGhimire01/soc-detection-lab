@echo off
REM Wazuh Active Response wrapper (Windows).
REM Wazuh runs this .cmd and pipes the alert JSON to its stdin; we hand that
REM straight to PowerShell, which reads it and disables the compromised account.
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0disable-account.ps1"
