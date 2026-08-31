:; printf '{}\n'; exit 0
@echo off
rem Windows entry point for the TrustGuard GitHub Copilot plugin hooks. The first line
rem is the POSIX half of the polyglot: unix only reaches this file when
rem trustguard-hook.sh exited non-zero without answering, so it fails open
rem rather than handing GitHub Copilot an empty stdout. cmd.exe reads it as a label
rem and continues here.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0trustguard-hook.ps1" -Event "%~1"
exit /b %errorlevel%
