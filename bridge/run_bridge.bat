@echo off
REM SAT-1 bridge. Edit the ports below to match Device Manager.
REM One satellite radio (needs only 2 USB ports):
set VERSAL=COM7
set RADIO=COM5
set PY=python
cd /d %~dp0
%PY% sat_bridge.py --versal %VERSAL% --radio %RADIO%
REM Two satellite radios (full duplex, needs 3 USB ports) use this line instead:
REM %PY% sat_bridge.py --versal %VERSAL% --tx COM5 --rx COM6
pause
