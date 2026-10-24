@echo off
REM ---------------------------------------------------------------------------
REM pythondeid scheduled refresh wrapper (Stonebranch Universal Task / SQL Agent CmdExec)
REM
REM   deid_refresh.cmd <profile> [connection] [extra refresh options]
REM   e.g.  deid_refresh.cmd external uat --with-files
REM
REM Environment (set on the task, never in this file):
REM   DEID_SECRET_KEY   masking key (from the scheduler's credential / vault)
REM   DEID_PYTHON       full path to the ActiveState python.exe (schedulers do not run "state shell")
REM   DEID_DB_PASSWORD  only for SQL-login connections (Windows authentication needs none)
REM
REM Exit code = pythondeid's exit code (0 success; see docs\scheduling.md for the full list).
REM ---------------------------------------------------------------------------
setlocal
set "PROFILE=%~1"
set "CONN=%~2"
if "%PROFILE%"=="" (
  echo DEID_RESULT status=CONFIG_ERROR exit_code=10 message=usage: deid_refresh.cmd ^<profile^> [connection]
  exit /b 10
)
if "%DEID_PYTHON%"=="" set "DEID_PYTHON=python"
set "CONN_ARG="
if not "%CONN%"=="" set "CONN_ARG=--connection %CONN%"
cd /d "%~dp0.."
"%DEID_PYTHON%" main.py --profile %PROFILE% %CONN_ARG% refresh %3 %4 %5 %6
exit /b %ERRORLEVEL%
