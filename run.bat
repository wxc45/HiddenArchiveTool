@echo off
setlocal
pushd "%~dp0"
title HiddenArchiveTool

rem ---- 1) find a usable python (skip the Microsoft Store stub) ----
set "PY="

py -3 -c "import sys" >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto :start

python -c "import sys" >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto :start

if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if defined PY goto :start
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if defined PY goto :start
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY goto :start
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if defined PY goto :start
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if defined PY goto :start
if exist "C:/Python314/python.exe" set "PY=C:/Python314/python.exe"
if defined PY goto :start
if exist "C:/Python313/python.exe" set "PY=C:/Python313/python.exe"
if defined PY goto :start
if exist "C:/Python312/python.exe" set "PY=C:/Python312/python.exe"
if defined PY goto :start
goto :nopython

:start
echo Using interpreter: %PY%
echo.
%PY% "%~dp0launcher.py"
echo.
echo --- finished, press any key to close ---
pause >nul
popd
exit /b 0

:nopython
echo.
echo  [ERROR] Python was not found on this computer.
echo.
echo   1) Install Python 3.9+ :  https://www.python.org/downloads/
echo   2) During setup, tick  "Add python.exe to PATH"
echo   3) Then double-click run.bat again
echo.
echo  Already installed? Edit this file and set PY to your python.exe path.
echo.
pause
popd
exit /b 1
