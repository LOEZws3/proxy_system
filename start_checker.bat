@echo off
chcp 65001 >nul
title Proxy Checker
echo.
echo ========================================
echo   🔍 ЗАПУСК ПРОКСИ-ЧЕКЕРА (БЕСКОНЕЧНЫЙ)
echo ========================================
echo.

set PYTHON_PATH=C:\Users\olika\AppData\Local\Python\pythoncore-3.14-64\python.exe

if not exist "%PYTHON_PATH%" (
    echo ❌ Python не найден!
    pause
    exit
)

"%PYTHON_PATH%" proxy_checker.py

pause