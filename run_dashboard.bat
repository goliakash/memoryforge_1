@echo off
title Hindsight SecOps Memory Agent
echo ========================================================
echo  Starting Hindsight SecOps ^& Compliance Memory Agent...
echo ========================================================
cd /d " %~dp0\
python backend/run.py
pause
