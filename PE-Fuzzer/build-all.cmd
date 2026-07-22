@echo off
setlocal

rem Builds every fuzz target as its own binary under bin\PE-Fuzzer-<target>\.
rem Usage: build-all.cmd [Configuration] [Platform]   (defaults: Release x64)

set CONFIG=%~1
if "%CONFIG%"=="" set CONFIG=Release
set PLATFORM=%~2
if "%PLATFORM%"=="" set PLATFORM=x64

for %%T in (image sections rich imports exports relocations tls resources debug utils) do (
    echo === Building fuzz target: %%T ===
    msbuild "%~dp0PE-Fuzzer.vcxproj" /m /nologo /v:minimal ^
        /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /p:FuzzTarget=%%T
    if errorlevel 1 exit /b 1
)

echo All fuzz targets built.
