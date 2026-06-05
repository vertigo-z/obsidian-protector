@echo off
echo Make sure all the relevant build files are in this current folder, or the bat will fail.
echo Standby...
timeout 5 > nul

echo Building resource file...
.\windres.exe resource.rc -o resource.o
if %errorlevel% neq 0 (
    echo Failed to compile resource.c
)

timeout 2 > nul

echo Building crypter...
.\gcc.exe obsidian.c resource.o -o obsidian.exe -lbcrypt -I.
if %errorlevel% neq 0 (
    echo Failed to compile adv-crypter.c
)

echo Build completed successfully!
timeout 3 > nul
