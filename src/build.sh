#!/bin/bash
echo "building stub object file..."
clang --target=x86_64-pc-windows-gnu -masm=intel -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -Oz -c stub.c -o stub.o
echo 'linking stub...'
x86_64-w64-mingw32-ld stub.o -o stub.exe -nostdlib --build-id=none -s --entry=_start
echo 'creating binary...'
x86_64-w64-mingw32-objcopy -O binary stub.exe stub.bin
echo 'building arm64 stub...'
if command -v aarch64-w64-mingw32-ld >/dev/null 2>&1 && command -v aarch64-w64-mingw32-objcopy >/dev/null 2>&1; then
    clang --target=aarch64-pc-windows-gnu -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -Oz -c stub-arm64.c -o stub-arm64.o
    aarch64-w64-mingw32-ld stub-arm64.o -o stub-arm64.exe -nostdlib --build-id=none -s --entry=_start
    aarch64-w64-mingw32-objcopy -O binary stub-arm64.exe stub-arm64.bin
else
    echo 'no arm64 build tools found, copying prebuilt stub from ../stubs...'
    cp ../stubs/stub-arm64.bin stub-arm64.bin || { echo 'error: ../stubs/stub-arm64.bin not found'; exit 1; }
fi
echo 'compiling resources...'
x86_64-w64-mingw32-windres ../resource.rc -O coff -o resource.o -I. -I..
echo 'building final crypter binary...'
x86_64-w64-mingw32-gcc -D_WINDOWS -D_WIN64 -I. -I.. -O1 obsidian.c resource.o -o obsidian.exe -lbcrypt
echo "done"
