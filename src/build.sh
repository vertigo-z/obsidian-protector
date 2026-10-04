#!/bin/bash
echo "building stub object file..."
clang --target=x86_64-pc-windows-gnu -masm=intel -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -Oz -c stub.c -o stub.o
echo 'linking stub...'
x86_64-w64-mingw32-ld stub.o -o stub.exe -nostdlib --build-id=none -s --entry=_start
echo 'creating binary...'
x86_64-w64-mingw32-objcopy -O binary stub.exe stub.bin
echo 'compiling resources...'
x86_64-w64-mingw32-windres ../resource.rc -O coff -o resource.o -I. -I..
echo 'building final crypter binary...'
x86_64-w64-mingw32-gcc -D_WINDOWS -D_WIN64 -I. -I.. -O1 obsidian.c resource.o -o obsidian.exe -
echo "done"