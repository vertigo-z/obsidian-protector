<p>
  <img align="center" width="800" height="100%" src="img/stars-only.png" alt="obsidian logo">
</p>
<p>
  <d><strong>obsidian community edition - universal pe packer</strong></d>
  <br/>
  <sup>advanced, open-source obfuscation</sup>
</p>
<p>
  <a href="https://obsidian.st/" target="_blank">
    <img alt="obsidian badge" src="https://img.shields.io/badge/*-obsidian-indigo?labelColor=indigo">
  </a>
  <a href="https://metrics.torproject.org/rs.html#details/714FCD4134044155A16A4EB440E30EF1F52B19B1" target="_blank">
    <img alt="tor native badge" src="https://img.shields.io/badge/tor%20native-purple?logo=torproject">
  </a>
  <a href="/stub.c">
    <img alt="nostdlib badge" src="https://img.shields.io/badge/nostdlib-grey?logo=C">
  </a>
</p>
<p> 
  <a href="https://obsidian.st" target="_blank">clearnet</a> • <a href="http://obsidiand244wsh2jnmqvnim2becs73dims5wc5hzse3o5ywvw6ryoyd.onion/" target="_blank">tor</a> • <a href="http://obsidian.i2p/?i2paddresshelper=edexepj4bnni4ct5otbivq73tjmyontztz5qa56qrni2rdldh4rq.b32.i2p" target="_blank">i2p</a>
</p>

---

## introduction:

obsidian is a custom universal pe packer / executable protector written in C. it is designed to be paired with a loader stub that decrypts and executes the packed payload. obsidian ce (community edition) supports ARM64 natively with a specialized stub. we also recently added support for pyinstalled exectuables with a special fork of the pyinstaller bootloader. see the **packing with pyinstaller** section below.

the stub included uses rolling xor obfuscation with shifts and does not contain any anti-debugging mechanisms. this packer/stub has been tested to work on putty.exe, strings.exe, and can even pack itself, and then pack other executables from the packed state. when the `--pyinstaller` flag is used and a `.py` file is targeted, obsidian uses pyinstaller to build an exe and then immediately obfuscates and outputs the file.

full source for both arm64 and amd64 stubs are included in this repo. feel free to modify it to suit your needs or to evade detection. 

---

<img align="center" width="1000" height="100%" src="img/splash.gif" alt="obsidian splashscreen">

---

## features:

**community edition-v1.4:**
* pyinstalled executables now supported
* ARM64 fully supported
* improved xor algorithm
* hash-based import lookups
* compiled xorshift64+ stub (stubs/stub.bin)
* high entropy ASLR support
* stub template (BYOS - bring your own stub)
* extensive debug output (-DDEBUG & --debug flags)
* randomized config marker
* zeroed out optional headers
* secure key generation
* checksum recalculation
* pe section manipulation
* progress bar and colors

## packing with pyinstaller:
in order to obfuscate a python script with obsidian, make sure that pyinstaller is installed on the system and is in your PATH, then run obsidian with the `--pyinstaller` flag against a .py file. obsidian will then use the system pyinstaller to build the package and then encrypt the output.
```
.\obsidian.ce.universal.exe --pyinstaller script.py obfuscated-py.exe
```
spec-files are supported however this is an experimental feature. submit an issue should you face a problem with it.

---

<a href="https://obsidian.st" target="_blank">
  <img align="center" width="1000" height="100%" src="img/ad.png" alt="obsidian logo">
</a>

## obsidian pro:
<a href="https://obsidian.st/"><img alt="Static Badge" src="https://img.shields.io/badge/available%20now-indigo"></a>

obsidian pro is an upgraded version of obsidian community edition with SPECK encryption, aPlib compression, and anti-debugging syscalls. it is licensed using open-source obsidian [keykeeper](https://github.com/vertigo6622/obsidian-keykeeper) which sits behind a clearnet-to-tor proxy, enabling anonymous license management.

**where to find:**
<p> 
  <a href="https://obsidian.st" target="_blank">clearnet</a> • <a href="http://obsidiand244wsh2jnmqvnim2becs73dims5wc5hzse3o5ywvw6ryoyd.onion/" target="_blank">tor</a> • <a href="http://obsidian.i2p/?i2paddresshelper=edexepj4bnni4ct5otbivq73tjmyontztz5qa56qrni2rdldh4rq.b32.i2p" target="_blank">i2p</a>
</p>

**pro edition features:**

* SPECK 128/128 CTR encryption
* aPlib compression (--compress)
* resource encryption
* extensive syscall anti-debug (--ultra)
* anti-sandbox
* hmac integrity checks
* [ollvm-22](https://github.com/vertigo6622/ollvm-22) obfuscated

---

## to-do:

**community edition:**
* qol (quality of life) improvements for pyinstaller
  * spec-file handling
  * arm64 code path
  * patch already built pyinstaller bundles
  * modified bootloaders as resources 
* remain updated to keep ahead of av detection

**commercial edition(future):**
* gui
* anti-dump protection
* license support/hardware binding
* online key provisioning
* DRM-like protections

## usage:
`.\obsidian.ce.universal.exe program.exe packed.exe`

<img align="center" width="1000" height="100%" src="img/putty.png" alt="putty debugging output">
<img align="center" width="1000" height="100%" src="img/die.png" alt="detect-it-easy">
<img align="center" width="1000" height="100%" src="img/die2.png" alt="detect-it-easy">

---

## ce obfuscation engine:

```C
void obfuscate_data(uint8_t* data, size_t size, uint64_t key) {
    uint8_t key_xor_aa = (uint8_t)(key ^ 0xAA);
    uint8_t key_xor_aa_shr8 = (uint8_t)((key ^ 0xAA) >> 8);
    
    for (size_t i = 0; i < size; i++) {
        uint64_t subkey = key ^ (i * 0x9E3779B97F4A7C15ULL);
        subkey = (subkey ^ (subkey >> 30)) * 0xBF58476D1CE4E5B9ULL;
        subkey = (subkey ^ (subkey >> 27)) * 0x94D049BB133111EBULL;
        subkey = subkey ^ (subkey >> 31);
        
        uint8_t shift1 = (uint8_t)((i * 8) & 0x3F);
        uint8_t shift2 = (uint8_t)((24 + i * 8) & 0x3F);
        uint8_t shift3 = (uint8_t)((56 + i * 8) & 0x3F);
        
        uint8_t mask = (uint8_t)(subkey >> shift1)
                     ^ (uint8_t)(subkey >> shift2)
                     ^ (uint8_t)(subkey >> shift3);
        
        data[i] ^= mask;
        data[i] += key_xor_aa;
        data[i] -= key_xor_aa_shr8;
    }
}
```
**obfuscation process:**
1. use constants to derive values for add and sub operations
2. mix in 'golden ratio' constants into a subkey to increase entropy
3. generate shifts and final mask variable
4. apply transformation to data

---

## stub reference sheet:

| | stub.bin | stub.Oz.bin | stub.obfuscated.bin | stub.full.obf.bin | stub-arm64.bin |
| :--- | :--- | :--- | :--- | :--- | :--- |
| description: | no optimization | aggressive size optimization | control flow flattening + instruction substitution | fully obfuscated (bogus control flow, splitting, flattening, substitution) | arm64 variant, -O1 optimized |
| size: | 17kb | 13kb | 17kb | 57kb | 5kb |
| tools: | clang/llvm | clang/llvm + Oz | clang/llvm + Oz + [ollvm-22](https://github.com/vertigo6622/ollvm-22) | clang/llvm + Oz + [ollvm-22](https://github.com/vertigo6622/ollvm-22) | clang/llvm + O1 |
| note: | basic | smallest/fastest | balanced | largest/slowest | now available in stubs/ folder |

## compile:
**requirements:** 

gcc:
* mingw64 tool suite available at `https://winlibs.com/`
* windbg or other debugger
* python interpreter for `clean.py`

llvm/clang:
* llvm 22 toolchain
* mingw64 tool suite

**arm64 requirements:**
* arm64 llvm/mingw64 toolchain (included in some bundles)

### amd64 commands:

**step 1: build stub object file**

gcc:
```
.\gcc.exe stub.c -o stub.o -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector
```

llvm/clang:
```
clang --target=x86_64-pc-windows-gnu \
    -I/llvm-mingw-20260311-ucrt-macos-universal/generic-w64-mingw32/include \
    -masm=intel \
    -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -Oz \
    -c stub.c -o stub.o
```

**step 2: link and strip stub binary**

both:
```
.\ld.exe stub.o -o stub.exe -nostdlib --build-id=none -s --entry=_start
```
```
.\objcopy.exe -O binary stub.exe stub.bin
```
```
.\windres.exe resource.rc -o resource.o
```

**step 3: build obsidian ce**

gcc:
```
.\gcc.exe obsidian.c resource.o -o obsidian.exe -lbcrypt
```

llvm/clang:
```
x86_64-w64-mingw32-clang \
  -I/llvm-mingw-20260311-ucrt-macos-universal/generic-w64-mingw32/include -O1 \
  obsidian.c resource.o -o obsidian.exe -lbcrypt
```

### arm64 commands:

**step 1: build stub object file**

```
/llvm/llvm-mingw-20260311-ucrt-macos-universal/bin/aarch64-w64-mingw32-clang \
  -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -O1 \
  -c stub-arm64.c -o stub-arm64.o
```

**step 2: link and strip stub binary**

```
.\ld.lld.exe stub.o -o stub.exe --build-id=none -s --entry=_start
```
```
.\objcopy.exe -O binary stub.exe stub.bin
```
```
.\windres.exe resource.rc -o resource.o
```
**note:** resource file step must happen after both arm64 and amd64 stubs are in .bin format

**step 3: build obsidian ce**

gcc:
```
.\gcc.exe obsidian.c resource.o -o obsidian.exe -lbcrypt
```

llvm/clang:
```
x86_64-w64-mingw32-clang \
  -I/llvm-mingw-20260311-ucrt-macos-universal/generic-w64-mingw32/include -O1 \
  obsidian.c resource.o -o obsidian.exe -lbcrypt
```
---

<p align="center">
  <a href="https://deepwiki.com/vertigo6622/obsidian-protector"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
  <a href="/LICENSE"><img alt="License used by repo" src="https://img.shields.io/badge/license-ACSL%201.4-indigo"></a>
  <img alt="Approximate number of clones" src="https://img.shields.io/badge/clones-1300%2B-orange">
  <a href="https://docs.obsidian.st" target="_blank">
    <img alt="Static Badge" src="https://img.shields.io/badge/view%20the%20docs-blue">
  </a>
</p>
<p align="center">
  <img alt="arm64 supported" src="https://img.shields.io/badge/architecture-ARM64-blue">
  <img alt="amd64 supported" src="https://img.shields.io/badge/architecture-AMD64-orange">
  <a href="https://obsidian.st/donate" target="_blank">
    <img alt="donation button" src="https://img.shields.io/badge/donate-red">
  </a>
</p>





