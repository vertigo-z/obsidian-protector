#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_DIR64    10

typedef struct {
    uint32_t virtual_address;
    uint32_t raw_offset;
    uint32_t raw_size;
} SECTION_INFO;

#pragma pack(push, 1)
typedef struct {
    uint64_t key;
    uint32_t original_oep;
    uint32_t encrypted_start_rva;
    uint32_t encrypted_size;
    uint64_t image_base;
    uint32_t sections_rva;
    uint32_t stub_code_size;
    uint32_t import_rva;
    uint32_t import_size;
    uint32_t resource_rva;
    uint32_t resource_size;
    uint32_t tls_rva;
    uint32_t tls_size;
    uint32_t exception_rva;
    uint32_t exception_size;
    uint32_t reloc_rva;
    uint32_t reloc_size;
    uint8_t section_count;
    uint32_t overlay_rva;
    uint32_t overlay_size;
    uint8_t py;
} STUB_CONFIG;
#pragma pack(pop)

typedef void* (WINAPI *fn_VirtualAlloc)(void*, size_t, DWORD, DWORD);
typedef BOOL (WINAPI *fn_VirtualProtect)(void*, size_t, DWORD, DWORD*);
typedef BOOL (WINAPI *fn_VirtualFree)(void*, size_t, DWORD);
typedef void (WINAPI *fn_OutputDebugStringA)(LPCSTR);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);

typedef struct _STUB_RUNTIME {
    fn_VirtualAlloc pVirtualAlloc;
    fn_VirtualProtect pVirtualProtect;
    fn_VirtualFree pVirtualFree;
    fn_OutputDebugStringA pOutputDebugStringA;
    fn_LoadLibraryA pLoadLibraryA;
    fn_GetProcAddress pGetProcAddress;
    fn_GetModuleHandleA pGetModuleHandleA;
} STUB_RUNTIME;

void debug_print(STUB_RUNTIME* rt, const char* msg);
void debug_print_hex(STUB_RUNTIME* rt, const char* name, uint64_t value);
void debug_print_dec(STUB_RUNTIME* rt, const char* name, uint64_t value);
void xorshift64_plus(uint8_t* data, size_t size, uint64_t key);
void position_independent_entry(void);

void SecureWipe(unsigned char* ptr, size_t len) {
    volatile unsigned char* p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

static uint32_t crc32_hash_str(const char* str) {
    uint32_t crc = 0xFFFFFFFF;
    uint32_t poly = 0x82F63B78;
    while (*str) {
        uint8_t c = (uint8_t)*str;
        if (c >= 'a' && c <= 'z') c -= 32;
        crc ^= c;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (poly & -(int32_t)(crc & 1));
        }
        str++;
    }
    return ~crc;
}

void resolve_imports(STUB_RUNTIME* rt) {
    void* peb = (void*)__readgsqword(0x60);

    void* ldr = *(void**)((uint8_t*)peb + 0x18);
    void* list_head = *(void**)((uint8_t*)ldr + 0x20);
    void* current = list_head;

    void* k32 = NULL;
    
    for (int i = 0; i < 10; i++) {
        current = *(void**)current;
        if (current == list_head) break;
        void* base = *(void**)((uint8_t*)current + 0x20);
        if (!base) continue;
        wchar_t* n = *(wchar_t**)((uint8_t*)current + 0x50);
        uint16_t l = *(uint16_t*)((uint8_t*)current + 0x48) / 2;
        char name[64];
        int j;
        for (j = 0; j < l && j < 63; j++) name[j] = (char)n[j];
        name[j] = 0;
        uint32_t h = crc32_hash_str(name);
        if (h == 0xB37B13DA) { k32 = base; break; }
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)k32;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(k32 + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* exp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(k32 + exp_dir->VirtualAddress);
    
    uint32_t* names = (uint32_t*)(k32 + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)(k32 + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)(k32 + exports->AddressOfFunctions);

    const char* req_funcs[] = {
        "VirtualAlloc", "VirtualProtect", "VirtualFree",
        "OutputDebugStringA", "GetProcAddress",
        "LoadLibraryA", "GetModuleHandleA"
    };

    void** ptrs[] = {
	    (void**)&rt->pVirtualAlloc, (void**)&rt->pVirtualProtect, (void**)&rt->pVirtualFree,
	    (void**)&rt->pOutputDebugStringA, (void**)&rt->pGetProcAddress,
	    (void**)&rt->pLoadLibraryA, (void**)&rt->pGetModuleHandleA
    };

    for (int i = 0; i < 7; i++) {
        for (uint32_t j = 0; j < exports->NumberOfNames; j++) {
            char* name = (char*)(k32 + names[j]);
            const char* target = req_funcs[i];
            int match = 1;
            for (int k = 0; target[k] != 0; k++) {
                if (name[k] != target[k]) { match = 0; break; }
            }
            if (match) {
                uint16_t ordinal = ordinals[j];
                *ptrs[i] = (void*)(k32 + functions[ordinal]);
                break;
            }
        }
    }
}

void resolve_payload_imports(uint8_t* target_base, STUB_CONFIG* config, STUB_RUNTIME* rt) {
    if (!config->import_rva || !rt->pLoadLibraryA || !rt->pGetProcAddress) {
	    return;
    }
    uint8_t* base = target_base;
    IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)(base + config->import_rva);
    while (iid->Name) {
        char* dll_name = (char*)(base + iid->Name);
        HMODULE hMod = rt->pLoadLibraryA(dll_name);
        if (!hMod) {
            iid++;
            continue;
        }
        uint64_t* thunk = (uint64_t*)(base + iid->FirstThunk);
        uint64_t* orig_thunk = iid->OriginalFirstThunk ? (uint64_t*)(base + iid->OriginalFirstThunk) : thunk;
        while (*orig_thunk) {
            FARPROC proc = NULL;
            if (*orig_thunk & 0x8000000000000000ULL) {
                proc = rt->pGetProcAddress(hMod, (LPCSTR)(*orig_thunk & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* name_rec = (IMAGE_IMPORT_BY_NAME*)(base + *orig_thunk);
                proc = rt->pGetProcAddress(hMod, name_rec->Name);
            }
            if (proc) *thunk = (uint64_t)proc;
            thunk++;
            orig_thunk++;
        }
        iid++;
    }
}

void apply_relocations(STUB_RUNTIME* rt, uint8_t* current_base, uint8_t* original_image_base, IMAGE_DATA_DIRECTORY* reloc_dir, size_t image_size) {
    if (reloc_dir->VirtualAddress == 0 || reloc_dir->Size == 0) {
        return;
    }
    int64_t delta = (int64_t)current_base - (int64_t)original_image_base;
    #ifdef DEBUG 
        debug_print_hex(rt, "Reloc Delta", delta); 
    #endif
    if (delta == 0) {
        return;
    }
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(current_base + reloc_dir->VirtualAddress);
    IMAGE_BASE_RELOCATION* reloc_end = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc_dir->Size);
    while (reloc < reloc_end && reloc->VirtualAddress != 0 && reloc->SizeOfBlock != 0) {        
        if (reloc->VirtualAddress >= image_size) break; 
        if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        if ((uint8_t*)reloc + reloc->SizeOfBlock > (uint8_t*)reloc_end) break;
        uint8_t* page_rva = current_base + reloc->VirtualAddress;
        uint32_t num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        uint16_t* entry = (uint16_t*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        #ifdef DEBUG
            int relocs_processed = 0;
        #endif
        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t type = entry[i] >> 12;      
            uint16_t offset = entry[i] & 0x0FFF; 

            if (type == IMAGE_REL_BASED_DIR64) {
                if (reloc->VirtualAddress + offset + 8 > image_size) continue;
                uint64_t* target_ptr = (uint64_t*)(page_rva + offset);
                *target_ptr += delta;
                #ifdef DEBUG
                    relocs_processed += 1;
                #endif
            } 
        }
        #ifdef DEBUG
            debug_print_dec(rt, "Number of relocs processed", relocs_processed);
        #endif
        reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
    }
}

void manual_relocations(uint8_t* base, uint8_t* preferred_base, size_t image_size) {
    int64_t delta = (int64_t)base - (int64_t)preferred_base;
    if (delta == 0) return;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        uint8_t* start = base + sec[i].VirtualAddress;
        uint8_t* end = start + (sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData);
        
        start = (uint8_t*)(((uintptr_t)start + 7) & ~7ULL);
        
        for (uint64_t* p = (uint64_t*)start; (uint8_t*)(p + 1) <= end; p++) {
            uint64_t val = *p;
            if (val >= (int64_t)preferred_base && val < (int64_t)preferred_base + image_size) {
                *p = val + delta;
            }
        }
    }
}

void apply_section_permissions(STUB_RUNTIME* rt, uint8_t* base, IMAGE_NT_HEADERS* nt, IMAGE_SECTION_HEADER* sec) {
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint8_t* addr = base + sec[i].VirtualAddress;
        size_t size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (size == 0) continue;
        DWORD prot = PAGE_READONLY;
        DWORD chars = sec[i].Characteristics;
        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            prot = (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (chars & IMAGE_SCN_MEM_WRITE) {
            prot = PAGE_READWRITE;
        } else if (chars & IMAGE_SCN_MEM_READ) {
            prot = PAGE_READONLY;
        } else {
            prot = PAGE_NOACCESS;
        }
        DWORD old;
        rt->pVirtualProtect(addr, size, prot, &old);
    }
}

void restore_directories_and_relocate(STUB_RUNTIME* rt, STUB_CONFIG* config, IMAGE_NT_HEADERS* nt, uint8_t* target_base) {
    if (config->resource_rva != 0 || config->exception_rva != 0 || config->tls_rva != 0 || config->reloc_rva != 0) {
        DWORD old_header_prot;
        rt->pVirtualProtect(target_base, 0x1000, PAGE_READWRITE, &old_header_prot);
        #ifdef DEBUG
            debug_print(rt, "Made headers writable");
        #endif
        if (config->resource_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = config->resource_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = config->resource_size;
            #ifdef DEBUG
                debug_print(rt, "Restored resource directory");
            #endif
        } 
        if (config->exception_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = config->exception_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = config->exception_size;
            #ifdef DEBUG
                debug_print(rt, "Restored exception directory");
            #endif
        }
        if (config->tls_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = config->tls_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = config->tls_size;
            #ifdef DEBUG
                debug_print(rt, "Restored TLS directory");
            #endif
        }
        if (config->reloc_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = config->reloc_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = config->reloc_size;
            #ifdef DEBUG
                debug_print(rt, "Restored reloc directory");
            #endif
            #ifdef DEBUG
                debug_print(rt, "Applying relocations");
            #endif
            apply_relocations(rt, target_base, (uint8_t*)(uintptr_t)config->image_base, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], nt->OptionalHeader.SizeOfImage);
            #ifdef DEBUG
                debug_print(rt, "Relocations applied");
            #endif
            manual_relocations(target_base, (uint8_t*)(uintptr_t)config->image_base, nt->OptionalHeader.SizeOfImage);
            #ifdef DEBUG
                debug_print(rt, "Additional relocations applied");
            #endif
        }
        rt->pVirtualProtect(target_base, 0x1000, old_header_prot, &old_header_prot);
        #ifdef DEBUG
            debug_print(rt, "Restored headers to read-only");
        #endif
    }
}


typedef void(WINAPI *TLS_CALLBACK)(PVOID, DWORD, PVOID);

void tls_callbacks(uint8_t* base, uint32_t tls_rva, STUB_RUNTIME* rt) {
    if (!tls_rva) return;
    IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(base + tls_rva);
    if (tls->AddressOfCallBacks == 0 || tls->StartAddressOfRawData == 0 || tls->EndAddressOfRawData == 0 || tls->SizeOfZeroFill == 0) {
        return;
    }
    TLS_CALLBACK* callbacks = (TLS_CALLBACK*)tls->AddressOfCallBacks;
    for (int i = 0; callbacks[i] != NULL; i++) {
        callbacks[i](base, DLL_PROCESS_ATTACH, NULL);
    }
}

void* memcpy(void* dest, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    while (n--) *d++ = *s++;
    return dest;
}

void debug_print(STUB_RUNTIME* rt, const char* msg) {
    if (rt->pOutputDebugStringA) {
        rt->pOutputDebugStringA(msg);
    }
}

void debug_print_hex(STUB_RUNTIME* rt, const char* name, uint64_t value) {
    char buffer[128];
    char* p = buffer;
    while (*name) *p++ = *name++;
    *p++ = ':';
    *p++ = ' ';
    *p++ = '0';
    *p++ = 'x';
    char hex[] = "0123456789ABCDEF";
    int started = 0;
    for (int i = 60; i >= 0; i -= 4) {
        int digit = (int)((value >> i) & 0xF);
        if (digit != 0) started = 1;
        if (started || i == 0) {
            *p++ = hex[digit];
        }
    }
    *p = 0;
    debug_print(rt, buffer);
}

void debug_print_dec(STUB_RUNTIME* rt, const char* name, uint64_t value) {
    char buffer[128];
    char* p = buffer;
    while (*name) *p++ = *name++;
    *p++ = ':';
    *p++ = ' ';
    if (value == 0) {
        *p++ = '0';
    } else {
        char numbuf[21];
        char* np = numbuf + 20;
        *np = 0;
        while (value > 0) {
            *--np = '0' + (value % 10);
            value /= 10;
        }
        while (*np) *p++ = *np++;
    }
    *p = 0;
    debug_print(rt, buffer);
}

void xorshift64_plus(uint8_t* data, size_t size, uint64_t key) {
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
        
        data[i] += key_xor_aa_shr8;
        data[i] -= key_xor_aa;
        data[i] ^= mask;
    }
}

__attribute__((noinline))
void stub_main(STUB_CONFIG* config) {
    STUB_RUNTIME rt;
    resolve_imports(&rt);

    if (rt.pVirtualProtect) {
        uint8_t* stub_region = (uint8_t*)((uintptr_t)config - (uintptr_t)config->stub_code_size);
        size_t stub_total = (size_t)config->stub_code_size + sizeof(STUB_CONFIG) + 4;
        DWORD old_stub_region_prot;
        rt.pVirtualProtect(stub_region, stub_total, PAGE_EXECUTE_READWRITE, &old_stub_region_prot);
    }
    
    #ifdef DEBUG
        debug_print(&rt, "Stub main starting");
        debug_print_hex(&rt, "Decryption key", config->key);
        debug_print_dec(&rt, "Original OEP", config->original_oep);
        debug_print_dec(&rt, "Encrypted size", config->encrypted_size);
        debug_print_dec(&rt, "Image base", config->image_base);
        debug_print_dec(&rt, "Sections RVA", config->sections_rva);
    #endif

    void* buffer = rt.pVirtualAlloc(NULL, config->encrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        #ifdef DEBUG
            debug_print(&rt, "VirtualAlloc failed");
        #endif
        return;
    }
    #ifdef DEBUG
        debug_print_hex(&rt, "Allocated buffer", (uint64_t)buffer);
    #endif

    void* peb = (void*)__readgsqword(0x60);
    uint8_t* actual_base = *(uint8_t**)((uint8_t*)peb + 0x10);

    uint8_t* encrypted = actual_base + config->sections_rva;
    uint8_t* decrypted = (uint8_t*)buffer;

    SECTION_INFO* section_infos = (SECTION_INFO*)((uint8_t*)config + sizeof(STUB_CONFIG) + 4);
    for (uint8_t i = 0; i < config->section_count; i++) {
        if (section_infos[i].raw_size == 0) continue;
        uint8_t* src = actual_base + section_infos[i].virtual_address;
        uint8_t* dst = decrypted + section_infos[i].raw_offset;
        memcpy(dst, src, section_infos[i].raw_size);
    }
    #ifdef DEBUG
        debug_print(&rt, "Starting decryption");
    #endif
    xorshift64_plus(decrypted, config->encrypted_size, config->key);
    #ifdef DEBUG
        debug_print(&rt, "Decryption complete");
    #endif


    uint8_t* target_base = actual_base;
    uint8_t* target_sections = actual_base + config->sections_rva;
    DWORD old_protect2;

    for (uint8_t i = 0; i < config->section_count; i++) {
        if (section_infos[i].raw_size == 0) continue;
        uint8_t* src = (uint8_t*)buffer + section_infos[i].raw_offset;
        uint8_t* dst = target_base + section_infos[i].virtual_address;
        rt.pVirtualProtect(dst, section_infos[i].raw_size, PAGE_READWRITE, &old_protect2);
        memcpy(dst, src, section_infos[i].raw_size);
    }

    SecureWipe((unsigned char*)buffer, config->encrypted_size);
    #ifdef DEBUG
        debug_print(&rt, "Overwrote temporary buffer with zeros");
    #endif
    rt.pVirtualFree(buffer, 0, MEM_RELEASE);
    #ifdef DEBUG
        debug_print(&rt, "Released temporary buffer");
    #endif

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)target_base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(target_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0 && sec[i].Misc.VirtualSize > 0) {
            uint8_t* bss = target_base + sec[i].VirtualAddress;
            #ifdef DEBUG
                debug_print(&rt, "Zeroing BSS section");
            #endif
            SecureWipe(bss, sec[i].Misc.VirtualSize);
        } else if (sec[i].SizeOfRawData > 0 && sec[i].Misc.VirtualSize > sec[i].SizeOfRawData) {
            uint32_t extra_offset = sec[i].VirtualAddress + sec[i].SizeOfRawData;
            uint32_t extra_size = sec[i].Misc.VirtualSize - sec[i].SizeOfRawData;
            uint8_t* extra = target_base + extra_offset;
            #ifdef DEBUG
                debug_print(&rt, "Zeroing extra section data");
            #endif
            SecureWipe(extra, extra_size);
        }
    }

    restore_directories_and_relocate(&rt, config, nt, target_base);

    #ifdef DEBUG
        debug_print(&rt, "Resolving payload imports");
    #endif
    resolve_payload_imports(target_base, config, &rt);

    apply_section_permissions(&rt, target_base, nt, sec);

    void (*original_entry)() = (void(*)())(target_base + config->original_oep);

    DWORD old_stub_prot;
    rt.pVirtualProtect(config, sizeof(STUB_CONFIG), PAGE_READWRITE, &old_stub_prot);
    SecureWipe((unsigned char*)config, sizeof(STUB_CONFIG));
    rt.pVirtualProtect(config, sizeof(STUB_CONFIG), old_stub_prot, &old_stub_prot);
    #ifdef DEBUG
        debug_print(&rt, "Wiped payload config");
    #endif

    #ifdef DEBUG
        debug_print_hex(&rt, "Jumping to original entry point", (uint64_t)original_entry);
    #endif
    original_entry();
}

static volatile uint32_t MARKER_VALUE = 0xDEADBEEF;

__attribute__((noinline))
void position_independent_entry(void) {
    void* return_addr = __builtin_return_address(0);
    uint8_t* marker_location = (uint8_t*)return_addr;
    uint8_t* x = (uint8_t*)&MARKER_VALUE;
    int count = 0;
    while (1) {
        if (marker_location[0] == x[0] && marker_location[1] == x[1] && 
            marker_location[2] == x[2] && marker_location[3] == x[3]) {
            count++;
            if (count == 2) break;
        }
        marker_location++;
    }
    STUB_CONFIG* config = (STUB_CONFIG*)(marker_location - sizeof(STUB_CONFIG));
    stub_main(config);
}

__attribute__((naked)) int _start() {
    __asm__ volatile (
        ".intel_syntax noprefix\n"
        ".byte 0x0F, 0x0B, 0x0F, 0x0B, 0x0F, 0x0B\n"
        "and rsp, 0xFFFFFFFFFFFFFFF0\n"
        "sub rsp, 0x20\n"               
        "call position_independent_entry\n"
        "add rsp, 0x20\n"
        "ret\n"
        ".att_syntax prefix\n"
    );
}

int __main() { return 0; }
