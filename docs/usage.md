# C/C++ API Reference

All examples assume you have linked against `libspecter.a` and included `specter.h`.

```
-L<path> -lspectre -lc++ -framework Foundation -framework Security
```

> **Platform note:** `make` builds for both iOS (`aarch64-apple-ios`) and macOS (`aarch64-apple-darwin`). Use `make ios` or `make macos` to build a single target.

C++ gets typed template wrappers for `mem_read`/`mem_write` automatically. In C, pass `sizeof(T)` explicitly.

---

## Table of Contents

1. [Error Codes](#1-error-codes)
2. [Initialization](#2-initialization)
3. [Inline Hooks](#3-inline-hooks)
4. [Patches](#4-patches)
5. [Memory Read / Write](#5-memory-read--write)
6. [Image & Symbol API](#6-image--symbol-api)
7. [Hardware Breakpoints](#7-hardware-breakpoints)
8. [Shellcode Loading](#8-shellcode-loading)
9. [Pattern Scanning](#9-pattern-scanning)
10. [Memory Protection](#10-memory-protection)
11. [Image Enumeration](#11-image-enumeration)
12. [Patch Introspection](#12-patch-introspection)
13. [Memory Backup](#13-memory-backup)
14. [Segment / Section Querying](#14-segment--section-querying)
15. [Common Patterns](#15-common-patterns)

---

## 1. Error Codes

Every function returns `int32_t`. Zero means success; negative values are errors.

| Code | Name | Meaning |
|------|------|---------|
| `0` | `MEM_OK` | Success |
| `-1` | `MEM_ERR_GENERIC` | Catch-all / unexpected error |
| `-2` | `MEM_ERR_NULL` | Required pointer argument was NULL |
| `-3` | `MEM_ERR_NOT_FOUND` | Image / symbol / hook not found |
| `-4` | `MEM_ERR_EXISTS` | Hook already installed at address |
| `-5` | `MEM_ERR_ALLOC` | Memory allocation failed |
| `-6` | `MEM_ERR_PROTECT` | vm_protect / Mach VM call failed |
| `-7` | `MEM_ERR_PATCH` | Stealth-write or verify failed |
| `-8` | `MEM_ERR_RELOC` | Instruction relocation failed |
| `-9` | `MEM_ERR_THREAD` | Thread suspend / resume failed |
| `-10` | `MEM_ERR_SYMBOL` | dlsym / symbol resolution failed |
| `-11` | `MEM_ERR_RANGE` | Branch target out of ±128 MB range |
| `-12` | `MEM_ERR_EMPTY` | Empty instruction / patch data |
| `-13` | `MEM_ERR_HW_LIMIT` | Hardware breakpoint limit exceeded |
| `-14` | `MEM_ERR_SCAN_PATTERN` | Invalid scan pattern |
| `-15` | `MEM_ERR_SCAN_ACCESS` | Scan hit unreadable memory |
| `-16` | `MEM_ERR_SCAN_REGION` | Image region enumeration failed |
| `-17` | `MEM_ERR_MACHO` | Mach-O segment/section parse error |

Helper macro for quick prototyping:

```c
#define CHECK(expr) \
    do { int32_t _rc = (expr); \
         if (_rc != MEM_OK) { printf(#expr " failed: %d\n", _rc); return; } \
    } while (0)
```

---

## 2. Initialization

Call `mem_init` once before any RVA-based operation. `image_name` is matched as a substring against the full dylib path reported by dyld.

```c
// Minimal
CHECK(mem_init("MyApp", NULL));

// With base address
uintptr_t base;
CHECK(mem_init("MyApp", &base));
printf("MyApp at 0x%lx\n", base);
```

To look up a different image without changing the RVA target:

```c
uintptr_t uikit_base;
CHECK(mem_get_image_base("UIKitCore", &uikit_base));
```

---

## 3. Inline Hooks

An inline hook overwrites the first bytes of the target function with a branch to your replacement. A trampoline is allocated with the relocated original instructions so you can call back into the original.

### 3.1 Hook by RVA

```c
typedef int (*AddFn)(int, int);
static AddFn g_orig_add;

static int hooked_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return g_orig_add(a, b);
}

void install(void) {
    CHECK(mem_init("MyApp", NULL));

    uint64_t  handle;
    uintptr_t trampoline;
    CHECK(mem_hook_install(0x12340, (uintptr_t)hooked_add, &trampoline, &handle));
    g_orig_add = (AddFn)trampoline;
}
```

```cpp
// C++ equivalent
using AddFn = int(*)(int, int);
static AddFn g_orig;
static uint64_t g_handle;

static int hooked_add(int a, int b) {
    return g_orig(a, b) + 1;
}

void install() {
    CHECK(mem_init("MyApp", nullptr));

    uintptr_t trampoline;
    CHECK(mem_hook_install(0x12340, reinterpret_cast<uintptr_t>(hooked_add),
                           &trampoline, &g_handle));
    g_orig = reinterpret_cast<AddFn>(trampoline);
}
```

### 3.2 Hook by Symbol

Resolves the target via `dlsym` automatically.

```c
typedef void *(*MallocFn)(size_t);
static MallocFn g_orig_malloc;

static void *hooked_malloc(size_t size) {
    printf("malloc(%zu)\n", size);
    return g_orig_malloc(size);
}

void hook_malloc(void) {
    uint64_t  handle;
    uintptr_t trampoline;
    CHECK(mem_hook_symbol("malloc", (uintptr_t)hooked_malloc, &trampoline, &handle));
    g_orig_malloc = (MallocFn)trampoline;
}
```

### 3.3 Hook by Absolute Address

When you already have the ASLR-slid address. Removal is by address, not handle.

```c
uintptr_t trampoline;
CHECK(mem_hook_install_at(0x10012340, (uintptr_t)my_hook, &trampoline));
// ...
CHECK(mem_hook_remove_at(0x10012340));
```

### 3.4 Code-Cave Hooks

Places the trampoline in existing NOP padding in the target image's `__TEXT` segment instead of a new `mmap` allocation. Invisible to scanners looking for anonymous executable pages.

```c
uint64_t  handle;
uintptr_t trampoline;

// By RVA
CHECK(mem_hook_install_cave(0x12340, (uintptr_t)my_hook, &trampoline, &handle));

// By absolute address
CHECK(mem_hook_install_cave_at(0x10012340, (uintptr_t)my_hook, &trampoline, &handle));
```

> Requires a NOP region of at least 256 bytes within ±128 MB of the target. Returns `MEM_ERR_ALLOC` if none is found.

### 3.5 Removing Hooks

```c
// By handle (for mem_hook_install / _symbol / _cave variants)
CHECK(mem_hook_remove(handle));

// By address (for mem_hook_install_at)
CHECK(mem_hook_remove_at(target_addr));
```

Removal restores original bytes, frees the trampoline, and resumes any suspended threads.

### 3.6 Hook Introspection

```c
size_t count = mem_hook_count();

int32_t hooked = mem_hook_is_hooked(0x10012340); // 1 or 0

uintptr_t addrs[64];
size_t    total;
mem_hook_list(addrs, 64, &total);
for (size_t i = 0; i < total && i < 64; i++)
    printf("hook at 0x%lx\n", addrs[i]);
```

---

## 4. Patches

Patches overwrite arbitrary bytes and save the originals for revert. All writes go through the stealth `mach_vm_remap` path.

### 4.1 Hex Patch by RVA

Spaces in the hex string are ignored.

```c
uintptr_t patch_addr;

// NOP (1F 20 03 D5)
CHECK(mem_patch_apply(0xABCD0, "1F2003D5", &patch_addr));

// RET (C0 03 5F D6)
CHECK(mem_patch_apply(0xABCD0, "C0035FD6", NULL));

// Multiple instructions
CHECK(mem_patch_apply(0xABCD0, "1F2003D5 1F2003D5 C0035FD6", NULL));
```

### 4.2 Raw Bytes at Absolute Address

```c
uint8_t nop[4] = {0x1F, 0x20, 0x03, 0xD5};
uintptr_t addr_out;
CHECK(mem_patch_apply_at(0x100123F0, nop, sizeof(nop), &addr_out));
```

### 4.3 Code-Cave Patch

Writes payload to a nearby NOP region and installs a single `B` instruction at the target (4-byte footprint).

```c
CHECK(mem_patch_apply_cave(0xABCD0,
      "E0031FAA"   // MOV X0, XZR
      "C0035FD6",  // RET
      NULL));
```

### 4.4 Reverting Patches

```c
CHECK(mem_patch_revert(patch_addr));
```

---

## 5. Memory Read / Write

### 5.1 Typed Reads and Writes

**C** — pass `sizeof(T)` explicitly:

```c
uint32_t value;
CHECK(mem_read(0x100123F0, &value, sizeof value));

float speed = 5.0f;
CHECK(mem_write(0x100123F4, &speed, sizeof speed));
```

**C++** — template wrappers deduce the size:

```cpp
uint32_t value;
CHECK(mem_read(0x100123F0, &value));

float speed = 5.0f;
CHECK(mem_write(0x100123F4, speed));
```

### 5.2 RVA-Relative Access

Requires `mem_init` to have been called.

```c
uint32_t flags;
CHECK(mem_read_rva(0xABCD0, &flags, sizeof flags));

uint32_t new_flags = 0;
CHECK(mem_write_rva(0xABCD0, &new_flags, sizeof new_flags));
```

### 5.3 Pointer Chain Traversal

Follows a chain of pointer dereferences. The result is the final address, not the data at it.

```c
// *(*(base + 0x10) + 0x28) + 0x8
uintptr_t offsets[] = {0x10, 0x28, 0x8};
uintptr_t result;
CHECK(mem_read_pointer_chain(0x100200000, offsets, 3, &result));
```

### 5.4 Stealth Write to Code Pages

`mem_write` / `mem_write_rva` use plain `memcpy` and will fault on executable pages. Use `mem_write_bytes` for the `mach_vm_remap` + icache flush path:

```c
uint8_t nop[] = {0x1F, 0x20, 0x03, 0xD5};
CHECK(mem_write_bytes(0x100123F0, nop, sizeof nop));
```

---

## 6. Image & Symbol API

```c
// Image base lookup
uintptr_t base;
CHECK(mem_get_image_base("UIKitCore", &base));

// Symbol resolution (cached after first call)
uintptr_t addr;
CHECK(mem_resolve_symbol("malloc", &addr));

// Manually cache a symbol
mem_cache_symbol("_my_func", 0x100099ABC);

// Clear cache (e.g. after dlopen/dlclose)
mem_clear_symbol_cache();
```

---

## 7. Hardware Breakpoints

Intercepts execution using ARM64 debug registers and Mach exception handling. **No code is modified** at the target address. Maximum 6 concurrent breakpoints (`mem_brk_max_breakpoints()`).

```c
static void replacement(void) {
    printf("intercepted\n");
    // WARNING: calling the original directly would re-trigger the breakpoint.
    // For call-original patterns, prefer inline hooks (mem_hook_install).
}

void install(void) {
    CHECK(mem_init("MyApp", NULL));

    printf("%d/%d breakpoints in use\n",
           mem_brk_active_count(), mem_brk_max_breakpoints());

    // By RVA
    uint64_t handle;
    CHECK(mem_brk_install(0x12340, (uintptr_t)replacement, &handle));
    CHECK(mem_brk_remove(handle));

    // By absolute address
    CHECK(mem_brk_install_at(0x10012340, (uintptr_t)replacement, &handle));
    CHECK(mem_brk_remove_at(0x10012340));
}
```

> **Hardware breakpoints vs inline hooks:**
> - Breakpoints leave **zero code footprint** — ideal for read-only pages or integrity-checked code.
> - Inline hooks let you **call the original** easily via the trampoline.
> - Breakpoints are limited to **6 concurrent** addresses.

---

## 8. Shellcode Loading

Loads raw ARM64 machine code into executable memory with optional symbol relocations.

### Simple Load

```c
static const uint8_t nop_ret[] = {
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0xC0, 0x03, 0x5F, 0xD6, // RET
};

uintptr_t sc_addr;
CHECK(mem_shellcode_load(nop_ret, sizeof nop_ret,
                         NULL, NULL, 0,  // no relocations
                         0, 0,           // no near hint, reserved
                         &sc_addr));

// Call it
((void (*)(void))sc_addr)();

// Free
CHECK(mem_shellcode_free(sc_addr));
```

### With Symbol Relocations

Patch 64-bit symbol addresses into the shellcode at specified offsets before execution.

```c
// Shellcode that calls malloc via a relocated pointer at offset 12
static uint8_t sc[] = {
    0x49, 0x00, 0x00, 0x58, // LDR X9, #8
    0x20, 0x01, 0x3F, 0xD6, // BLR X9
    0xC0, 0x03, 0x5F, 0xD6, // RET
    0x00, 0x00, 0x00, 0x00, // .quad placeholder (offset 12)
    0x00, 0x00, 0x00, 0x00,
};

size_t      offsets[]  = {12};
const char *symbols[]  = {"malloc"};

uintptr_t sc_addr;
CHECK(mem_shellcode_load(sc, sizeof sc,
                         offsets, symbols, 1,
                         0, 0,
                         &sc_addr));
```

### Near-Address Allocation

If your shellcode uses `B`/`BL` instructions that need to reach within ±128 MB of a specific target:

```c
CHECK(mem_shellcode_load(sc, sizeof sc,
                         offsets, symbols, 1,
                         0x100123F0,  // allocate near this address
                         0, &sc_addr));
```

---

## 9. Pattern Scanning

Scan memory ranges or entire loaded images for byte patterns. IDA-style patterns use hex bytes separated by spaces, with `??` as a wildcard.

### 9.1 Scan a Memory Range

```c
uintptr_t results[64];
size_t    count;
CHECK(mem_scan_pattern(start, size, "DE AD ?? EF", results, 64, &count));
for (size_t i = 0; i < count && i < 64; i++)
    printf("match at 0x%lx\n", results[i]);
```

### 9.2 Scan an Entire Image

```c
uintptr_t results[64];
size_t    count;
CHECK(mem_scan_image("MyApp", "1F 20 03 D5 C0 03 5F D6", results, 64, &count));
```

### 9.3 Find First Match

```c
uintptr_t addr;
CHECK(mem_scan_find_first(start, size, "DE AD ?? EF", &addr));

// Or in an entire image:
CHECK(mem_scan_image_first("MyApp", "DE AD ?? EF", &addr));
```

### 9.4 Raw Bytes + Mask

```c
uint8_t pattern[] = {0xDE, 0xAD, 0x00, 0xEF};
const char *mask  = "xx?x";
uintptr_t results[64];
size_t    count;
CHECK(mem_scan_raw(start, size, pattern, mask, sizeof pattern,
                   results, 64, &count));
```

### 9.5 Cached Scanning

Subsequent calls with the same parameters return cached results.

```c
uintptr_t results[64];
size_t    count;
CHECK(mem_scan_cached(start, size, "DE AD ?? EF", results, 64, &count));

// Clear when patterns may have changed:
mem_scan_clear_cache();
```

---

## 10. Memory Protection

Query and modify memory page protection flags.

### 10.1 Query Protection

```c
int32_t prot;
CHECK(mem_get_protection(0x100004000, &prot));
printf("prot flags: %d\n", prot);

// Quick boolean checks (return 1 or 0)
if (mem_is_readable(0x100004000))
    printf("readable\n");
if (mem_is_writable(0x100004000))
    printf("writable\n");
if (mem_is_executable(0x100004000))
    printf("executable\n");
```

### 10.2 Query Region Info

```c
uintptr_t region_addr;
size_t    region_size;
int32_t   prot;
CHECK(mem_get_region_info(0x100004000, &region_addr, &region_size, &prot));
printf("region: 0x%lx size: 0x%zx prot: %d\n", region_addr, region_size, prot);

// Find region containing or after an address:
CHECK(mem_find_region(0x100004000, &region_addr, &region_size, &prot));
```

### 10.3 Change Protection

```c
#include <mach/vm_prot.h>
CHECK(mem_protect(page_addr, page_size, VM_PROT_READ | VM_PROT_WRITE));
```

### 10.4 Enumerate All Regions

```c
size_t count;
mem_get_all_regions(NULL, 0, &count); // query count first

mem_region_t *regions = malloc(count * sizeof(mem_region_t));
mem_get_all_regions(regions, count, &count);
for (size_t i = 0; i < count; i++)
    printf("0x%lx  size=0x%zx  prot=%d\n",
           regions[i].address, regions[i].size, regions[i].protection);
free(regions);
```

---

## 11. Image Enumeration

List all loaded dynamic libraries and their base addresses.

```c
// Get total count
size_t count;
CHECK(mem_image_count(&count));
printf("%zu images loaded\n", count);

// List all images
mem_image_t *images = malloc(count * sizeof(mem_image_t));
CHECK(mem_image_list(images, count, &count));

for (size_t i = 0; i < count; i++) {
    char name[512];
    if (mem_image_name(images[i].index, name, sizeof name) == MEM_OK)
        printf("[%u] 0x%lx  %s\n", images[i].index, images[i].base, name);
}
free(images);
```

---

## 12. Patch Introspection

Query details about active patches.

```c
// Count and list active patches
size_t count = mem_patch_count();

uintptr_t addrs[64];
size_t    total;
mem_patch_list(addrs, 64, &total);

// Inspect a specific patch
for (size_t i = 0; i < total && i < 64; i++) {
    size_t sz;
    mem_patch_size(addrs[i], &sz);

    uint8_t orig[64], patch[64], curr[64];
    mem_patch_orig_bytes(addrs[i], orig, sz);
    mem_patch_patch_bytes(addrs[i], patch, sz);
    mem_patch_curr_bytes(addrs[i], curr, sz);

    // Compare curr vs patch to detect external modification
    if (memcmp(curr, patch, sz) != 0)
        printf("patch at 0x%lx was externally modified\n", addrs[i]);
}
```

---

## 13. Memory Backup

Standalone memory backup and restore, independent of the patch system. Useful for backing up a region before making manual modifications.

```c
// Create a backup
uint64_t handle;
CHECK(mem_backup_create(0x100004000, 64, &handle));

// ... modify memory however you want ...

// Query backup info
uintptr_t backed_addr;
size_t    backed_size;
mem_backup_address(handle, &backed_addr);
mem_backup_size(handle, &backed_size);

// Read original and current bytes
uint8_t orig[64], curr[64];
mem_backup_orig_bytes(handle, orig, 64);
mem_backup_curr_bytes(handle, curr, 64);

// Restore original bytes
CHECK(mem_backup_restore(handle));

// Destroy when no longer needed (does not restore)
CHECK(mem_backup_destroy(handle));
```

---

## 14. Segment / Section Querying

Query Mach-O segments and sections of loaded images.

```c
// Get a segment (e.g., __TEXT)
mem_segment_t text;
CHECK(mem_get_segment("MyApp", "__TEXT", &text));
printf("__TEXT: 0x%lx - 0x%lx (%zu bytes)\n", text.start, text.end, text.size);

// Get a specific section within a segment
mem_segment_t text_text;
CHECK(mem_get_section("MyApp", "__TEXT", "__text", &text_text));
printf("__text: 0x%lx - 0x%lx (%zu bytes)\n",
       text_text.start, text_text.end, text_text.size);

// Useful for targeted scanning
uintptr_t results[256];
size_t    count;
mem_scan_pattern(text_text.start, text_text.size, "C0 03 5F D6",
                 results, 256, &count);
printf("found %zu RET instructions in __text\n", count);
```

---

## 15. Common Patterns

### Guard Against Double Install

```c
void ensure_hooked(uintptr_t addr) {
    if (mem_hook_is_hooked(addr))
        return;
    mem_hook_install_at(addr, (uintptr_t)my_hook, NULL);
}
```

### Remove All Hooks on Teardown

```c
void cleanup(uint64_t *handles, size_t count) {
    for (size_t i = 0; i < count; i++)
        mem_hook_remove(handles[i]);
}
```

### Read a Struct via Pointer Chain

```c
typedef struct { float x, y, z; } Vec3;

uintptr_t offsets[] = {0x20, 0x8};
uintptr_t vec_ptr;
if (mem_read_pointer_chain(game_obj, offsets, 2, &vec_ptr) == MEM_OK) {
    Vec3 pos;
    mem_read(vec_ptr, &pos, sizeof pos);
    printf("%.2f %.2f %.2f\n", pos.x, pos.y, pos.z);
}
```

### Hook + Call Original

```c
typedef int32_t (*CheckFn)(void *);
static CheckFn  g_orig_check;
static uint64_t g_handle;

static int32_t hooked_check(void *ctx) {
    int32_t result = g_orig_check(ctx);
    return result == 0 ? 1 : result; // patch return value
}

void setup(void) {
    CHECK(mem_init("MyApp", NULL));
    uintptr_t tramp;
    CHECK(mem_hook_install(0xDEAD0, (uintptr_t)hooked_check, &tramp, &g_handle));
    g_orig_check = (CheckFn)tramp;
}
```

### Verify a Patch Later

```c
uint8_t expected[] = {0x1F, 0x20, 0x03, 0xD5};
uint8_t actual[4];
if (mem_read(patch_addr, actual, 4) == MEM_OK) {
    if (memcmp(actual, expected, 4) != 0)
        printf("patch was reverted externally\n");
}
```
