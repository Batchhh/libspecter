# Specter — API Reference & Usage Examples

All examples below assume you have linked against `libspecter.a` and included `specter.h`. For C++ the file uses `extern "C"` and provides typed template wrappers for `mem_read`/`mem_write`; for C pass `sizeof(T)` explicitly.

---

## Table of contents

1. [Error handling](#1-error-handling)
2. [Initialization](#2-initialization)
3. [Inline hooks](#3-inline-hooks)
   - [By RVA](#31-hook-by-rva)
   - [By symbol name](#32-hook-by-symbol-name)
   - [By absolute address](#33-hook-by-absolute-address)
   - [Code-cave variant](#34-code-cave-hooks)
   - [Removing hooks](#35-removing-hooks)
   - [Hook introspection](#36-hook-introspection)
4. [Patches](#4-patches)
   - [Hex patch by RVA](#41-hex-patch-by-rva)
   - [Raw bytes at absolute address](#42-raw-bytes-at-absolute-address)
   - [Code-cave patch](#43-code-cave-patch)
   - [Reverting patches](#44-reverting-patches)
5. [Memory read / write](#5-memory-read--write)
   - [Typed reads and writes](#51-typed-reads-and-writes)
   - [RVA-relative access](#52-rva-relative-access)
   - [Pointer chain traversal](#53-pointer-chain-traversal)
   - [Stealth write to code pages](#54-stealth-write-to-code-pages)
6. [Image and symbol API](#6-image-and-symbol-api)
7. [Hardware breakpoints](#7-hardware-breakpoints)
8. [Shellcode loading](#8-shellcode-loading)
9. [Common patterns](#9-common-patterns)

---

## 1. Error handling

Every function returns `int32_t`. Zero is `MEM_OK`; any negative value is an error.

```c
int32_t rc = mem_init("MyApp", NULL);
if (rc != MEM_OK) {
    // rc is one of MEM_ERR_NOT_FOUND, MEM_ERR_NULL, etc.
    printf("mem_init failed: %d\n", rc);
    return;
}
```

A recommended macro for quick prototyping:

```c
#define CHECK(expr) \
    do { int32_t _rc = (expr); \
         if (_rc != MEM_OK) { printf(#expr " failed: %d\n", _rc); return; } \
    } while (0)

CHECK(mem_init("MyApp", NULL));
```

---

## 2. Initialization

Call `mem_init` once before any RVA-based operation. Pass `NULL` for `base_out` if you do not need the image base address.

```c
// Minimal init
CHECK(mem_init("MyApp", NULL));

// With base address
uintptr_t base;
CHECK(mem_init("MyApp", &base));
printf("MyApp loaded at 0x%lx\n", base);
```

`image_name` is matched as a substring against the full dylib path as reported by dyld. Passing `"MyApp"` matches `/var/containers/Bundle/.../MyApp.app/MyApp`.

To look up the base of a different image (e.g., a framework) without changing the RVA target:

```c
uintptr_t uikit_base;
CHECK(mem_get_image_base("UIKitCore", &uikit_base));
```

---

## 3. Inline hooks

An inline hook overwrites the first 16 bytes of the target function with a redirect branch. A trampoline containing the relocated original instructions is allocated separately so the original function can still be called.

### 3.1 Hook by RVA

Use when you know the function's offset inside the target image (e.g., from static analysis).

```c
// C example
typedef int (*OrigFn)(int a, int b);
static OrigFn g_orig_add;

static int hooked_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return g_orig_add(a, b);  // call original
}

void install(void) {
    CHECK(mem_init("MyApp", NULL));

    uint64_t  handle;
    uintptr_t trampoline;
    CHECK(mem_hook_install(
        0x12340,            // RVA of target function
        (uintptr_t)hooked_add,
        &trampoline,        // NULL if you don't need to call original
        &handle             // required; needed for removal
    ));
    g_orig_add = (OrigFn)trampoline;
}

void uninstall(uint64_t handle) {
    mem_hook_remove(handle);
}
```

```cpp
// C++ example — typed trampoline cast
using AddFn = int(*)(int, int);
static AddFn g_orig_add;
static uint64_t g_handle;

static int hooked_add(int a, int b) {
    printf("add(%d, %d)\n", a, b);
    return g_orig_add(a, b);
}

void install() {
    CHECK(mem_init("MyApp", nullptr));

    uintptr_t trampoline;
    CHECK(mem_hook_install(0x12340, reinterpret_cast<uintptr_t>(hooked_add),
                           &trampoline, &g_handle));
    g_orig_add = reinterpret_cast<AddFn>(trampoline);
}
```

### 3.2 Hook by symbol name

Use when the target is an exported symbol resolvable via `dlsym`.

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
    CHECK(mem_hook_symbol("malloc", (uintptr_t)hooked_malloc,
                          &trampoline, &handle));
    g_orig_malloc = (MallocFn)trampoline;
}
```

### 3.3 Hook by absolute address

Use when you already know the runtime address (e.g., resolved by your own means). Removal is by address, not by handle.

```c
uintptr_t target_addr = 0x10012340; // already ASLR-slid
uintptr_t trampoline;

CHECK(mem_hook_install_at(target_addr, (uintptr_t)my_hook, &trampoline));
// ...
CHECK(mem_hook_remove_at(target_addr));
```

### 3.4 Code-cave hooks

The code-cave variants place the trampoline inside existing NOP padding in the target image's `__TEXT` segment. This avoids creating a separate `mmap` allocation, making the trampoline invisible to scanners that look for anonymous executable pages.

```c
uint64_t  handle;
uintptr_t trampoline;

// By RVA
CHECK(mem_hook_install_cave(0x12340, (uintptr_t)my_hook, &trampoline, &handle));

// By absolute address
CHECK(mem_hook_install_cave_at(0x10012340, (uintptr_t)my_hook, &trampoline, &handle));

// Removal uses the same handle-based API
CHECK(mem_hook_remove(handle));
```

> **Note:** Code-cave allocation requires a NOP region of at least 256 bytes within ±128 MB of the target. If no such region exists, the function returns `MEM_ERR_ALLOC`.

### 3.5 Removing hooks

```c
// Handle-based removal (for mem_hook_install / _symbol / _cave)
CHECK(mem_hook_remove(handle));

// Address-based removal (for mem_hook_install_at)
CHECK(mem_hook_remove_at(target_addr));
```

Removal restores the original bytes, frees the trampoline, and resumes any suspended threads.

### 3.6 Hook introspection

```c
// Number of active hooks
size_t count = mem_hook_count();

// Check if a specific address is hooked
int32_t hooked = mem_hook_is_hooked(0x10012340); // 1 = yes, 0 = no

// List all hooked addresses
uintptr_t addrs[64];
size_t    total;
mem_hook_list(addrs, 64, &total);
for (size_t i = 0; i < total && i < 64; i++)
    printf("hook at 0x%lx\n", addrs[i]);
```

---

## 4. Patches

Patches overwrite arbitrary bytes at a target address and remember the original bytes for restoration. All patch writes go through the stealth `mach_vm_remap` path (see [architecture.md](architecture.md)).

### 4.1 Hex patch by RVA

Encode the replacement bytes as a hex string. Spaces are ignored for readability.

```c
// NOP out 4 bytes (1F 20 03 D5 = NOP on ARM64)
uintptr_t patch_addr;
CHECK(mem_patch_apply(0xABCD0, "1F2003D5", &patch_addr));

// RET immediately (C0 03 5F D6)
CHECK(mem_patch_apply(0xABCD0, "C0035FD6", NULL));

// Multiple instructions — spaces allowed
CHECK(mem_patch_apply(0xABCD0, "1F2003D5 1F2003D5 C0035FD6", NULL));
```

### 4.2 Raw bytes at absolute address

```c
uint8_t nop[4] = {0x1F, 0x20, 0x03, 0xD5};
uintptr_t addr_out;
CHECK(mem_patch_apply_at(0x100123F0, nop, sizeof(nop), &addr_out));
```

### 4.3 Code-cave patch

Writes the payload to a nearby NOP region and installs a single `B` (branch) instruction at the target. This keeps the visible footprint at the target to just 4 bytes.

```c
// Payload lands in a code cave; target gets a 4-byte branch
CHECK(mem_patch_apply_cave(0xABCD0,
      "E0031FAA"  // MOV x0, xzr
      "C0035FD6", // RET
      NULL));
```

The cave and branch instruction are both reverted by `mem_patch_revert`.

### 4.4 Reverting patches

Pass the address returned by `mem_patch_apply*` (or the address you passed to `mem_patch_apply_at`).

```c
CHECK(mem_patch_revert(patch_addr));
```

---

## 5. Memory read / write

### 5.1 Typed reads and writes

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
CHECK(mem_read(0x100123F0, &value));   // sizeof(uint32_t) inferred

float speed = 5.0f;
CHECK(mem_write(0x100123F4, speed));   // sizeof(float) inferred
```

### 5.2 RVA-relative access

Adds the image base automatically. Requires `mem_init` to have been called first.

```c
uint32_t flags;
CHECK(mem_read_rva(0xABCD0, &flags, sizeof flags));

uint32_t new_flags = 0;
CHECK(mem_write_rva(0xABCD0, &new_flags, sizeof new_flags));
```

### 5.3 Pointer chain traversal

Follows a chain of pointer dereferences with per-step offsets. The result is the final pointer value, not the data at it.

```c
// Follow: base → *(base + 0x10) → *(... + 0x28) → *(... + 0x8)
uintptr_t offsets[] = {0x10, 0x28, 0x8};
uintptr_t result;
CHECK(mem_read_pointer_chain(
    0x100200000,    // starting address
    offsets,
    3,              // number of offsets
    &result         // final pointer value
));
printf("final addr: 0x%lx\n", result);

// No offsets — just dereference base once
CHECK(mem_read_pointer_chain(0x100200000, NULL, 0, &result));
```

### 5.4 Stealth write to code pages

`mem_write` and `mem_write_rva` are plain `memcpy`-based and will fault on executable pages. Use `mem_write_bytes` to write via the `mach_vm_remap` stealth path:

```c
uint8_t patch[] = {0x1F, 0x20, 0x03, 0xD5}; // NOP
CHECK(mem_write_bytes(0x100123F0, patch, sizeof patch));
```

---

## 6. Image and symbol API

```c
// Get the ASLR-slid base address of any loaded image
uintptr_t base;
CHECK(mem_get_image_base("UIKitCore", &base));
printf("UIKitCore at 0x%lx\n", base);

// Resolve a symbol via dlsym (cached after first call)
uintptr_t malloc_addr;
CHECK(mem_resolve_symbol("malloc", &malloc_addr));

// Pre-populate the cache with an address you obtained yourself
mem_cache_symbol("my_private_func", 0x100099ABC);

// Invalidate all cached lookups (e.g., after a dlopen/dlclose)
mem_clear_symbol_cache();
```

---

## 7. Hardware breakpoints

Hardware breakpoints intercept execution at a target address **without modifying any code** — they use ARM64 debug registers and the Mach exception handling infrastructure. The CPU raises an exception when PC reaches the watched address; the exception handler redirects execution to the replacement function.

Maximum concurrently active breakpoints: 6 (`mem_brk_max_breakpoints()`).

```c
typedef void (*SomeFn)(void);
static SomeFn g_orig_some;

// The replacement receives normal control flow.
// To call the original, do NOT call g_orig_some() directly — that would
// re-trigger the breakpoint. Use a handle (not shown here) or
// save and restore debug state manually.
static void replacement(void) {
    printf("intercepted\n");
    // Calling g_orig_some() here would cause infinite recursion.
    // For functions where you need to call the original, prefer
    // an inline hook (mem_hook_install) instead.
}

void install(void) {
    CHECK(mem_init("MyApp", NULL));

    int32_t max = mem_brk_max_breakpoints(); // typically 6
    int32_t cur = mem_brk_active_count();
    printf("%d/%d breakpoints in use\n", cur, max);

    uint64_t handle;
    CHECK(mem_brk_install(0x12340, (uintptr_t)replacement, &handle));

    // Removal
    CHECK(mem_brk_remove(handle));
}

// Alternatively, by absolute address
void install_at(uintptr_t addr) {
    uint64_t handle;
    CHECK(mem_brk_install_at(addr, (uintptr_t)replacement, &handle));

    // Or remove by address
    CHECK(mem_brk_remove_at(addr));
}
```

> **When to use hardware breakpoints vs inline hooks:**
>
> - Hardware breakpoints leave **zero code footprint** — ideal for read-only pages or situations where you cannot modify code.
> - Inline hooks let you **call the original function** easily via the trampoline.
> - Hardware breakpoints are limited to **6 concurrent** addresses.

---

## 8. Shellcode loading

Load raw ARM64 machine code into executable memory. Optionally patch in symbol addresses at specified offsets (relocations).

```c
// Simple shellcode — just NOPs followed by RET
static const uint8_t nop_ret[] = {
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0xC0, 0x03, 0x5F, 0xD6, // RET
};

uintptr_t sc_addr;
CHECK(mem_shellcode_load(
    nop_ret, sizeof nop_ret,
    NULL, NULL, 0,   // no relocations
    0,               // no near-address hint
    0,               // auto_free reserved, pass 0
    &sc_addr
));
printf("shellcode at 0x%lx\n", sc_addr);

// Call the loaded shellcode
((void (*)(void))sc_addr)();

// Free when done
CHECK(mem_shellcode_free(sc_addr));
```

### Loading shellcode with symbol relocations

If your shellcode contains embedded 64-bit pointers (e.g., for `BLR` targets), provide relocation entries:

```c
// Shellcode that calls malloc via a relocated pointer
// Offset 16 in the byte array is where the 64-bit malloc address goes
static uint8_t sc[] = {
    // LDR X9, #8      — load pointer from offset 8 ahead
    0x49, 0x00, 0x00, 0x58,
    // BLR X9          — call malloc
    0x20, 0x01, 0x3F, 0xD6,
    // RET
    0xC0, 0x03, 0x5F, 0xD6,
    // .quad placeholder for malloc address (offset 12)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

size_t      reloc_offsets[]  = {12};
const char *reloc_symbols[]  = {"malloc"};

uintptr_t sc_addr;
CHECK(mem_shellcode_load(
    sc, sizeof sc,
    reloc_offsets, reloc_symbols, 1,  // 1 relocation
    0,    // no near-address hint
    0,
    &sc_addr
));

// Use near_address if your shellcode uses B/BL instructions
// that need to reach within ±128 MB of a specific target
uintptr_t target = 0x100123F0;
CHECK(mem_shellcode_load(
    sc, sizeof sc,
    reloc_offsets, reloc_symbols, 1,
    target,  // allocate cave near target
    0,
    &sc_addr
));
```

---

## 9. Common patterns

### Guard against double installation

```c
static uint64_t g_hook_handle = 0;

void ensure_hooked(void) {
    if (mem_hook_is_hooked(known_addr))
        return; // already installed
    mem_hook_install_at(known_addr, (uintptr_t)my_hook, NULL);
}
```

### Enumerate all hooks on teardown

```c
void remove_all_hooks(uint64_t *handles, size_t count) {
    for (size_t i = 0; i < count; i++)
        mem_hook_remove(handles[i]);
}
```

### Read a struct from a data pointer chain

```c
typedef struct { float x, y, z; } Vec3;

// *(*(game_obj + 0x20) + 0x8) is a pointer to a Vec3
uintptr_t offsets[] = {0x20, 0x8};
uintptr_t vec_ptr;
if (mem_read_pointer_chain(game_obj_addr, offsets, 2, &vec_ptr) == MEM_OK) {
    Vec3 pos;
    mem_read(vec_ptr, &pos, sizeof pos);
    printf("pos: %.2f %.2f %.2f\n", pos.x, pos.y, pos.z);
}
```

### Hook + call original (safe pattern)

```c
typedef int32_t (*CheckFn)(void *ctx);
static CheckFn  g_orig_check;
static uint64_t g_check_handle;

static int32_t hooked_check(void *ctx) {
    int32_t result = g_orig_check(ctx); // call original via trampoline
    if (result == 0) {
        // patch return value
        result = 1;
    }
    return result;
}

void setup_check_hook(void) {
    CHECK(mem_init("MyApp", NULL));

    uintptr_t tramp;
    CHECK(mem_hook_install(0xDEAD0, (uintptr_t)hooked_check, &tramp, &g_check_handle));
    g_orig_check = (CheckFn)tramp;
}
```

### Patching with verification

`mem_patch_apply` always verifies the write before returning. If verification fails it returns `MEM_ERR_PATCH`. If you need to confirm again at a later point:

```c
uint8_t expected[] = {0x1F, 0x20, 0x03, 0xD5};
uint8_t actual[4];
if (mem_read(patch_addr, actual, 4) == MEM_OK) {
    if (memcmp(actual, expected, 4) != 0)
        printf("patch was reverted externally\n");
}
```
