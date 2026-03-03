# Specter — Rust Usage

Specter is compiled as a C static library (`libspecter.a`) with a C ABI. Using it from Rust means linking the archive and declaring the `extern "C"` functions. All calls go through `unsafe`; the examples below show a thin safe-wrapper pattern you can adapt.

---

## Table of contents

1. [Project setup](#1-project-setup)
2. [Declaring the bindings](#2-declaring-the-bindings)
3. [Error handling](#3-error-handling)
4. [Initialization](#4-initialization)
5. [Inline hooks](#5-inline-hooks)
6. [Patches](#6-patches)
7. [Memory read / write](#7-memory-read--write)
8. [Image and symbol API](#8-image-and-symbol-api)
9. [Hardware breakpoints](#9-hardware-breakpoints)
10. [Shellcode loading](#10-shellcode-loading)
11. [Common patterns](#11-common-patterns)

---

## 1. Project setup

### `Cargo.toml`

```toml
[dependencies]
# no specter-mem dependency — link the static archive directly

[build-dependencies]
# nothing required; cargo:rustc-link directives handle linking
```

### `build.rs`

```rust
fn main() {
    // Path to the directory containing libspecter.a
    println!("cargo:rustc-link-search=native=/path/to/specter/target/aarch64-apple-ios/release");
    println!("cargo:rustc-link-lib=static=specter");

    // Required system frameworks on iOS/macOS
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
}
```

Set the target once:

```bash
rustup target add aarch64-apple-ios
cargo build --target aarch64-apple-ios
```

---

## 2. Declaring the bindings

Put the raw declarations in `src/ffi.rs` inside your consumer project and declare it in your crate root:

```rust
// src/lib.rs  (or src/main.rs)
mod ffi;
```

`ffi.rs` mirrors `specter.h` exactly:

```rust
use std::ffi::c_char;

// Error codes
pub const MEM_OK: i32           =  0;
pub const MEM_ERR_GENERIC: i32  = -1;
pub const MEM_ERR_NULL: i32     = -2;
pub const MEM_ERR_NOT_FOUND: i32= -3;
pub const MEM_ERR_EXISTS: i32   = -4;
pub const MEM_ERR_ALLOC: i32    = -5;
pub const MEM_ERR_PROTECT: i32  = -6;
pub const MEM_ERR_PATCH: i32    = -7;
pub const MEM_ERR_RELOC: i32    = -8;
pub const MEM_ERR_THREAD: i32   = -9;
pub const MEM_ERR_SYMBOL: i32   = -10;
pub const MEM_ERR_RANGE: i32    = -11;
pub const MEM_ERR_EMPTY: i32    = -12;
pub const MEM_ERR_HW_LIMIT: i32 = -13;

extern "C" {
    // Init
    pub fn mem_init(image_name: *const c_char, base_out: *mut usize) -> i32;

    // Hooks
    pub fn mem_hook_install(rva: usize, replacement: usize,
                            trampoline_out: *mut usize, handle_out: *mut u64) -> i32;
    pub fn mem_hook_symbol(symbol_name: *const c_char, replacement: usize,
                           trampoline_out: *mut usize, handle_out: *mut u64) -> i32;
    pub fn mem_hook_install_at(target: usize, replacement: usize,
                               trampoline_out: *mut usize) -> i32;
    pub fn mem_hook_install_cave(rva: usize, replacement: usize,
                                 trampoline_out: *mut usize, handle_out: *mut u64) -> i32;
    pub fn mem_hook_install_cave_at(target: usize, replacement: usize,
                                    trampoline_out: *mut usize, handle_out: *mut u64) -> i32;
    pub fn mem_hook_remove(handle: u64) -> i32;
    pub fn mem_hook_remove_at(target: usize) -> i32;
    pub fn mem_hook_count() -> usize;
    pub fn mem_hook_is_hooked(target: usize) -> i32;
    pub fn mem_hook_list(buf: *mut usize, cap: usize, count_out: *mut usize) -> i32;

    // Patches
    pub fn mem_patch_apply(rva: usize, hex_str: *const c_char, address_out: *mut usize) -> i32;
    pub fn mem_patch_apply_at(address: usize, data: *const u8, len: usize,
                              address_out: *mut usize) -> i32;
    pub fn mem_patch_apply_cave(rva: usize, hex_str: *const c_char, address_out: *mut usize) -> i32;
    pub fn mem_patch_revert(address: usize) -> i32;

    // Read / Write
    pub fn mem_read(address: usize, out: *mut std::ffi::c_void, size: usize) -> i32;
    pub fn mem_read_rva(rva: usize, out: *mut std::ffi::c_void, size: usize) -> i32;
    pub fn mem_read_pointer_chain(base: usize, offsets: *const usize,
                                  offset_count: usize, result_out: *mut usize) -> i32;
    pub fn mem_write(address: usize, value: *const std::ffi::c_void, size: usize) -> i32;
    pub fn mem_write_rva(rva: usize, value: *const std::ffi::c_void, size: usize) -> i32;
    pub fn mem_write_bytes(address: usize, data: *const u8, len: usize) -> i32;

    // Image / Symbol
    pub fn mem_get_image_base(image_name: *const c_char, base_out: *mut usize) -> i32;
    pub fn mem_resolve_symbol(symbol_name: *const c_char, address_out: *mut usize) -> i32;
    pub fn mem_cache_symbol(symbol_name: *const c_char, address: usize);
    pub fn mem_clear_symbol_cache();

    // Hardware breakpoints
    pub fn mem_brk_install(rva: usize, replacement: usize, handle_out: *mut u64) -> i32;
    pub fn mem_brk_install_at(target: usize, replacement: usize, handle_out: *mut u64) -> i32;
    pub fn mem_brk_remove(handle: u64) -> i32;
    pub fn mem_brk_remove_at(target: usize) -> i32;
    pub fn mem_brk_active_count() -> i32;
    pub fn mem_brk_max_breakpoints() -> i32;

    // Shellcode
    pub fn mem_shellcode_load(code: *const u8, code_len: usize,
                              reloc_offsets: *const usize, reloc_symbols: *const *const c_char,
                              reloc_count: usize, near_address: usize, auto_free: i32,
                              address_out: *mut usize) -> i32;
    pub fn mem_shellcode_free(address: usize) -> i32;
}
```

---

## 3. Error handling

Every function returns `i32`. Zero is `MEM_OK`; negative values are errors.

A simple result type makes call sites cleaner:

```rust
use crate::ffi::MEM_OK;

#[derive(Debug)]
pub struct SpecterError(pub i32);

pub type Result<T> = std::result::Result<T, SpecterError>;

fn check(rc: i32) -> Result<()> {
    if rc == MEM_OK { Ok(()) } else { Err(SpecterError(rc)) }
}
```

---

## 4. Initialization

Call once before any RVA-based operation.

```rust
use std::ffi::CString;
use crate::ffi;

pub fn init(image_name: &str) -> Result<usize> {
    let name = CString::new(image_name).unwrap();
    let mut base: usize = 0;
    unsafe { check(ffi::mem_init(name.as_ptr(), &mut base))? };
    Ok(base)
}

// Usage
let base = init("MyApp")?;
println!("MyApp loaded at {:#x}", base);
```

To look up a different image without changing the RVA target:

```rust
pub fn image_base(name: &str) -> Result<usize> {
    let cname = CString::new(name).unwrap();
    let mut base: usize = 0;
    unsafe { check(ffi::mem_get_image_base(cname.as_ptr(), &mut base))? };
    Ok(base)
}

let uikit = image_base("UIKitCore")?;
```

---

## 5. Inline hooks

### Hook by RVA

```rust
use std::sync::OnceLock;

// Signature of the function we are hooking
type AddFn = unsafe extern "C" fn(a: i32, b: i32) -> i32;

static ORIG_ADD: OnceLock<AddFn> = OnceLock::new();
static mut HOOK_HANDLE: u64 = 0;

unsafe extern "C" fn hooked_add(a: i32, b: i32) -> i32 {
    println!("add({a}, {b})");
    ORIG_ADD.get().unwrap()(a, b)   // call original via trampoline
}

pub fn install_add_hook() -> Result<()> {
    let mut trampoline: usize = 0;
    let mut handle: u64 = 0;
    unsafe {
        check(ffi::mem_hook_install(
            0x12340,                              // RVA from static analysis
            hooked_add as usize,
            &mut trampoline,
            &mut handle,
        ))?;
        ORIG_ADD.set(std::mem::transmute(trampoline)).ok();
        HOOK_HANDLE = handle;
    }
    Ok(())
}

pub fn remove_add_hook() -> Result<()> {
    unsafe { check(ffi::mem_hook_remove(HOOK_HANDLE)) }
}
```

### Hook by symbol name

```rust
type MallocFn = unsafe extern "C" fn(size: usize) -> *mut std::ffi::c_void;
static ORIG_MALLOC: OnceLock<MallocFn> = OnceLock::new();

unsafe extern "C" fn hooked_malloc(size: usize) -> *mut std::ffi::c_void {
    println!("malloc({size})");
    ORIG_MALLOC.get().unwrap()(size)
}

pub fn hook_malloc() -> Result<()> {
    let sym = CString::new("malloc").unwrap();
    let mut trampoline: usize = 0;
    let mut handle: u64 = 0;
    unsafe {
        check(ffi::mem_hook_symbol(
            sym.as_ptr(),
            hooked_malloc as usize,
            &mut trampoline,
            &mut handle,
        ))?;
        ORIG_MALLOC.set(std::mem::transmute(trampoline)).ok();
    }
    Ok(())
}
```

### Hook by absolute address

```rust
pub fn hook_at(target: usize, replacement: usize) -> Result<usize> {
    let mut trampoline: usize = 0;
    unsafe { check(ffi::mem_hook_install_at(target, replacement, &mut trampoline))? };
    Ok(trampoline)
}

pub fn remove_hook_at(target: usize) -> Result<()> {
    unsafe { check(ffi::mem_hook_remove_at(target)) }
}
```

### Code-cave hooks

```rust
pub fn hook_cave(rva: usize, replacement: usize) -> Result<(usize, u64)> {
    let mut trampoline: usize = 0;
    let mut handle: u64 = 0;
    unsafe {
        check(ffi::mem_hook_install_cave(rva, replacement, &mut trampoline, &mut handle))?;
    }
    Ok((trampoline, handle))
}
```

> Code-cave trampolines live inside the image's own `__TEXT` NOP padding — no anonymous `mmap` pages are created.

### Hook introspection

```rust
pub fn hook_count() -> usize {
    unsafe { ffi::mem_hook_count() }
}

pub fn is_hooked(target: usize) -> bool {
    unsafe { ffi::mem_hook_is_hooked(target) == 1 }
}

pub fn list_hooks() -> Vec<usize> {
    let mut buf = vec![0usize; 64];
    let mut total: usize = 0;
    unsafe { ffi::mem_hook_list(buf.as_mut_ptr(), buf.len(), &mut total) };
    buf.truncate(total.min(buf.len()));
    buf
}
```

---

## 6. Patches

### Hex patch by RVA

```rust
pub fn patch(rva: usize, hex: &str) -> Result<usize> {
    let hex_cstr = CString::new(hex).unwrap();
    let mut addr: usize = 0;
    unsafe { check(ffi::mem_patch_apply(rva, hex_cstr.as_ptr(), &mut addr))? };
    Ok(addr)
}

// NOP a 4-byte instruction
let patch_addr = patch(0xABCD0, "1F2003D5")?;

// RET immediately
patch(0xABCD0, "C0035FD6")?;

// Revert
unsafe { check(ffi::mem_patch_revert(patch_addr))? };
```

### Raw bytes at absolute address

```rust
pub fn patch_bytes(address: usize, data: &[u8]) -> Result<()> {
    unsafe {
        check(ffi::mem_patch_apply_at(address, data.as_ptr(), data.len(),
                                              std::ptr::null_mut()))
    }
}

let nop = [0x1Fu8, 0x20, 0x03, 0xD5];
patch_bytes(0x100123F0, &nop)?;
```

### Code-cave patch

```rust
pub fn patch_cave(rva: usize, hex: &str) -> Result<usize> {
    let hex_cstr = CString::new(hex).unwrap();
    let mut addr: usize = 0;
    unsafe {
        check(ffi::mem_patch_apply_cave(rva, hex_cstr.as_ptr(), &mut addr))?;
    }
    Ok(addr)
}

// Payload goes into NOP padding; target gets a 4-byte branch
patch_cave(0xABCD0, "E0031FAAC0035FD6")?;
```

---

## 7. Memory read / write

```rust
/// Read a value of type T from an absolute address.
pub unsafe fn read<T: Copy>(address: usize) -> Result<T> {
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    check(ffi::mem_read(
        address,
        out.as_mut_ptr() as *mut std::ffi::c_void,
        std::mem::size_of::<T>(),
    ))?;
    Ok(out.assume_init())
}

/// Write a value of type T to an absolute address.
pub unsafe fn write<T>(address: usize, value: &T) -> Result<()> {
    check(ffi::mem_write(
        address,
        value as *const T as *const std::ffi::c_void,
        std::mem::size_of::<T>(),
    ))
}

// Usage
let flags: u32 = unsafe { read(0x100123F0)? };
unsafe { write(0x100123F4, &5.0f32)? };
```

### RVA-relative access

```rust
pub unsafe fn read_rva<T: Copy>(rva: usize) -> Result<T> {
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    check(ffi::mem_read_rva(
        rva,
        out.as_mut_ptr() as *mut std::ffi::c_void,
        std::mem::size_of::<T>(),
    ))?;
    Ok(out.assume_init())
}

let value: u32 = unsafe { read_rva(0xABCD0)? };
```

### Pointer chain traversal

```rust
pub fn follow_chain(base: usize, offsets: &[usize]) -> Result<usize> {
    let mut result: usize = 0;
    let (ptr, len) = if offsets.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (offsets.as_ptr(), offsets.len())
    };
    unsafe { check(ffi::mem_read_pointer_chain(base, ptr, len, &mut result))? };
    Ok(result)
}

// Follow: base → *(base + 0x10) → *(… + 0x28) → *(… + 0x8)
let addr = follow_chain(0x100200000, &[0x10, 0x28, 0x8])?;
println!("final addr: {addr:#x}");
```

### Stealth write to code pages

```rust
pub fn write_bytes(address: usize, data: &[u8]) -> Result<()> {
    unsafe {
        check(ffi::mem_write_bytes(address, data.as_ptr(), data.len()))
    }
}

write_bytes(0x100123F0, &[0x1F, 0x20, 0x03, 0xD5])?; // NOP
```

---

## 8. Image and symbol API

```rust
pub fn resolve_symbol(name: &str) -> Result<usize> {
    let cname = CString::new(name).unwrap();
    let mut addr: usize = 0;
    unsafe { check(ffi::mem_resolve_symbol(cname.as_ptr(), &mut addr))? };
    Ok(addr)
}

pub fn cache_symbol(name: &str, address: usize) {
    let cname = CString::new(name).unwrap();
    unsafe { ffi::mem_cache_symbol(cname.as_ptr(), address) };
}

pub fn clear_symbol_cache() {
    unsafe { ffi::mem_clear_symbol_cache() };
}

// Usage
let malloc_addr = resolve_symbol("malloc")?;
cache_symbol("my_private_func", 0x100099ABC);
```

---

## 9. Hardware breakpoints

Hardware breakpoints intercept execution without modifying any code — ARM64 debug registers raise a Mach exception redirected to your replacement function. Maximum: 6 concurrent.

```rust
pub fn install_breakpoint(rva: usize, replacement: usize) -> Result<u64> {
    let mut handle: u64 = 0;
    unsafe { check(ffi::mem_brk_install(rva, replacement, &mut handle))? };
    Ok(handle)
}

pub fn remove_breakpoint(handle: u64) -> Result<()> {
    unsafe { check(ffi::mem_brk_remove(handle)) }
}

// Example
unsafe extern "C" fn my_replacement() {
    println!("intercepted");
    // Do NOT call the original here — it would re-trigger the breakpoint.
    // Use an inline hook (mem_hook_install) if you need to call the original.
}

let max = unsafe { ffi::mem_brk_max_breakpoints() };
let cur = unsafe { ffi::mem_brk_active_count() };
println!("{cur}/{max} breakpoints in use");

let handle = install_breakpoint(0x12340, my_replacement as usize)?;
remove_breakpoint(handle)?;
```

---

## 10. Shellcode loading

```rust
pub fn load_shellcode(
    code: &[u8],
    reloc_offsets: &[usize],
    reloc_symbols: &[&str],
    near_address: usize,
) -> Result<usize> {
    assert_eq!(reloc_offsets.len(), reloc_symbols.len());

    // Convert symbol names to CStrings first, then collect raw pointers
    let cstrings: Vec<CString> = reloc_symbols.iter()
        .map(|s| CString::new(*s).unwrap())
        .collect();
    let sym_ptrs: Vec<*const i8> = cstrings.iter().map(|cs| cs.as_ptr()).collect();

    let (off_ptr, sym_ptr, count) = if reloc_offsets.is_empty() {
        (std::ptr::null(), std::ptr::null(), 0)
    } else {
        (reloc_offsets.as_ptr(), sym_ptrs.as_ptr(), reloc_offsets.len())
    };

    let mut addr: usize = 0;
    unsafe {
        check(ffi::mem_shellcode_load(
            code.as_ptr(), code.len(),
            off_ptr, sym_ptr, count,
            near_address, 0,
            &mut addr,
        ))?;
    }
    Ok(addr)
}

pub fn free_shellcode(address: usize) -> Result<()> {
    unsafe { check(ffi::mem_shellcode_free(address)) }
}

// Simple shellcode — NOP, NOP, RET
let nop_ret: &[u8] = &[
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0xC0, 0x03, 0x5F, 0xD6, // RET
];

let sc_addr = load_shellcode(nop_ret, &[], &[], 0)?;
println!("shellcode at {sc_addr:#x}");

// Cast and call
let f: unsafe extern "C" fn() = unsafe { std::mem::transmute(sc_addr) };
unsafe { f() };

free_shellcode(sc_addr)?;
```

### With symbol relocations

```rust
// Shellcode that calls malloc via a relocated pointer at offset 12
let sc: &[u8] = &[
    0x49, 0x00, 0x00, 0x58, // LDR X9, #8
    0x20, 0x01, 0x3F, 0xD6, // BLR X9
    0xC0, 0x03, 0x5F, 0xD6, // RET
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // .quad placeholder
];

let addr = load_shellcode(sc, &[12], &["malloc"], 0)?;
```

---

## 11. Common patterns

### Guard against double installation

```rust
fn ensure_hooked(known_addr: usize, replacement: usize) -> Result<()> {
    if is_hooked(known_addr) {
        return Ok(());
    }
    hook_at(known_addr, replacement)?;
    Ok(())
}
```

### RAII hook guard

```rust
pub struct HookGuard(u64);

impl HookGuard {
    pub fn install(rva: usize, replacement: usize) -> Result<Self> {
        let mut trampoline: usize = 0;
        let mut handle: u64 = 0;
        unsafe {
            check(ffi::mem_hook_install(rva, replacement, &mut trampoline, &mut handle))?;
        }
        Ok(Self(handle))
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        unsafe { ffi::mem_hook_remove(self.0) };
    }
}

// Hook is automatically removed when guard goes out of scope
{
    let _guard = HookGuard::install(0x12340, hooked_add as usize)?;
    // ... do work ...
} // hook removed here
```

### Read a struct through a pointer chain

```rust
#[repr(C)]
struct Vec3 { x: f32, y: f32, z: f32 }

let vec_ptr = follow_chain(game_obj_addr, &[0x20, 0x8])?;
let pos: Vec3 = unsafe { read(vec_ptr)? };
println!("pos: {:.2} {:.2} {:.2}", pos.x, pos.y, pos.z);
```

### Hook + call original

```rust
type CheckFn = unsafe extern "C" fn(ctx: *mut std::ffi::c_void) -> i32;
static ORIG_CHECK: OnceLock<CheckFn> = OnceLock::new();
static mut CHECK_HANDLE: u64 = 0;

unsafe extern "C" fn hooked_check(ctx: *mut std::ffi::c_void) -> i32 {
    let result = ORIG_CHECK.get().unwrap()(ctx);
    if result == 0 { 1 } else { result }
}

pub fn setup_check_hook() -> Result<()> {
    let mut tramp: usize = 0;
    let mut handle: u64 = 0;
    unsafe {
        check(ffi::mem_hook_install(
            0xDEAD0, hooked_check as usize, &mut tramp, &mut handle,
        ))?;
        ORIG_CHECK.set(std::mem::transmute(tramp)).ok();
        CHECK_HANDLE = handle;
    }
    Ok(())
}
```
