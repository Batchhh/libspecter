//! # C FFI Layer
//!
//! Exposes the memory manipulation library to C/C++ callers via a stable ABI.
//! All functions follow these conventions:
//!
//! - Return `MEM_OK` (0) on success, or a negative `MEM_ERR_*` code on failure.
//! - Output parameters are written only when the function succeeds, unless otherwise noted.
//! - Pointer out-parameters that are documented as "optional" may be null; the function
//!   silently skips writing them in that case.
//! - Pointer out-parameters that are documented as "required" return `MEM_ERR_NULL` when null.
//! - All string parameters are expected to be valid, null-terminated UTF-8 C strings.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::{CStr, c_char};
use std::sync::atomic::{AtomicU64, Ordering};

// Error code constants
pub const MEM_OK: i32 = 0;
pub const MEM_ERR_GENERIC: i32 = -1;
pub const MEM_ERR_NULL: i32 = -2;
pub const MEM_ERR_NOT_FOUND: i32 = -3;
pub const MEM_ERR_EXISTS: i32 = -4;
pub const MEM_ERR_ALLOC: i32 = -5;
pub const MEM_ERR_PROTECT: i32 = -6;
pub const MEM_ERR_PATCH: i32 = -7;
pub const MEM_ERR_RELOC: i32 = -8;
pub const MEM_ERR_THREAD: i32 = -9;
pub const MEM_ERR_SYMBOL: i32 = -10;
pub const MEM_ERR_RANGE: i32 = -11;
pub const MEM_ERR_EMPTY: i32 = -12;
pub const MEM_ERR_HW_LIMIT: i32 = -13;

// Private error-mapping helpers

fn hook_err(e: &crate::memory::manipulation::hook::HookError) -> i32 {
    use crate::memory::manipulation::hook::HookError;
    match e {
        HookError::AlreadyExists(_) => MEM_ERR_EXISTS,
        HookError::ImageBaseNotFound(_) => MEM_ERR_NOT_FOUND,
        HookError::AllocationFailed => MEM_ERR_ALLOC,
        HookError::ProtectionFailed(_) => MEM_ERR_PROTECT,
        HookError::PatchFailed => MEM_ERR_PATCH,
        HookError::RelocationFailed => MEM_ERR_RELOC,
        HookError::ThreadError(_) => MEM_ERR_THREAD,
        HookError::SymbolError(_) => MEM_ERR_SYMBOL,
    }
}

fn patch_err(e: &crate::memory::manipulation::patch::PatchError) -> i32 {
    use crate::memory::manipulation::patch::PatchError;
    match e {
        PatchError::InvalidHex(_) => MEM_ERR_GENERIC,
        PatchError::ImageBaseNotFound(_) => MEM_ERR_NOT_FOUND,
        PatchError::ProtectionFailed(_) => MEM_ERR_PROTECT,
        PatchError::ThreadError(_) => MEM_ERR_THREAD,
        PatchError::EmptyInstructions => MEM_ERR_EMPTY,
        PatchError::CaveError(_) => MEM_ERR_ALLOC,
        PatchError::BranchOutOfRange => MEM_ERR_RANGE,
        PatchError::VerificationFailed => MEM_ERR_PATCH,
    }
}

fn rw_err(e: &crate::memory::manipulation::rw::RwError) -> i32 {
    use crate::memory::manipulation::rw::RwError;
    match e {
        RwError::NullPointer => MEM_ERR_NULL,
        RwError::ImageBaseNotFound(_) => MEM_ERR_NOT_FOUND,
        RwError::ProtectionFailed(_) => MEM_ERR_PROTECT,
        RwError::ThreadError(_) => MEM_ERR_THREAD,
    }
}

#[cfg(target_os = "ios")]
fn brk_err(e: &crate::memory::platform::breakpoint::BrkHookError) -> i32 {
    use crate::memory::platform::breakpoint::BrkHookError;
    match e {
        BrkHookError::TooManyHooks => MEM_ERR_HW_LIMIT,
        BrkHookError::AlreadyExists(_) => MEM_ERR_EXISTS,
        BrkHookError::ExceedsHwBreakpoints(_) => MEM_ERR_HW_LIMIT,
        BrkHookError::SetStateFailed => MEM_ERR_PROTECT,
        BrkHookError::NotFound(_) => MEM_ERR_NOT_FOUND,
        BrkHookError::InitFailed => MEM_ERR_GENERIC,
    }
}

fn loader_err(e: &crate::memory::allocation::shellcode::LoaderError) -> i32 {
    use crate::memory::allocation::shellcode::LoaderError;
    match e {
        LoaderError::AllocationFailed(_) => MEM_ERR_ALLOC,
        LoaderError::SymbolNotFound(_) => MEM_ERR_SYMBOL,
        LoaderError::WriteFailed(_) => MEM_ERR_PATCH,
        LoaderError::InvalidSize(_) => MEM_ERR_EMPTY,
        LoaderError::RelocationFailed(_) => MEM_ERR_RELOC,
    }
}

// Handle slabs (global registries)

static HOOK_REGISTRY: Lazy<Mutex<HashMap<u64, crate::memory::manipulation::hook::Hook>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static PATCH_REGISTRY: Lazy<Mutex<HashMap<usize, crate::memory::manipulation::patch::Patch>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(target_os = "ios")]
static BRK_REGISTRY: Lazy<Mutex<HashMap<u64, crate::memory::platform::breakpoint::Breakpoint>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static SHELLCODE_REGISTRY: Lazy<
    Mutex<HashMap<usize, crate::memory::allocation::shellcode::LoadedShellcode>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));

static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_handle() -> u64 {
    HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// Helpers for safe C-string conversion

/// Converts a raw C string pointer to a `&str`.
/// Returns `Err(MEM_ERR_NULL)` if the pointer is null, or `Err(MEM_ERR_GENERIC)` if it is not
/// valid UTF-8.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(MEM_ERR_NULL);
    }
    unsafe { CStr::from_ptr(ptr).to_str().map_err(|_| MEM_ERR_GENERIC) }
}

// Init API

/// Initializes the library by storing the target image name for all subsequent RVA-based
/// operations (hooks, patches, reads/writes relative to image base).
///
/// Must be called before any function that takes an RVA (relative virtual address).
///
/// `base_out` is optional: when non-null, receives the resolved load address of the image
/// (ASLR slide applied).  Returns `MEM_ERR_NOT_FOUND` if the image is not currently loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_init(image_name: *const c_char, base_out: *mut usize) -> i32 {
    let name = unsafe {
        match cstr_to_str(image_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    crate::config::set_target_image_name(name);
    if !base_out.is_null() {
        match crate::memory::info::image::get_image_base(name) {
            Ok(base) => unsafe { *base_out = base },
            Err(_) => return MEM_ERR_NOT_FOUND,
        }
    }
    MEM_OK
}

// Hook API

/// Installs an inline hook at `rva` (relative to the target image base).
///
/// `trampoline_out` receives the trampoline address; it may be null if the caller
/// does not need it.  `handle_out` is required (must be non-null) because the
/// returned handle is the only way to remove the hook via `mem_hook_remove`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_install(
    rva: usize,
    replacement: usize,
    trampoline_out: *mut usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    let hook = unsafe {
        match crate::memory::manipulation::hook::install(rva, replacement) {
            Ok(h) => h,
            Err(ref e) => return hook_err(e),
        }
    };
    let trampoline = hook.trampoline();
    let handle = next_handle();
    HOOK_REGISTRY.lock().insert(handle, hook);
    if !trampoline_out.is_null() {
        unsafe { *trampoline_out = trampoline };
    }
    unsafe { *handle_out = handle };
    MEM_OK
}

/// Installs an inline hook on the symbol named by `symbol_name`.
///
/// `trampoline_out` is optional; `handle_out` is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_symbol(
    symbol_name: *const c_char,
    replacement: usize,
    trampoline_out: *mut usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    let name = unsafe {
        match cstr_to_str(symbol_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let hook = unsafe {
        match crate::memory::manipulation::hook::hook_symbol(name, replacement) {
            Ok(h) => h,
            Err(ref e) => return hook_err(e),
        }
    };
    let trampoline = hook.trampoline();
    let handle = next_handle();
    HOOK_REGISTRY.lock().insert(handle, hook);
    if !trampoline_out.is_null() {
        unsafe { *trampoline_out = trampoline };
    }
    unsafe { *handle_out = handle };
    MEM_OK
}

/// Installs an inline hook at an absolute address.
///
/// No registry entry is created; the hook is removed via `mem_hook_remove_at`.
/// `trampoline_out` receives the trampoline address and is optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_install_at(
    target: usize,
    replacement: usize,
    trampoline_out: *mut usize,
) -> i32 {
    let trampoline = unsafe {
        match crate::memory::manipulation::hook::install_at_address(target, replacement) {
            Ok(t) => t,
            Err(ref e) => return hook_err(e),
        }
    };
    if !trampoline_out.is_null() {
        unsafe { *trampoline_out = trampoline };
    }
    MEM_OK
}

/// Installs a code-cave hook at `rva` (relative to the target image base).
///
/// `trampoline_out` is optional; `handle_out` is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_install_cave(
    rva: usize,
    replacement: usize,
    trampoline_out: *mut usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    let hook = unsafe {
        match crate::memory::manipulation::hook::install_in_cave(rva, replacement) {
            Ok(h) => h,
            Err(ref e) => return hook_err(e),
        }
    };
    let trampoline = hook.trampoline();
    let handle = next_handle();
    HOOK_REGISTRY.lock().insert(handle, hook);
    if !trampoline_out.is_null() {
        unsafe { *trampoline_out = trampoline };
    }
    unsafe { *handle_out = handle };
    MEM_OK
}

/// Installs a code-cave hook at an absolute address.
///
/// `trampoline_out` is optional; `handle_out` is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_install_cave_at(
    target: usize,
    replacement: usize,
    trampoline_out: *mut usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    let hook = unsafe {
        match crate::memory::manipulation::hook::install_in_cave_at_address(target, replacement) {
            Ok(h) => h,
            Err(ref e) => return hook_err(e),
        }
    };
    let trampoline = hook.trampoline();
    let handle = next_handle();
    HOOK_REGISTRY.lock().insert(handle, hook);
    if !trampoline_out.is_null() {
        unsafe { *trampoline_out = trampoline };
    }
    unsafe { *handle_out = handle };
    MEM_OK
}

/// Removes a hook by its handle (installed via any `mem_hook_install*` function that
/// produces a handle).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_remove(handle: u64) -> i32 {
    let hook = match HOOK_REGISTRY.lock().remove(&handle) {
        Some(h) => h,
        None => return MEM_ERR_NOT_FOUND,
    };
    hook.remove();
    MEM_OK
}

/// Removes a hook that was installed at an absolute address via `mem_hook_install_at`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_remove_at(target: usize) -> i32 {
    let removed = unsafe { crate::memory::manipulation::hook::remove_at_address(target) };
    if removed { MEM_OK } else { MEM_ERR_NOT_FOUND }
}

/// Returns the number of hooks currently managed by the internal registry inside
/// the hook module.  Note: hooks installed via `mem_hook_install_at` (no-handle
/// variant) are still counted by the underlying registry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_count() -> usize {
    crate::memory::manipulation::hook::hook_count()
}

/// Returns 1 if there is an active hook at `target`, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_is_hooked(target: usize) -> i32 {
    if crate::memory::manipulation::hook::is_hooked(target) {
        1
    } else {
        0
    }
}

/// Fills `buf` with up to `cap` hook target addresses from the internal hook registry.
/// Writes the total number of active hooks to `*count_out` (which may be larger than
/// `cap` if the buffer was too small).  `count_out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_hook_list(buf: *mut usize, cap: usize, count_out: *mut usize) -> i32 {
    if count_out.is_null() {
        return MEM_ERR_NULL;
    }
    let hooks = crate::memory::manipulation::hook::list_hooks();
    let total = hooks.len();
    unsafe { *count_out = total };
    if !buf.is_null() {
        let to_copy = total.min(cap);
        for (i, &addr) in hooks.iter().take(to_copy).enumerate() {
            unsafe { *buf.add(i) = addr };
        }
    }
    MEM_OK
}

// Patch API

/// Applies a hex-string patch at `rva` (relative to the target image base).
///
/// Stores the resulting `Patch` in the registry keyed by its address.
/// `address_out` receives the absolute address of the patch and is optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_apply(
    rva: usize,
    hex_str: *const c_char,
    address_out: *mut usize,
) -> i32 {
    let hex = unsafe {
        match cstr_to_str(hex_str) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let patch = match crate::memory::manipulation::patch::apply(rva, hex) {
        Ok(p) => p,
        Err(ref e) => return patch_err(e),
    };
    let addr = patch.address();
    if !address_out.is_null() {
        unsafe { *address_out = addr };
    }
    PATCH_REGISTRY.lock().insert(addr, patch);
    MEM_OK
}

/// Applies a raw-bytes patch at an absolute address.
///
/// `data` and `len` form a byte slice.  `address_out` is optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_apply_at(
    address: usize,
    data: *const u8,
    len: usize,
    address_out: *mut usize,
) -> i32 {
    if data.is_null() {
        return MEM_ERR_NULL;
    }
    if len == 0 {
        return MEM_ERR_EMPTY;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let patch = match crate::memory::manipulation::patch::apply_at_address(address, slice) {
        Ok(p) => p,
        Err(ref e) => return patch_err(e),
    };
    let addr = patch.address();
    if !address_out.is_null() {
        unsafe { *address_out = addr };
    }
    PATCH_REGISTRY.lock().insert(addr, patch);
    MEM_OK
}

/// Applies a hex-string patch via a code cave at `rva`.
///
/// `address_out` is optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_apply_cave(
    rva: usize,
    hex_str: *const c_char,
    address_out: *mut usize,
) -> i32 {
    let hex = unsafe {
        match cstr_to_str(hex_str) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let patch = match crate::memory::manipulation::patch::apply_in_cave(rva, hex) {
        Ok(p) => p,
        Err(ref e) => return patch_err(e),
    };
    let addr = patch.address();
    if !address_out.is_null() {
        unsafe { *address_out = addr };
    }
    PATCH_REGISTRY.lock().insert(addr, patch);
    MEM_OK
}

/// Reverts the patch that was applied at `address`, restoring the original bytes.
/// The patch is removed from the registry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_revert(address: usize) -> i32 {
    let patch = match PATCH_REGISTRY.lock().remove(&address) {
        Some(p) => p,
        None => return MEM_ERR_NOT_FOUND,
    };
    patch.revert();
    MEM_OK
}

// Read / Write API

/// Reads `size` raw bytes from `address` into `out`.
///
/// Works for any scalar type — pass `sizeof(T)` as size.
/// In C++ prefer the typed template wrapper `mem_read<T>(address, &value)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_read(address: usize, out: *mut u8, size: usize) -> i32 {
    if out.is_null() {
        return MEM_ERR_NULL;
    }
    if address == 0 {
        return MEM_ERR_NULL;
    }
    if size == 0 {
        return MEM_OK;
    }
    unsafe { std::ptr::copy_nonoverlapping(address as *const u8, out, size) };
    MEM_OK
}

/// Reads `size` raw bytes from `rva` (relative to the target image base) into `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_read_rva(rva: usize, out: *mut u8, size: usize) -> i32 {
    if out.is_null() {
        return MEM_ERR_NULL;
    }
    if size == 0 {
        return MEM_OK;
    }
    let image_name = match crate::config::get_target_image_name() {
        Some(n) => n,
        None => return MEM_ERR_NOT_FOUND,
    };
    let base = match crate::memory::info::image::get_image_base(&image_name) {
        Ok(b) => b,
        Err(_) => return MEM_ERR_NOT_FOUND,
    };
    unsafe { std::ptr::copy_nonoverlapping((base + rva) as *const u8, out, size) };
    MEM_OK
}

/// Follows a pointer chain starting at `base` through `offset_count` offsets.
/// `result_out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_read_pointer_chain(
    base: usize,
    offsets: *const usize,
    offset_count: usize,
    result_out: *mut usize,
) -> i32 {
    if result_out.is_null() {
        return MEM_ERR_NULL;
    }
    if offsets.is_null() && offset_count > 0 {
        return MEM_ERR_NULL;
    }
    let slice = if offset_count == 0 {
        &[] as &[usize]
    } else {
        unsafe { std::slice::from_raw_parts(offsets, offset_count) }
    };
    match unsafe { crate::memory::manipulation::rw::read_pointer_chain(base, slice) } {
        Ok(v) => {
            unsafe { *result_out = v };
            MEM_OK
        }
        Err(ref e) => rw_err(e),
    }
}

/// Writes `size` raw bytes from `value` to `address` (data memory, direct write).
///
/// For patching executable code use `mem_write_bytes` (stealth mach_vm_remap path).
/// In C++ prefer the typed template wrapper `mem_write<T>(address, value)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_write(address: usize, value: *const u8, size: usize) -> i32 {
    if value.is_null() {
        return MEM_ERR_NULL;
    }
    if address == 0 {
        return MEM_ERR_NULL;
    }
    if size == 0 {
        return MEM_OK;
    }
    unsafe { std::ptr::copy_nonoverlapping(value, address as *mut u8, size) };
    MEM_OK
}

/// Writes `size` raw bytes from `value` to `rva` (relative to the target image base).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_write_rva(rva: usize, value: *const u8, size: usize) -> i32 {
    if value.is_null() {
        return MEM_ERR_NULL;
    }
    if size == 0 {
        return MEM_OK;
    }
    let image_name = match crate::config::get_target_image_name() {
        Some(n) => n,
        None => return MEM_ERR_NOT_FOUND,
    };
    let base = match crate::memory::info::image::get_image_base(&image_name) {
        Ok(b) => b,
        Err(_) => return MEM_ERR_NOT_FOUND,
    };
    unsafe { std::ptr::copy_nonoverlapping(value, (base + rva) as *mut u8, size) };
    MEM_OK
}

/// Writes `len` bytes from `data` to `address` via the stealth write path
/// (mach_vm_remap + icache flush). Use this for patching executable code pages.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_write_bytes(address: usize, data: *const u8, len: usize) -> i32 {
    if data.is_null() {
        return MEM_ERR_NULL;
    }
    if len == 0 {
        return MEM_OK;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    match unsafe { crate::memory::manipulation::rw::write_bytes(address, slice) } {
        Ok(()) => MEM_OK,
        Err(ref e) => rw_err(e),
    }
}

// Image / Symbol API

/// Retrieves the base address of the loaded image named `image_name`.
/// `base_out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_get_image_base(
    image_name: *const c_char,
    base_out: *mut usize,
) -> i32 {
    if base_out.is_null() {
        return MEM_ERR_NULL;
    }
    let name = unsafe {
        match cstr_to_str(image_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    match crate::memory::info::image::get_image_base(name) {
        Ok(base) => {
            unsafe { *base_out = base };
            MEM_OK
        }
        Err(_) => MEM_ERR_NOT_FOUND,
    }
}

/// Resolves the address of `symbol_name` via `dlsym` (with caching).
/// `address_out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_resolve_symbol(
    symbol_name: *const c_char,
    address_out: *mut usize,
) -> i32 {
    if address_out.is_null() {
        return MEM_ERR_NULL;
    }
    let name = unsafe {
        match cstr_to_str(symbol_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    match crate::memory::info::symbol::resolve_symbol(name) {
        Ok(addr) => {
            unsafe { *address_out = addr };
            MEM_OK
        }
        Err(_) => MEM_ERR_SYMBOL,
    }
}

/// Manually inserts `(symbol_name, address)` into the symbol cache.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_cache_symbol(symbol_name: *const c_char, address: usize) {
    let name = unsafe {
        match cstr_to_str(symbol_name) {
            Ok(s) => s,
            Err(_) => return,
        }
    };
    crate::memory::info::symbol::cache_symbol(name, address);
}

/// Clears all entries from the symbol cache.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_clear_symbol_cache() {
    crate::memory::info::symbol::clear_cache();
}

// Breakpoint API

/// Installs a hardware breakpoint hook at `rva` (relative to the target image base).
/// `handle_out` must be non-null.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_brk_install(
    rva: usize,
    replacement: usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    let bp = unsafe {
        match crate::memory::platform::breakpoint::install(rva, replacement) {
            Ok(b) => b,
            Err(ref e) => return brk_err(e),
        }
    };
    let handle = next_handle();
    BRK_REGISTRY.lock().insert(handle, bp);
    unsafe { *handle_out = handle };
    MEM_OK
}

/// Installs a hardware breakpoint hook at an absolute address.
/// `handle_out` must be non-null.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_brk_install_at(
    target: usize,
    replacement: usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    let bp = unsafe {
        match crate::memory::platform::breakpoint::install_at_address(target, replacement) {
            Ok(b) => b,
            Err(ref e) => return brk_err(e),
        }
    };
    let handle = next_handle();
    BRK_REGISTRY.lock().insert(handle, bp);
    unsafe { *handle_out = handle };
    MEM_OK
}

/// Removes a breakpoint by handle.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_brk_remove(handle: u64) -> i32 {
    let bp = match BRK_REGISTRY.lock().remove(&handle) {
        Some(b) => b,
        None => return MEM_ERR_NOT_FOUND,
    };
    match bp.remove() {
        Ok(()) => MEM_OK,
        Err(ref e) => brk_err(e),
    }
}

/// Removes the breakpoint registered for `target` by iterating the registry.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_brk_remove_at(target: usize) -> i32 {
    let mut registry = BRK_REGISTRY.lock();
    // Find the handle whose Breakpoint watches `target`.
    let handle = match registry.iter().find_map(
        |(&h, bp)| {
            if bp.target() == target { Some(h) } else { None }
        },
    ) {
        Some(h) => h,
        None => return MEM_ERR_NOT_FOUND,
    };
    let bp = registry.remove(&handle).expect("handle was just found");
    drop(registry);
    match bp.remove() {
        Ok(()) => MEM_OK,
        Err(ref e) => brk_err(e),
    }
}

/// Returns the number of currently active hardware breakpoints.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_brk_active_count() -> i32 {
    crate::memory::platform::breakpoint::active_count() as i32
}

/// Returns the maximum number of hardware breakpoints supported by this device.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_brk_max_breakpoints() -> i32 {
    crate::memory::platform::breakpoint::max_breakpoints()
}

// Shellcode API

/// Loads shellcode into a code cave and returns its address.
///
/// Parameters:
/// - `code`          : pointer to the raw machine code bytes (required, non-null)
/// - `code_len`      : number of bytes at `code` (must be > 0)
/// - `reloc_offsets` : parallel array of byte offsets for symbol relocations
/// - `reloc_symbols` : parallel array of null-terminated C strings naming the symbols
/// - `reloc_count`   : length of both relocation arrays (0 = no relocations)
/// - `near_address`  : hint for cave allocation; pass 0 for no preference
/// - `auto_free`     : ignored by this implementation — shellcode is always stored in the
///   registry so `mem_shellcode_free` controls the lifetime
/// - `address_out`   : receives the address of the loaded shellcode (required, non-null)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_shellcode_load(
    code: *const u8,
    code_len: usize,
    reloc_offsets: *const usize,
    reloc_symbols: *const *const c_char,
    reloc_count: usize,
    near_address: usize,
    _auto_free: i32,
    address_out: *mut usize,
) -> i32 {
    if code.is_null() {
        return MEM_ERR_NULL;
    }
    if code_len == 0 {
        return MEM_ERR_EMPTY;
    }
    if address_out.is_null() {
        return MEM_ERR_NULL;
    }

    let code_slice = unsafe { std::slice::from_raw_parts(code, code_len) };

    let mut builder = crate::memory::allocation::shellcode::ShellcodeBuilder::new(code_slice);

    if near_address != 0 {
        builder = builder.near_address(near_address);
    }

    if reloc_count > 0 {
        if reloc_offsets.is_null() || reloc_symbols.is_null() {
            return MEM_ERR_NULL;
        }
        let offsets = unsafe { std::slice::from_raw_parts(reloc_offsets, reloc_count) };
        let sym_ptrs = unsafe { std::slice::from_raw_parts(reloc_symbols, reloc_count) };
        for i in 0..reloc_count {
            let sym_name = unsafe {
                match cstr_to_str(sym_ptrs[i]) {
                    Ok(s) => s,
                    Err(e) => return e,
                }
            };
            builder = builder.with_symbol(offsets[i], sym_name);
        }
    }

    // Always manage the shellcode lifetime through the registry — disable
    // auto-free on the Rust side so Drop does not free the cave while the
    // value is still live in the registry.
    builder = builder.no_auto_free();

    let loaded = match builder.load() {
        Ok(l) => l,
        Err(ref e) => return loader_err(e),
    };

    let addr = loaded.address;
    unsafe { *address_out = addr };
    SHELLCODE_REGISTRY.lock().insert(addr, loaded);
    MEM_OK
}

/// Frees shellcode that was previously loaded with `mem_shellcode_load`.
/// Removes the entry from the registry (triggering `Drop` / `free_cave`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_shellcode_free(address: usize) -> i32 {
    match SHELLCODE_REGISTRY.lock().remove(&address) {
        Some(loaded) => {
            // Re-enable auto_free so that Drop actually calls free_cave.
            // We do this by calling `free()` explicitly which does the same thing
            // regardless of the auto_free flag.
            loaded.free();
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}
