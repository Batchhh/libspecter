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
pub const MEM_ERR_SCAN_PATTERN: i32 = -14;
pub const MEM_ERR_SCAN_ACCESS: i32 = -15;
pub const MEM_ERR_SCAN_REGION: i32 = -16;
pub const MEM_ERR_MACHO: i32 = -17;

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

fn scan_err(e: &crate::memory::info::scan::ScanError) -> i32 {
    use crate::memory::info::scan::ScanError;
    match e {
        ScanError::InvalidPattern(_) => MEM_ERR_SCAN_PATTERN,
        ScanError::NotFound => MEM_ERR_NOT_FOUND,
        ScanError::MemoryAccessViolation(_) => MEM_ERR_SCAN_ACCESS,
        ScanError::InvalidRegion => MEM_ERR_SCAN_REGION,
        ScanError::ImageNotFound(_) => MEM_ERR_NOT_FOUND,
    }
}

fn protection_err(e: &crate::memory::info::protection::ProtectionError) -> i32 {
    use crate::memory::info::protection::ProtectionError;
    match e {
        ProtectionError::QueryFailed(_) => MEM_ERR_NOT_FOUND,
        ProtectionError::InvalidAddress(_) => MEM_ERR_NULL,
        ProtectionError::ProtectionFailed(_) => MEM_ERR_PROTECT,
    }
}

fn macho_err(e: &crate::memory::info::macho::MachoError) -> i32 {
    use crate::memory::info::macho::MachoError;
    match e {
        MachoError::ImageNotFound(_) => MEM_ERR_NOT_FOUND,
        MachoError::SegmentNotFound(_) => MEM_ERR_MACHO,
        MachoError::SectionNotFound(_, _) => MEM_ERR_MACHO,
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

static BACKUP_REGISTRY: Lazy<
    Mutex<HashMap<u64, crate::memory::manipulation::backup::MemoryBackup>>,
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

// Scan API

/// Scans a memory range for an IDA-style pattern (e.g., "A1 ?? B2 EF").
/// Writes up to `cap` result addresses into `buf`. Writes total match count to `*count_out`.
/// Both `buf` and `count_out` are optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_pattern(
    start: usize,
    size: usize,
    ida_pattern: *const c_char,
    buf: *mut usize,
    cap: usize,
    count_out: *mut usize,
) -> i32 {
    let pattern = unsafe {
        match cstr_to_str(ida_pattern) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let results = match crate::memory::info::scan::scan_ida_pattern(start, size, pattern) {
        Ok(r) => r,
        Err(ref e) => return scan_err(e),
    };
    let total = results.len();
    if !count_out.is_null() {
        unsafe { *count_out = total };
    }
    if !buf.is_null() {
        let to_copy = total.min(cap);
        for (i, &addr) in results.iter().take(to_copy).enumerate() {
            unsafe { *buf.add(i) = addr };
        }
    }
    MEM_OK
}

/// Scans an entire loaded image for an IDA-style pattern.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_image(
    image_name: *const c_char,
    ida_pattern: *const c_char,
    buf: *mut usize,
    cap: usize,
    count_out: *mut usize,
) -> i32 {
    let name = unsafe {
        match cstr_to_str(image_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let pattern = unsafe {
        match cstr_to_str(ida_pattern) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let results = match crate::memory::info::scan::scan_image(name, pattern) {
        Ok(r) => r,
        Err(ref e) => return scan_err(e),
    };
    let total = results.len();
    if !count_out.is_null() {
        unsafe { *count_out = total };
    }
    if !buf.is_null() {
        let to_copy = total.min(cap);
        for (i, &addr) in results.iter().take(to_copy).enumerate() {
            unsafe { *buf.add(i) = addr };
        }
    }
    MEM_OK
}

/// Scans a memory range with raw bytes and a mask string ('x' = match, '?' = wildcard).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_raw(
    start: usize,
    size: usize,
    pattern: *const u8,
    mask: *const c_char,
    pattern_len: usize,
    buf: *mut usize,
    cap: usize,
    count_out: *mut usize,
) -> i32 {
    if pattern.is_null() || mask.is_null() {
        return MEM_ERR_NULL;
    }
    let pattern_slice = unsafe { std::slice::from_raw_parts(pattern, pattern_len) };
    let mask_str = unsafe {
        match cstr_to_str(mask) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let results =
        match crate::memory::info::scan::scan_pattern(start, size, pattern_slice, mask_str) {
            Ok(r) => r,
            Err(ref e) => return scan_err(e),
        };
    let total = results.len();
    if !count_out.is_null() {
        unsafe { *count_out = total };
    }
    if !buf.is_null() {
        let to_copy = total.min(cap);
        for (i, &addr) in results.iter().take(to_copy).enumerate() {
            unsafe { *buf.add(i) = addr };
        }
    }
    MEM_OK
}

/// Scans with caching — subsequent calls with the same parameters return cached results.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_cached(
    start: usize,
    size: usize,
    ida_pattern: *const c_char,
    buf: *mut usize,
    cap: usize,
    count_out: *mut usize,
) -> i32 {
    let pattern = unsafe {
        match cstr_to_str(ida_pattern) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let results = match crate::memory::info::scan::scan_pattern_cached(start, size, pattern) {
        Ok(r) => r,
        Err(ref e) => return scan_err(e),
    };
    let total = results.len();
    if !count_out.is_null() {
        unsafe { *count_out = total };
    }
    if !buf.is_null() {
        let to_copy = total.min(cap);
        for (i, &addr) in results.iter().take(to_copy).enumerate() {
            unsafe { *buf.add(i) = addr };
        }
    }
    MEM_OK
}

/// Clears the scan result cache.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_clear_cache() {
    crate::memory::info::scan::clear_cache();
}

/// Convenience: finds the first match for an IDA-style pattern in a memory range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_find_first(
    start: usize,
    size: usize,
    ida_pattern: *const c_char,
    result_out: *mut usize,
) -> i32 {
    if result_out.is_null() {
        return MEM_ERR_NULL;
    }
    let pattern = unsafe {
        match cstr_to_str(ida_pattern) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let results = match crate::memory::info::scan::scan_ida_pattern(start, size, pattern) {
        Ok(r) => r,
        Err(ref e) => return scan_err(e),
    };
    unsafe { *result_out = results[0] };
    MEM_OK
}

/// Convenience: finds the first match for an IDA-style pattern in an entire image.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_scan_image_first(
    image_name: *const c_char,
    ida_pattern: *const c_char,
    result_out: *mut usize,
) -> i32 {
    if result_out.is_null() {
        return MEM_ERR_NULL;
    }
    let name = unsafe {
        match cstr_to_str(image_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let pattern = unsafe {
        match cstr_to_str(ida_pattern) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let results = match crate::memory::info::scan::scan_image(name, pattern) {
        Ok(r) => r,
        Err(ref e) => return scan_err(e),
    };
    unsafe { *result_out = results[0] };
    MEM_OK
}

// Memory Protection API

/// Queries the raw VM_PROT_* flags for the page containing `addr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_get_protection(addr: usize, prot_out: *mut i32) -> i32 {
    if prot_out.is_null() {
        return MEM_ERR_NULL;
    }
    match crate::memory::info::protection::get_protection(addr) {
        Ok(p) => {
            unsafe { *prot_out = p.raw() };
            MEM_OK
        }
        Err(ref e) => protection_err(e),
    }
}

/// Queries full region info for the address. All out-parameters are optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_get_region_info(
    addr: usize,
    region_addr_out: *mut usize,
    region_size_out: *mut usize,
    prot_out: *mut i32,
) -> i32 {
    match crate::memory::info::protection::get_region_info(addr) {
        Ok(info) => {
            if !region_addr_out.is_null() {
                unsafe { *region_addr_out = info.address };
            }
            if !region_size_out.is_null() {
                unsafe { *region_size_out = info.size };
            }
            if !prot_out.is_null() {
                unsafe { *prot_out = info.protection.raw() };
            }
            MEM_OK
        }
        Err(ref e) => protection_err(e),
    }
}

/// Finds the memory region containing or following `addr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_find_region(
    addr: usize,
    region_addr_out: *mut usize,
    region_size_out: *mut usize,
    prot_out: *mut i32,
) -> i32 {
    match crate::memory::info::protection::find_region(addr) {
        Ok(info) => {
            if !region_addr_out.is_null() {
                unsafe { *region_addr_out = info.address };
            }
            if !region_size_out.is_null() {
                unsafe { *region_size_out = info.size };
            }
            if !prot_out.is_null() {
                unsafe { *prot_out = info.protection.raw() };
            }
            MEM_OK
        }
        Err(ref e) => protection_err(e),
    }
}

/// Returns 1 if the address is readable, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_is_readable(addr: usize) -> i32 {
    if crate::memory::info::protection::is_readable(addr) {
        1
    } else {
        0
    }
}

/// Returns 1 if the address is writable, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_is_writable(addr: usize) -> i32 {
    if crate::memory::info::protection::is_writable(addr) {
        1
    } else {
        0
    }
}

/// Returns 1 if the address is executable, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_is_executable(addr: usize) -> i32 {
    if crate::memory::info::protection::is_executable(addr) {
        1
    } else {
        0
    }
}

/// Changes the memory protection for a region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_protect(addr: usize, size: usize, protection: i32) -> i32 {
    match crate::memory::info::protection::protect(
        addr,
        size,
        crate::memory::info::protection::PageProtection::from_raw(protection),
    ) {
        Ok(()) => MEM_OK,
        Err(ref e) => protection_err(e),
    }
}

/// C-compatible region info for `mem_get_all_regions`.
#[repr(C)]
pub struct MemRegion {
    pub address: usize,
    pub size: usize,
    pub protection: i32,
}

/// Enumerates all readable memory regions. Writes up to `cap` entries into `buf`.
/// `count_out` receives the total number of regions (may exceed `cap`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_get_all_regions(
    buf: *mut MemRegion,
    cap: usize,
    count_out: *mut usize,
) -> i32 {
    if count_out.is_null() {
        return MEM_ERR_NULL;
    }
    match crate::memory::info::protection::get_all_regions() {
        Ok(regions) => {
            let total = regions.len();
            unsafe { *count_out = total };
            if !buf.is_null() {
                let to_copy = total.min(cap);
                for (i, r) in regions.iter().take(to_copy).enumerate() {
                    unsafe {
                        *buf.add(i) = MemRegion {
                            address: r.address,
                            size: r.size,
                            protection: r.protection.raw(),
                        }
                    };
                }
            }
            MEM_OK
        }
        Err(ref e) => protection_err(e),
    }
}

// Image Enumeration API

/// C-compatible image info for `mem_image_list`.
#[repr(C)]
pub struct MemImage {
    pub index: u32,
    pub base: usize,
}

/// Returns the number of currently loaded images.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_image_count(count_out: *mut usize) -> i32 {
    if count_out.is_null() {
        return MEM_ERR_NULL;
    }
    unsafe { *count_out = crate::memory::info::image::image_count() as usize };
    MEM_OK
}

/// Fills `buf` with up to `cap` image entries (index + base address).
/// `count_out` receives the total number of loaded images.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_image_list(
    buf: *mut MemImage,
    cap: usize,
    count_out: *mut usize,
) -> i32 {
    if count_out.is_null() {
        return MEM_ERR_NULL;
    }
    let images = crate::memory::info::image::get_all_images();
    let total = images.len();
    unsafe { *count_out = total };
    if !buf.is_null() {
        let to_copy = total.min(cap);
        for (i, img) in images.iter().take(to_copy).enumerate() {
            unsafe {
                *buf.add(i) = MemImage {
                    index: img.index,
                    base: img.base,
                }
            };
        }
    }
    MEM_OK
}

/// Gets the full path of a loaded image by its dyld index.
/// Writes a null-terminated string into `name_buf`.
/// Returns `MEM_ERR_RANGE` if the buffer is too small, `MEM_ERR_NOT_FOUND` if index is invalid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_image_name(
    index: u32,
    name_buf: *mut u8,
    name_buf_size: usize,
) -> i32 {
    if name_buf.is_null() {
        return MEM_ERR_NULL;
    }
    match crate::memory::info::image::get_image_name(index) {
        Some(name) => {
            let name_bytes = name.as_bytes();
            if name_bytes.len() + 1 > name_buf_size {
                return MEM_ERR_RANGE;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_buf, name_bytes.len());
                *name_buf.add(name_bytes.len()) = 0; // null terminator
            }
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

// Patch Info API

/// Returns the size (in bytes) of the patch applied at `address`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_size(address: usize, size_out: *mut usize) -> i32 {
    if size_out.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = PATCH_REGISTRY.lock();
    match registry.get(&address) {
        Some(p) => {
            unsafe { *size_out = p.size() };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Reads the original bytes that were backed up when the patch was applied.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_orig_bytes(
    address: usize,
    buf: *mut u8,
    buf_size: usize,
) -> i32 {
    if buf.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = PATCH_REGISTRY.lock();
    match registry.get(&address) {
        Some(p) => {
            let orig = p.original_bytes();
            let to_copy = orig.len().min(buf_size);
            unsafe { std::ptr::copy_nonoverlapping(orig.as_ptr(), buf, to_copy) };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Reads the bytes that were written as the patch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_patch_bytes(
    address: usize,
    buf: *mut u8,
    buf_size: usize,
) -> i32 {
    if buf.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = PATCH_REGISTRY.lock();
    match registry.get(&address) {
        Some(p) => {
            let pb = p.patch_bytes();
            let to_copy = pb.len().min(buf_size);
            unsafe { std::ptr::copy_nonoverlapping(pb.as_ptr(), buf, to_copy) };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Reads the current live bytes at the patch address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_curr_bytes(
    address: usize,
    buf: *mut u8,
    buf_size: usize,
) -> i32 {
    if buf.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = PATCH_REGISTRY.lock();
    match registry.get(&address) {
        Some(p) => {
            let curr = p.current_bytes();
            let to_copy = curr.len().min(buf_size);
            unsafe { std::ptr::copy_nonoverlapping(curr.as_ptr(), buf, to_copy) };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Fills `buf` with up to `cap` active patch addresses.
/// `count_out` receives the total number of active patches.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_list(buf: *mut usize, cap: usize, count_out: *mut usize) -> i32 {
    if count_out.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = PATCH_REGISTRY.lock();
    let total = registry.len();
    unsafe { *count_out = total };
    if !buf.is_null() {
        for (i, &addr) in registry.keys().take(cap).enumerate() {
            unsafe { *buf.add(i) = addr };
        }
    }
    MEM_OK
}

/// Returns the number of active patches.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_patch_count() -> usize {
    PATCH_REGISTRY.lock().len()
}

// Memory Backup API

/// Creates a backup of `size` bytes at `address`. Returns a handle for later operations.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_create(
    address: usize,
    size: usize,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() {
        return MEM_ERR_NULL;
    }
    if address == 0 {
        return MEM_ERR_NULL;
    }
    if size == 0 {
        return MEM_ERR_EMPTY;
    }
    match crate::memory::manipulation::backup::MemoryBackup::create(address, size) {
        Ok(backup) => {
            let handle = next_handle();
            BACKUP_REGISTRY.lock().insert(handle, backup);
            unsafe { *handle_out = handle };
            MEM_OK
        }
        Err(_) => MEM_ERR_GENERIC,
    }
}

/// Restores the original bytes from a backup.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_restore(handle: u64) -> i32 {
    let registry = BACKUP_REGISTRY.lock();
    match registry.get(&handle) {
        Some(backup) => match backup.restore() {
            Ok(()) => MEM_OK,
            Err(_) => MEM_ERR_PATCH,
        },
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Returns the size of the backup.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_size(handle: u64, size_out: *mut usize) -> i32 {
    if size_out.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = BACKUP_REGISTRY.lock();
    match registry.get(&handle) {
        Some(backup) => {
            unsafe { *size_out = backup.size() };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Returns the address that was backed up.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_address(handle: u64, address_out: *mut usize) -> i32 {
    if address_out.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = BACKUP_REGISTRY.lock();
    match registry.get(&handle) {
        Some(backup) => {
            unsafe { *address_out = backup.address() };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Reads the stored original bytes into `buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_orig_bytes(handle: u64, buf: *mut u8, buf_size: usize) -> i32 {
    if buf.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = BACKUP_REGISTRY.lock();
    match registry.get(&handle) {
        Some(backup) => {
            let orig = backup.original_bytes();
            let to_copy = orig.len().min(buf_size);
            unsafe { std::ptr::copy_nonoverlapping(orig.as_ptr(), buf, to_copy) };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Reads the current live bytes at the backed-up address into `buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_curr_bytes(handle: u64, buf: *mut u8, buf_size: usize) -> i32 {
    if buf.is_null() {
        return MEM_ERR_NULL;
    }
    let registry = BACKUP_REGISTRY.lock();
    match registry.get(&handle) {
        Some(backup) => {
            let curr = backup.current_bytes();
            let to_copy = curr.len().min(buf_size);
            unsafe { std::ptr::copy_nonoverlapping(curr.as_ptr(), buf, to_copy) };
            MEM_OK
        }
        None => MEM_ERR_NOT_FOUND,
    }
}

/// Destroys a backup (frees resources, does not restore).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_backup_destroy(handle: u64) -> i32 {
    match BACKUP_REGISTRY.lock().remove(&handle) {
        Some(_) => MEM_OK,
        None => MEM_ERR_NOT_FOUND,
    }
}

// Segment / Section API

/// C-compatible segment/section data.
#[repr(C)]
pub struct MemSegment {
    pub start: usize,
    pub end: usize,
    pub size: usize,
}

/// Gets a named segment from a loaded image (e.g., "__TEXT", "__DATA").
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_get_segment(
    image_name: *const c_char,
    segment_name: *const c_char,
    data_out: *mut MemSegment,
) -> i32 {
    if data_out.is_null() {
        return MEM_ERR_NULL;
    }
    let name = unsafe {
        match cstr_to_str(image_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let seg = unsafe {
        match cstr_to_str(segment_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    match crate::memory::info::macho::get_segment(name, seg) {
        Ok(data) => {
            unsafe {
                *data_out = MemSegment {
                    start: data.start,
                    end: data.end,
                    size: data.size,
                }
            };
            MEM_OK
        }
        Err(ref e) => macho_err(e),
    }
}

/// Gets a named section within a segment from a loaded image
/// (e.g., segment "__TEXT", section "__text").
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mem_get_section(
    image_name: *const c_char,
    segment_name: *const c_char,
    section_name: *const c_char,
    data_out: *mut MemSegment,
) -> i32 {
    if data_out.is_null() {
        return MEM_ERR_NULL;
    }
    let name = unsafe {
        match cstr_to_str(image_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let seg = unsafe {
        match cstr_to_str(segment_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    let sect = unsafe {
        match cstr_to_str(section_name) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    match crate::memory::info::macho::get_section(name, seg, sect) {
        Ok(data) => {
            unsafe {
                *data_out = MemSegment {
                    start: data.start,
                    end: data.end,
                    size: data.size,
                }
            };
            MEM_OK
        }
        Err(ref e) => macho_err(e),
    }
}
