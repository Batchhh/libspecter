/**
 * specter.h — C/C++ interface to the Rust specter library.
 *
 * Target: aarch64-apple-ios / aarch64-apple-macosx
 * Link with: libspecter.a  (-L<build-dir> -lspectre)
 *
 * All functions return MEM_OK (0) on success and a negative MEM_ERR_* code on
 * failure, unless their return type is void or an explicit value (count, bool).
 *
 * Pointer arguments marked // optional // may be NULL; all others must be
 * valid pointers. Passing NULL for a required pointer returns MEM_ERR_NULL.
 */
#ifndef SPECTRE_H
#define SPECTRE_H

#include <stddef.h>
#include <stdint.h>
#include <TargetConditionals.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define MEM_OK              0
#define MEM_ERR_GENERIC    -1   /* Catch-all / unexpected error        */
#define MEM_ERR_NULL       -2   /* Required pointer argument was NULL  */
#define MEM_ERR_NOT_FOUND  -3   /* Image / symbol / hook not found     */
#define MEM_ERR_EXISTS     -4   /* Hook already installed at address   */
#define MEM_ERR_ALLOC      -5   /* Memory allocation failed            */
#define MEM_ERR_PROTECT    -6   /* vm_protect / mach VM call failed    */
#define MEM_ERR_PATCH      -7   /* Stealth-write or verify failed      */
#define MEM_ERR_RELOC      -8   /* Instruction relocation failed       */
#define MEM_ERR_THREAD     -9   /* Thread suspend / resume failed      */
#define MEM_ERR_SYMBOL    -10   /* dlsym / symbol resolution failed    */
#define MEM_ERR_RANGE     -11   /* Branch target out of ±128 MB range  */
#define MEM_ERR_EMPTY     -12   /* Empty instruction / patch data      */
#define MEM_ERR_HW_LIMIT  -13   /* Hardware breakpoint limit exceeded  */

// Init API

/**
 * Initialize the library with the name of the target image.
 *
 * Must be called once before any RVA-based function (mem_hook_install,
 * mem_patch_apply, mem_read_*_rva, mem_write_*_rva, etc.).
 *
 * @param image_name  Name or substring of the target binary/dylib as it
 *                    appears in the dyld image list (e.g. "MyApp", "libfoo").
 * @param base_out    Optional. Receives the resolved load address of the
 *                    image (ASLR slide applied). Pass NULL if not needed.
 *
 * @return MEM_OK on success; MEM_ERR_NOT_FOUND if the image is not loaded;
 *         MEM_ERR_NULL if image_name is NULL.
 */
int32_t mem_init(const char *image_name,
                 uintptr_t  *base_out); /* optional */

// Hook API
/*
 * Hooks are identified by an opaque uint64_t handle returned on
 * install. Pass the handle back to mem_hook_remove() to uninstall.
 *
 * mem_hook_install_at / mem_hook_remove_at operate on absolute
 * addresses without a handle — useful for one-shot hooks where the
 * target address is already known.
 */

/** Install inline hook at image-relative RVA.
 *  @param trampoline_out  Receives address of the original-function
 *                         trampoline. May be NULL if not needed.
 *  @param handle_out      Required. Receives the removal handle. */
int32_t mem_hook_install(uintptr_t rva,
                         uintptr_t replacement,
                         uintptr_t *trampoline_out, /* optional */
                         uint64_t  *handle_out);

/** Install inline hook on a named symbol (resolved via dlsym). */
int32_t mem_hook_symbol(const char *symbol_name,
                        uintptr_t   replacement,
                        uintptr_t  *trampoline_out, /* optional */
                        uint64_t   *handle_out);

/** Install inline hook at an absolute address.
 *  Removal: mem_hook_remove_at(target). */
int32_t mem_hook_install_at(uintptr_t target,
                            uintptr_t replacement,
                            uintptr_t *trampoline_out); /* optional */

/** Code-cave variant — trampoline lives inside existing NOP padding. */
int32_t mem_hook_install_cave(uintptr_t rva,
                              uintptr_t replacement,
                              uintptr_t *trampoline_out, /* optional */
                              uint64_t  *handle_out);

int32_t mem_hook_install_cave_at(uintptr_t target,
                                 uintptr_t replacement,
                                 uintptr_t *trampoline_out, /* optional */
                                 uint64_t  *handle_out);

/** Remove a hook using the handle from mem_hook_install / _symbol / _cave. */
int32_t mem_hook_remove(uint64_t handle);

/** Remove a hook by its absolute target address (for mem_hook_install_at). */
int32_t mem_hook_remove_at(uintptr_t target);

/** Number of currently active inline hooks. */
size_t  mem_hook_count(void);

/** Returns 1 if a hook is installed at target, 0 otherwise. */
int32_t mem_hook_is_hooked(uintptr_t target);

/** Fill buf with up to cap hook target addresses.
 *  Writes actual count to *count_out (may exceed cap if buf is small). */
int32_t mem_hook_list(uintptr_t *buf, size_t cap, size_t *count_out);

/* 
 * Patch API
 *
 * Patches are identified by the absolute address where they were
 * applied. Pass that address to mem_patch_revert() to restore
 * original bytes.
  */

/** Apply a hex-encoded patch at an image-relative RVA.
 *  hex_str format: "1F2003D5 C0035FD6" (spaces ignored). */
int32_t mem_patch_apply(uintptr_t    rva,
                        const char  *hex_str,
                        uintptr_t   *address_out); /* optional */

/** Apply raw bytes at an absolute address. */
int32_t mem_patch_apply_at(uintptr_t       address,
                           const uint8_t  *data,
                           size_t          len,
                           uintptr_t      *address_out); /* optional */

/** Apply hex patch via a code cave (branch + payload in NOP padding). */
int32_t mem_patch_apply_cave(uintptr_t    rva,
                             const char  *hex_str,
                             uintptr_t   *address_out); /* optional */

/** Restore original bytes saved when the patch was applied. */
int32_t mem_patch_revert(uintptr_t address);

/*
 * Read / Write API
 *
 * C callers pass sizeof(T) explicitly:
 *   uint32_t v; mem_read(addr, &v, sizeof v);
 *
 * C++ callers can use the typed template wrappers below the extern "C" block:
 *   uint32_t v; mem_read(addr, &v);   // size deduced automatically
 */

/** Read size bytes from address into out. */
int32_t mem_read    (uintptr_t address, void       *out,  size_t size);
/** Read size bytes from rva (image-relative) into out. */
int32_t mem_read_rva(uintptr_t rva,     void       *out,  size_t size);

/** Follow a pointer chain: start at base, dereference + add each offset.
 *  result_out receives the final address. */
int32_t mem_read_pointer_chain(uintptr_t        base,
                               const uintptr_t *offsets,
                               size_t           offset_count,
                               uintptr_t       *result_out);

/** Write size bytes from value to address (data memory, direct write). */
int32_t mem_write    (uintptr_t address, const void *value, size_t size);
/** Write size bytes from value to rva (image-relative). */
int32_t mem_write_rva(uintptr_t rva,     const void *value, size_t size);

/** Write raw bytes via stealth path (mach_vm_remap + icache flush).
 *  Use this when patching executable code pages. */
int32_t mem_write_bytes(uintptr_t address, const uint8_t *data, size_t len);

/* 
 * Image / Symbol API
 *  */

/** Get the load address (ASLR slide applied) of a loaded dylib/image.
 *  image_name may be a substring of the full path. */
int32_t mem_get_image_base(const char *image_name, uintptr_t *base_out);

/** Resolve a symbol address via dlsym(RTLD_DEFAULT, ...). */
int32_t mem_resolve_symbol(const char *symbol_name, uintptr_t *address_out);

/** Manually insert a symbol → address mapping into the cache. */
void    mem_cache_symbol(const char *symbol_name, uintptr_t address);

/** Evict all entries from the symbol cache. */
void    mem_clear_symbol_cache(void);

/*
 * Hardware Breakpoint API  (max 6 concurrent on ARM64, iOS only)
 *
 * Breakpoints redirect execution via Mach exception handling —
 * no code is modified at the target address.
 *  */
#if TARGET_OS_IOS

/** Install hardware breakpoint hook at image-relative RVA. */
int32_t mem_brk_install(uintptr_t rva,
                        uintptr_t replacement,
                        uint64_t *handle_out);

/** Install hardware breakpoint hook at absolute address. */
int32_t mem_brk_install_at(uintptr_t target,
                           uintptr_t replacement,
                           uint64_t *handle_out);

/** Remove breakpoint by handle. */
int32_t mem_brk_remove(uint64_t handle);

/** Remove breakpoint by target address. */
int32_t mem_brk_remove_at(uintptr_t target);

/** Number of currently active hardware breakpoints. */
int32_t mem_brk_active_count(void);

/** Maximum hardware breakpoints supported on this device (typically 6). */
int32_t mem_brk_max_breakpoints(void);

#endif /* TARGET_OS_IOS */

/* 
 * Shellcode API
 *  */

/**
 * Load raw machine-code bytes into executable memory and apply
 * symbol relocations.
 *
 * @param code            Pointer to the shellcode bytes.
 * @param code_len        Size of the shellcode in bytes.
 * @param reloc_offsets   Array of byte offsets within the shellcode
 *                        where 64-bit symbol addresses will be written.
 *                        May be NULL when reloc_count == 0.
 * @param reloc_symbols   Parallel array of null-terminated symbol names
 *                        to resolve via dlsym.
 *                        May be NULL when reloc_count == 0.
 * @param reloc_count     Number of entries in reloc_offsets/reloc_symbols.
 * @param near_address    If non-zero, allocate the code cave within
 *                        ±128 MB of this address (required for B/BL targets).
 * @param auto_free       Reserved for future use; pass 0.
 * @param address_out     Receives the address of the loaded shellcode.
 */
int32_t mem_shellcode_load(const uint8_t  *code,
                           size_t          code_len,
                           const size_t   *reloc_offsets,   /* optional */
                           const char    **reloc_symbols,   /* optional */
                           size_t          reloc_count,
                           uintptr_t       near_address,
                           int32_t         auto_free,
                           uintptr_t      *address_out);

/** Free shellcode previously loaded with mem_shellcode_load. */
int32_t mem_shellcode_free(uintptr_t address);

#ifdef __cplusplus
} /* extern "C" */

template <typename T>
inline int32_t mem_read(uintptr_t address, T *out) {
    return mem_read(address, static_cast<void *>(out), sizeof(T));
}
template <typename T>
inline int32_t mem_read_rva(uintptr_t rva, T *out) {
    return mem_read_rva(rva, static_cast<void *>(out), sizeof(T));
}
template <typename T>
inline int32_t mem_write(uintptr_t address, const T &value) {
    return mem_write(address, static_cast<const void *>(&value), sizeof(T));
}
template <typename T>
inline int32_t mem_write_rva(uintptr_t rva, const T &value) {
    return mem_write_rva(rva, static_cast<const void *>(&value), sizeof(T));
}

#endif /* __cplusplus */

#endif /* SPECTRE_H */
