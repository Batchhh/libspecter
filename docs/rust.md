# Rust API

Specter can be used directly as a Rust crate without going through the C FFI layer.

```toml
[dependencies]
specter-mem = "1.0"
```

> **Platform note:** The crate builds for both iOS (`aarch64-apple-ios`) and macOS (`aarch64-apple-darwin`). Use `make ios` or `make macos` to build a single target.
>
> **Note:** The crate type is `staticlib` by default. To use it as a Rust dependency you may need to add `"lib"` to `crate-type` in the downstream `Cargo.toml`, or consume the modules directly in-tree.

## Initialization

Before using RVA-based APIs, set the target image name:

```rust
use specter::config;

config::set_target_image_name("MyApp");
```

## Inline Hooking

### Hook by RVA

```rust
use specter::memory::manipulation::hook;

unsafe {
    let h = hook::install(0x1234, replacement_fn as usize)?;

    // Call the original function through the trampoline
    let result: i32 = h.call_original(|orig: extern "C" fn(i32) -> i32| orig(42));

    // Check integrity
    assert!(h.verify_integrity());

    // Remove the hook (restores original bytes)
    h.remove();
}
```

### Hook by Symbol

```rust
use specter::memory::manipulation::hook;

unsafe {
    let h = hook::hook_symbol("_objc_msgSend", replacement_fn as usize)?;
    // use h.call_original(...) to invoke the original
}
```

### Hook at Absolute Address

```rust
use specter::memory::manipulation::hook;

unsafe {
    let trampoline = hook::install_at_address(0x100004000, replacement_fn as usize)?;
}
```

### Stealth Hook (Code Cave)

Installs the trampoline in a NOP code cave instead of a new allocation, making it harder to detect:

```rust
use specter::memory::manipulation::hook;

unsafe {
    let h = hook::install_in_cave(0x1234, replacement_fn as usize)?;
}
```

### Hook Utilities

```rust
use specter::memory::manipulation::hook;

let count = hook::hook_count();
let targets = hook::list_hooks();
let active = hook::is_hooked(0x100004000);
```

## Memory Patching

### Hex Patch at RVA

```rust
use specter::memory::manipulation::patch;

let p = patch::apply(0x1234, "1F 20 03 D5")?; // NOP

// Revert to original bytes
p.revert();
```

### Assembly Patch at RVA

Uses the `jit-assembler` crate to build ARM64 instructions inline:

```rust
use specter::memory::manipulation::patch;

let p = patch::apply_asm(0x1234, |asm| {
    asm.nop().ret()
})?;
```

### Code-Cave Patches

Write patch payload into a nearby code cave and branch to it:

```rust
use specter::memory::manipulation::patch;

// Hex in cave
let p = patch::apply_in_cave(0x1234, "1F 20 03 D5 C0 03 5F D6")?;

// Assembly in cave
let p = patch::apply_asm_in_cave(0x1234, |asm| {
    asm.nop().ret()
})?;
```

### Patch at Absolute Address

```rust
use specter::memory::manipulation::patch;

let p = patch::apply_at_address(0x100004000, &[0x1F, 0x20, 0x03, 0xD5])?;
```

## Memory Read / Write

### Typed Read/Write

```rust
use specter::memory::manipulation::rw;

unsafe {
    let value: u32 = rw::read::<u32>(0x100004000)?;
    rw::write::<u32>(0x100004000, 0xDEADBEEF)?;
}
```

### RVA-based Read/Write

```rust
use specter::memory::manipulation::rw;

unsafe {
    let value: u64 = rw::read_at_rva::<u64>(0x1234)?;
    rw::write_at_rva::<u32>(0x1234, 0)?;
}
```

### Pointer Chain

```rust
use specter::memory::manipulation::rw;

unsafe {
    // Follows: *(*(base + 0x10) + 0x20) + 0x30
    let addr = rw::read_pointer_chain(base, &[0x10, 0x20, 0x30])?;
}
```

### Write to Code Memory

Writes through `mach_vm_remap` (stealth) and invalidates the instruction cache:

```rust
use specter::memory::manipulation::rw;

unsafe {
    rw::write_code::<u32>(0x100004000, 0xD503201F)?; // NOP
    rw::write_bytes(0x100004000, &[0x1F, 0x20, 0x03, 0xD5])?;
}
```

## Symbol Resolution

```rust
use specter::memory::info::symbol;

let addr = symbol::resolve_symbol("_objc_msgSend")?;

// Manually cache a known address
symbol::cache_symbol("_my_func", 0x100004000);

// Clear the cache
symbol::clear_cache();
```

## Image Lookup

```rust
use specter::memory::info::image;

let base = image::get_image_base("MyApp")?;
```

## Pattern Scanning

### IDA-Style Pattern Scan

```rust
use specter::memory::info::scan;

// Scan a range
let results = scan::scan_ida_pattern(start, size, "DE AD ?? EF")?;

// Scan an entire image
let results = scan::scan_image("MyApp", "48 8B ?? ?? 48 89")?;

// Cached scan (subsequent calls return cached results)
let results = scan::scan_pattern_cached(start, size, "DE AD ?? EF")?;
```

### Raw Pattern Scan

```rust
use specter::memory::info::scan;

let pattern = vec![0xDE, 0xAD, 0x00, 0xEF];
let mask = "xx?x";
let results = scan::scan_pattern(start, size, &pattern, mask)?;
```

## Hardware Breakpoints

Limited to 6 concurrent breakpoints. Does not modify code — uses ARM64 debug registers and Mach exception handling.

### Install / Remove

```rust
use specter::memory::platform::breakpoint;

unsafe {
    let bp = breakpoint::install(0x1234, replacement_fn as usize)?;

    // Call the original by temporarily disabling the breakpoint
    let result: i32 = bp.call_original(|orig: extern "C" fn(i32) -> i32| orig(42));

    bp.remove()?;
}
```

### Breakpoint Info

```rust
use specter::memory::platform::breakpoint;

let active = breakpoint::active_count();
let max = breakpoint::max_breakpoints(); // typically 6
```

## Shellcode Loading

### Simple Load

```rust
use specter::memory::allocation::shellcode;

let code: &[u8] = &[0xC0, 0x03, 0x5F, 0xD6]; // RET
let loaded = shellcode::load(code)?;

unsafe {
    let result = loaded.execute();
}
// Memory is freed on drop
```

### Builder with Symbol Relocations

```rust
use specter::memory::allocation::shellcode::ShellcodeBuilder;

let loaded = ShellcodeBuilder::new(&raw_bytes)
    .with_symbol(0x20, "_printf")        // resolve and write _printf address at offset 0x20
    .with_symbol(0x28, "_objc_msgSend")  // same for _objc_msgSend at offset 0x28
    .near_address(0x100004000)           // allocate near this address
    .no_auto_free()                      // persist after drop
    .load()?;

unsafe {
    // Execute with a custom signature
    loaded.execute_as(|f: extern "C" fn(i32, i32) -> i32| f(1, 2));

    // Or get a raw function pointer
    let f: extern "C" fn() -> usize = loaded.as_function();
}

// Manual cleanup (since auto_free is off)
loaded.free();
```

### Load from ARM64 Instructions

```rust
use specter::memory::allocation::shellcode::ShellcodeBuilder;

let instructions: &[u32] = &[
    0xD2800000, // MOV X0, #0
    0xD65F03C0, // RET
];

let loaded = ShellcodeBuilder::from_instructions(instructions).load()?;
```
