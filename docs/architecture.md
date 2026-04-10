# Architecture

Internal design documentation for contributors and advanced users.

---

## Platforms

Specter builds for both **iOS** (`aarch64-apple-ios`) and **macOS** (`aarch64-apple-darwin`). Both targets share the same codebase — all APIs use Mach kernel and dyld primitives available on both platforms. `make` builds both; `make ios` or `make macos` for a single target.

---

## Layer Model

```mermaid
graph LR
    CC[C/C++ consumer — specter.h]
    RC[Rust caller — direct]
    FFI[src/ffi.rs — stable C ABI · error mapping · 5 registries]
    Mods[src/memory/ — manipulation · info · platform · allocation]
    Kern[Mach kernel · dyld · POSIX]

    CC --> FFI
    FFI --> Mods
    RC -.->|bypasses FFI| Mods
    Mods --> Kern
```

### Two consumption modes

1. **C/C++ via FFI** — link `libspecter.a`, include `specter.h`. The FFI layer (`src/ffi.rs`) manages handle registries and maps Rust errors to `MEM_ERR_*` codes.
2. **Rust direct** — use `specter::memory::*` modules directly. No FFI overhead, full access to Rust types (`Hook`, `Patch`, `Breakpoint`, `LoadedShellcode`).

---

## Initialization (`src/config.rs`)

```mermaid
sequenceDiagram
    participant C as Caller
    participant FFI as ffi.rs
    participant Cfg as config.rs
    participant Img as image.rs
    participant dyld

    C->>FFI: mem_init("MyApp", &base_out)
    FFI->>Cfg: set_target_image_name("MyApp")
    FFI->>Img: get_image_base("MyApp")
    Img->>dyld: _dyld_image_count / _dyld_get_image_name
    dyld-->>Img: iterate image list
    Img-->>Img: cache in RwLock HashMap
    Img-->>FFI: Ok(base_address)
    FFI-->>C: MEM_OK, base_out = base_address

    Note over FFI,Img: All subsequent RVA calls resolve absolute = base + rva
```

The target image name is stored in a `RwLock<Option<String>>` in `config.rs`. The image cache in `image.rs` uses a `RwLock<HashMap>` for thread-safe lookups.

---

## Inline Hook Engine (`src/memory/manipulation/hook.rs`)

### Standard hook — full flow

```mermaid
flowchart TD
    Start([install / install_at_address])
    CheckExists{Hook exists at target?}
    ErrExists([HookError::AlreadyExists])
    ReadFirst[Read first instruction at target]
    IsThunk{First instr is a B thunk?}
    AllocNear[alloc_trampoline_near — mmap within ±128 MB]
    AllocAny[alloc_trampoline — mmap anywhere]
    Suspend[Suspend all other threads]
    Relocate[Relocate 4 instructions to trampoline]
    RelocOK{All 4 instrs relocated?}
    ErrReloc([RelocationFailed — free + resume])
    AppendReturn[Append obfuscated branch back to target+16]
    Protect[mprotect trampoline RX]
    FlushCache[Flush caches — dc cvau, dsb ish, ic ivau, dsb ish, isb]
    WriteHook[Write 16-byte polymorphic branch via stealth_write]
    WriteOK{Write succeeded?}
    ErrPatch([PatchFailed — free + resume])
    RegisterCRC[Register FNV-1a checksum for tamper detection]
    Resume[Resume all threads]
    Done([return Hook with target + trampoline])

    Start --> CheckExists
    CheckExists -->|yes| ErrExists
    CheckExists -->|no| ReadFirst
    ReadFirst --> IsThunk
    IsThunk -->|yes| AllocNear
    IsThunk -->|no| AllocAny
    AllocNear --> Suspend
    AllocAny --> Suspend
    Suspend --> Relocate
    Relocate --> RelocOK
    RelocOK -->|no| ErrReloc
    RelocOK -->|yes| AppendReturn
    AppendReturn --> Protect
    Protect --> FlushCache
    FlushCache --> WriteHook
    WriteHook --> WriteOK
    WriteOK -->|no| ErrPatch
    WriteOK -->|yes| RegisterCRC
    RegisterCRC --> Resume
    Resume --> Done
```

### Instruction relocation

The trampoline must contain the 4 original instructions relocated to a new address. PC-relative instructions need fixup:

```mermaid
flowchart TD
    Instr[ARM64 instruction at PC]

    IsADR{ADR / ADRP?}
    EmitADR[LDR Xd, #8 + B +12 + .quad abs_target — 16 bytes]

    IsLDRLit{LDR literal W/X/SW?}
    EmitLDR[LDR X17 + LDR Xd from X17 + B +12 + .quad — 20 bytes]

    IsBL{BL?}
    EmitBL[ADR X30, #16 + absolute BR — 20 bytes]

    IsB{B?}
    EmitB[Absolute BR to resolved target — 16 bytes]

    IsCond{B.cond / CBZ / CBNZ / TBZ / TBNZ?}
    EmitCond[Invert cond + LDR X2 + BR X2 — 20 bytes]

    Default[Copy verbatim — 4 bytes]

    Instr --> IsADR
    IsADR -->|yes| EmitADR
    IsADR -->|no| IsLDRLit
    IsLDRLit -->|yes| EmitLDR
    IsLDRLit -->|no| IsBL
    IsBL -->|yes| EmitBL
    IsBL -->|no| IsB
    IsB -->|yes| EmitB
    IsB -->|no| IsCond
    IsCond -->|yes| EmitCond
    IsCond -->|no| Default
```

### Polymorphic branch encoding

Each hook redirect is randomly varied on every install using `arc4random()` — two hooks to the same address will produce different bytes.

```mermaid
flowchart LR
    arc4random -->|bit 16 == 0| VariantA
    arc4random -->|bit 16 == 1| VariantB
    arc4random -->|reg = rand mod 9| Reg[scratch reg x9–x17]

    VariantA[Variant A: LDR Xn, #8 / BR Xn / .quad dest — 16 bytes]
    VariantB[Variant B: MOVZ + MOVK x3 + BR Xn — 16 bytes]

    Reg --> VariantA
    Reg --> VariantB
```

Obfuscated branches (used in trampolines) prepend a random junk sled (1–4 NOP/self-move instructions) and optionally an opaque predicate before the actual branch.

### Code-cave hook

```mermaid
flowchart TD
    Start([install_in_cave])
    ScanNOP[Scan __TEXT for NOP run >= 256 bytes within ±128 MB]
    Found{Cave found?}
    ErrAlloc([HookError::AllocationFailed])
    Suspend[Suspend all threads]
    Relocate[Relocate 4 instrs into temp buffer]
    CaveWrite[stealth_write relocated instrs + return branch into cave]
    TargetWrite[stealth_write 16-byte branch at target]
    Resume[Resume threads]
    Done([return Hook — trampoline = cave addr])

    Start --> ScanNOP
    ScanNOP --> Found
    Found -->|no| ErrAlloc
    Found -->|yes| Suspend
    Suspend --> Relocate
    Relocate --> CaveWrite
    CaveWrite --> TargetWrite
    TargetWrite --> Resume
    Resume --> Done
```

> The trampoline lives **inside the image's own `__TEXT` segment**, invisible to scanners that look for anonymous `mmap` pages.

---

## Integrity Monitor (`src/memory/manipulation/checksum.rs`)

A background thread periodically verifies that installed hooks haven't been tampered with.

```mermaid
flowchart TD
    Install[Hook installed] --> Register[Register FNV-1a hash of hook bytes]
    Register --> FirstHook{First hook registered?}
    FirstHook -->|yes| StartMonitor[Start background thread — 5s interval]
    FirstHook -->|no| Done[Done]
    StartMonitor --> Loop[Sleep then verify_all]
    Loop --> Tampered{Any hooks tampered?}
    Tampered -->|no| Loop
    Tampered -->|yes| Callback[restore_hook_bytes + update checksum]
    Callback --> Loop
```

The monitor uses FNV-1a hashing (fast, non-cryptographic) to compare current bytes against the expected state. On tamper detection, it automatically re-writes the hook redirect bytes via `restore_hook_bytes`.

---

## Stealth Patching (`src/memory/manipulation/patch.rs`)

The standard `vm_protect(RW) → write → vm_protect(RX)` sequence is observable by security frameworks. Specter avoids it.

### mach_vm_remap write path

```mermaid
flowchart TD
    S1([stealth_write addr + bytes])
    S2[mach_vm_remap — alias VA created, both VAs share the same physical frames]
    S3[mach_vm_protect alias RW — __TEXT stays RX, no observable change]
    S4[memcpy through alias — write instantly visible in __TEXT via shared frames]
    S5[mach_vm_deallocate — alias VA gone, __TEXT unaffected]
    S6[icache flush — dc cvau · dsb ish · ic ivau · dsb ish · isb]
    S7([return Ok])

    S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7
```

### Patch lifecycle

```mermaid
flowchart TD
    ApplyFn(["patch::apply(rva, hex_str)"])
    ParseHex[Parse hex string — strip whitespace, hex decode]
    ResolveBase[Resolve image base — address = base + rva]
    Suspend[Suspend all threads]
    SaveOrig[Read and save original bytes]
    StealthWrite[stealth_write via mach_vm_remap alias]
    Verify{Re-read bytes match expected?}
    ErrVerify(["VerificationFailed + resume"])
    Resume[Resume threads]
    Done(["return Patch with address + original_bytes"])

    Revert(["patch.revert"])
    SuspendR[Suspend all threads]
    RestoreOrig[stealth_write original bytes]
    FreeCave[Free code cave if any]
    ResumeR[Resume threads]

    ApplyFn --> ParseHex --> ResolveBase --> Suspend --> SaveOrig
    SaveOrig --> StealthWrite --> Verify
    Verify -->|no| ErrVerify
    Verify -->|yes| Resume --> Done

    Revert --> SuspendR --> RestoreOrig --> FreeCave --> ResumeR
```

### Assembly patches

`patch::apply_asm` and `patch::apply_asm_in_cave` accept a closure that builds ARM64 instructions using the `jit-assembler` crate:

```
patch::apply_asm(rva, |asm| asm.nop().ret())
```

The builder generates `Vec<u32>` instructions which are serialized to bytes and written through the same stealth path.

### Fallback path

```mermaid
flowchart LR
    Try[mach_vm_remap]
    OK{KERN_SUCCESS and max_prot has W?}
    Remap[Write via alias — stealthy]
    Fallback[fallback_write: vm_protect RW+COPY, memcpy, restore RX, icache flush]

    Try --> OK
    OK -->|yes| Remap
    OK -->|no| Fallback
```

---

## Hardware Breakpoints (`src/memory/platform/breakpoint.rs`)

```mermaid
flowchart TD
    subgraph arch[Exception routing topology]
        direction LR
        cpu[ARM64 CPU — debug registers]
        mach[Mach kernel]
        eport[(exception port)]
        eht[exception_handler_thread]
        cpu -- EXC_BREAKPOINT --> mach
        mach -- mach_msg --> eport
        eport -- deliver --> eht
        eht -- reply new PC --> mach
        mach -- resume --> cpu
    end

    S1([first breakpoint_install call])
    S2[task_get_exception_ports — save existing handler]
    S3[mach_port_allocate + task_set_exception_ports EXC_MASK_BREAKPOINT]
    S4[pthread_create — start exception_handler_thread]
    S5[task_set_state + thread_set_state ARM_DEBUG_STATE64]
    S6([breakpoint armed])

    R1([execution reaches target address])
    R2[CPU raises EXC_BREAKPOINT — Mach routes to exception port]
    R3[find_hook PC returns replacement address]
    R4[mach_msg reply with new_state.PC = replacement]
    R5([CPU resumes at replacement])

    S1 --> S2 --> S3 --> S4 --> S5 --> S6
    R1 --> R2 --> R3 --> R4 --> R5

    S3 -.->|registers| eport
    S4 -.->|listens on| eport
    S5 -.->|arms| cpu
    R2 -.->|routed via| eport
    R3 -.->|handled by| eht
```

### Slot management

```mermaid
flowchart LR
    sysctl[sysctlbyname hw.optional.breakpoint] --> hw_count[hw_breakpoints — typically 6]
    install[breakpoint::install_at_address] --> check{active_count >= hw_count?}
    check -->|yes| err([ExceedsHwBreakpoints])
    check -->|no| slot[add_hook to slot array — max 16 entries, 6 armed]
    slot --> dbg[apply_debug_state on task + all threads]
```

### Calling the original

`Breakpoint::call_original` temporarily clears debug registers on the current thread (`suspend_self`), calls the original function, then re-arms them (`resume_self`). This avoids infinite recursion.

---

## Code Cave Finder (`src/memory/info/code_cave.rs`)

Scans the target image for reusable NOP regions and zero-byte alignment padding.

```mermaid
flowchart TD
    Request["allocate_cave_near(target, size)"]
    GetImage[get_target_image_name]
    Scan["find_caves_in_image — scan 32 MB from base"]

    subgraph ScanTypes[Two scan types]
        NOP["find_nop_sequences — runs of 0x1F2003D5"]
        Padding["find_alignment_padding — runs of 0x00 bytes"]
    end

    Scan --> NOP & Padding
    NOP & Padding --> Merge[Merge and sort by address]
    Merge --> Filter{Within ±128 MB and size >= requested?}
    Filter -->|yes| Register[Mark allocated in CaveRegistry]
    Filter -->|no| Next[Try next cave]
    Next --> Filter
    Register --> Done(["return CodeCave"])
```

The `CaveRegistry` (`Mutex<HashMap<usize, CodeCave>>`) tracks allocated caves to prevent double allocation. Caves are freed when hooks/patches are reverted.

---

## Memory Read / Write (`src/memory/manipulation/rw.rs`)

```mermaid
flowchart TD
    subgraph DataPages[Data pages — readable / writable]
        MemRead[read T — ptr::read]
        MemWrite[write T — ptr::write]
        MemReadRVA[read_at_rva T — addr = base + rva]
        MemWriteRVA[write_at_rva T — addr = base + rva]
    end

    subgraph CodePages[Code pages — executable]
        WriteCode[write_code T — stealth_write + icache flush]
        WriteBytes[write_bytes — suspend, stealth_write, icache flush, resume]
    end

    subgraph Chain[Pointer chain]
        MemChain[read_pointer_chain — deref each offset, add last]
    end
```

### Pointer chain traversal

```mermaid
flowchart LR
    base[base 0x100200000]
    deref1[deref base + 0x10 = ptr_A]
    deref2[deref ptr_A + 0x28 = ptr_B]
    final[ptr_B + 0x08 = result]

    base -->|+0x10 deref| deref1
    deref1 -->|+0x28 deref| deref2
    deref2 -->|+0x08 last, no deref| final
```

---

## Pattern Scanning (`src/memory/info/scan.rs`)

```mermaid
flowchart TD
    IDA[scan_ida_pattern]
    Parse[parse_ida_pattern — bytes + mask]
    ScanFn[scan_pattern]
    Check[is_readable_memory]
    Loop[Linear scan — compare byte-by-byte, skip wildcards]
    Results[Vec of match addresses]

    ImageScan[scan_image]
    GetSections[get_image_sections via mach_vm_region]
    ScanEach[scan_pattern per section]

    CachedScan[scan_pattern_cached]
    CacheCheck{In SCAN_CACHE?}
    Hit[Return cached results]
    Miss[scan then store in cache]

    IDA --> Parse --> ScanFn --> Check --> Loop --> Results
    ImageScan --> GetSections --> ScanEach --> Results
    CachedScan --> CacheCheck
    CacheCheck -->|yes| Hit
    CacheCheck -->|no| Miss
```

---

## Symbol Resolution (`src/memory/info/symbol.rs`)

```mermaid
flowchart LR
    Call[resolve_symbol]
    Cache{In DashMap cache?}
    Hit[return cached address]
    dlsym[dlsym RTLD_DEFAULT]
    Found{non-NULL?}
    Store[store in cache, return address]
    Err([SymbolError::NotFound])

    Call --> Cache
    Cache -->|yes| Hit
    Cache -->|no| dlsym
    dlsym --> Found
    Found -->|yes| Store
    Found -->|no| Err
```

---

## Shellcode Loader (`src/memory/allocation/shellcode.rs`)

```mermaid
flowchart TD
    Builder["ShellcodeBuilder::new(bytes)"]
    Config["Configure: .with_symbol, .near_address, .no_auto_free"]
    Load[builder.load]

    Alloc{near_address set?}
    AllocNear[allocate_cave_near]
    AllocAny[allocate_cave]

    Align[4-byte align cave address]
    Relocate["Resolve symbols via dlsym, write 64-bit addrs at offsets"]
    Write["rw::write_bytes via stealth_write"]
    Verify[Byte-by-byte verify]
    CheckExec[protection::is_executable]
    Flush[invalidate_icache]
    Done(["LoadedShellcode — address + size"])

    Builder --> Config --> Load --> Alloc
    Alloc -->|yes| AllocNear
    Alloc -->|no| AllocAny
    AllocNear --> Align
    AllocAny --> Align
    Align --> Relocate --> Write --> Verify --> CheckExec --> Flush --> Done
```

`LoadedShellcode` supports:
- `execute()` — call as `extern "C" fn() -> usize`
- `execute_as(|f| f(...))` — call with custom signature
- `as_function::<F>()` — get a raw function pointer
- Auto-cleanup on drop (unless `.no_auto_free()` was used)

---

## Thread Safety (`src/memory/platform/thread.rs`)

All hook and patch operations bracket the write inside a Mach thread-suspension window:

```mermaid
flowchart LR
    S[suspend_other_threads]
    W[stealth_write + icache flush]
    R[resume_threads]

    S --> W --> R
```

---

## Concurrency Model

```mermaid
flowchart TD
    subgraph FFI[FFI registries — Mutex]
        HR[HOOK_REGISTRY]
        PR[PATCH_REGISTRY]
        BR[BRK_REGISTRY]
        SR[SHELLCODE_REGISTRY]
        BKR[BACKUP_REGISTRY]
    end

    subgraph Internal[Internal registries — Mutex]
        HookReg[hook::REGISTRY]
        CaveReg[code_cave::REGISTRY]
        CRCReg[checksum::CHECKSUMS]
        ScanCache[scan::SCAN_CACHE]
    end

    subgraph LockFree[Lock-free — DashMap]
        SC[symbol::CACHE]
    end

    subgraph RWL[RwLock]
        IC[image::IMAGE_CACHE]
        TC[config::TARGET_IMAGE_NAME]
    end

    subgraph PatchWindow[Thread-safe patch window]
        direction LR
        Susp[Suspend other threads] --> Write[stealth_write + icache flush] --> Res[Resume threads]
    end

    HookReg & CaveReg --> PatchWindow
```

> All hook and patch operations bracket the write inside a Mach thread-suspension window. This eliminates races where another thread could execute partially-written hook bytes.

### Lock hierarchy

To prevent deadlocks, locks are always acquired in this order when multiple are needed:
1. Thread suspension (outermost)
2. FFI registries
3. Internal registries (hook, cave, checksum)
4. Caches (symbol, image, scan)

---

## Memory Protection (`src/memory/info/protection.rs`)

Wraps `mach_vm_region` and `mach_vm_protect` with a typed `PageProtection` abstraction.

| Function | Description |
|----------|-------------|
| `get_protection(addr)` | Query current RWX flags |
| `get_region_info(addr)` | Full region metadata (address, size, protection) |
| `find_region(addr)` | Find region containing or following address |
| `protect(addr, size, prot)` | Change protection flags |
| `is_readable/writable/executable(addr)` | Quick boolean checks |
| `get_all_regions()` | Enumerate all readable regions in the process |

Used internally by the scan engine (to verify readability before scanning), the code cave finder, and the fallback write path. Also exposed via the C FFI for direct use by consumers.

---

## Mach-O Segment/Section Querying (`src/memory/info/macho.rs`)

Queries named segments and sections of loaded Mach-O images via Darwin's `getsegmentdata()` and `getsectiondata()` C functions. The image base address (from `get_image_base`) is cast to a `mach_header_64*` for these calls.

| Function | Description |
|----------|-------------|
| `get_segment(image_name, seg_name)` | Get segment address, end, and size |
| `get_section(image_name, seg_name, sect_name)` | Get section within a segment |

Returns `SegmentData { start, end, size }`. Useful for targeted scanning — e.g., scan only `__TEXT,__text` instead of the entire image.

---

## Image Enumeration (`src/memory/info/image.rs`)

Beyond the existing `get_image_base(name)` lookup, the image module now provides:

| Function | Description |
|----------|-------------|
| `get_all_images()` | List all loaded images with index, name, and base |
| `image_count()` | Total number of loaded dyld images |
| `get_image_name(index)` | Full path of an image by dyld index |

All functions call dyld APIs (`_dyld_image_count`, `_dyld_get_image_name`, `_dyld_get_image_header`).

---

## Memory Backup (`src/memory/manipulation/backup.rs`)

Standalone backup and restore mechanism, independent of the patch system. Creates a snapshot of bytes at an address that can be restored later.

```mermaid
flowchart TD
    Create(["MemoryBackup::create(addr, size)"])
    ReadOrig[Read bytes at addr via rw::read]
    Store[Store address + original_bytes]
    Done(["MemoryBackup"])

    Restore(["backup.restore()"])
    Suspend[Suspend all threads]
    StealthWrite[stealth_write original bytes]
    Resume[Resume threads]

    Create --> ReadOrig --> Store --> Done
    Restore --> Suspend --> StealthWrite --> Resume
```

Backups are tracked in the FFI layer via `BACKUP_REGISTRY` (handle-based, same pattern as hooks).

---

## Patch Introspection

The `Patch` struct now tracks three byte states:

| Field | Description |
|-------|-------------|
| `original_bytes` | Bytes that were overwritten when the patch was applied |
| `patch_bytes` | Bytes that were written as the patch |
| `current_bytes()` | Live read of bytes at the patch address |

Comparing `current_bytes()` against `patch_bytes` detects external modification. The FFI exposes `mem_patch_list`, `mem_patch_count`, `mem_patch_size`, `mem_patch_orig_bytes`, `mem_patch_patch_bytes`, and `mem_patch_curr_bytes` for enumeration and inspection.

---

## Build Artifacts

```
target/
├── aarch64-apple-ios/
│   └── release/
│       └── libspecter.a          ← iOS static library
└── aarch64-apple-darwin/
    └── release/
        └── libspecter.a          ← macOS static library

specter.h                         ← C/C++ header (shared by both)
```
