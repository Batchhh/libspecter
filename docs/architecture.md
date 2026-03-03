# Specter — Architecture

This document explains how the framework is built internally. It is aimed at contributors and advanced users who need to understand what is happening under the hood.

---

## Layer model

```mermaid
graph TD
    Consumer["C/C++ consumer<br/>(includes specter.h)"]
    FFI["src/ffi.rs<br/>─────────────────────────<br/>• Converts C types → Rust<br/>• Maps errors → MEM_ERR_*<br/>• Owns 4 handle registries<br/>  hooks / patches / brk / shellcode"]
    Hook["hook.rs<br/>Inline hook engine"]
    Patch["patch.rs<br/>Stealth patching"]
    RW["rw.rs<br/>Read / Write"]
    Brk["breakpoint.rs<br/>HW breakpoints"]
    Shell["shellcode.rs<br/>Executable loader"]
    Info["info/<br/>image.rs · symbol.rs<br/>code_cave.rs · scan.rs"]
    Kernel["Mach kernel / dyld / POSIX<br/>─────────────────────────────────────<br/>mach_vm_remap · vm_protect · task_threads<br/>mach_port_* · mach_msg · dlsym · _dyld_*"]

    Consumer -->|"stable C ABI<br/>extern C"| FFI
    FFI --> Hook
    FFI --> Patch
    FFI --> RW
    FFI --> Brk
    FFI --> Shell
    Hook --> Info
    Patch --> Info
    Shell --> Info
    Hook --> Kernel
    Patch --> Kernel
    RW --> Kernel
    Brk --> Kernel
    Shell --> Kernel
    Info --> Kernel
```

---

## Initialization (`src/config.rs`)

```mermaid
sequenceDiagram
    participant C as C/C++ caller
    participant FFI as ffi.rs
    participant Cfg as config.rs
    participant Img as image.rs (cache)
    participant dyld

    C->>FFI: mem_init("MyApp", &base_out)
    FFI->>Cfg: set_target_image_name("MyApp")
    FFI->>Img: get_image_base("MyApp")
    Img->>dyld: _dyld_image_count() / _dyld_get_image_name()
    dyld-->>Img: iterate image list
    Img-->>Img: cache result in DashMap
    Img-->>FFI: Ok(base_address)
    FFI-->>C: MEM_OK, *base_out = base_address

    Note over FFI,Img: All subsequent RVA calls resolve: absolute = base + rva
```

---

## Inline hook engine (`src/memory/manipulation/hook.rs`)

### Standard hook — full flow

```mermaid
flowchart TD
    Start(["mem_hook_install / install_at_address"])
    CheckExists{"Hook already<br/>exists at target?"}
    ErrExists(["return MEM_ERR_EXISTS"])
    ReadFirst["Read first instruction<br/>at target"]
    IsThunk{"First instr<br/>is a B thunk?"}
    AllocNear["alloc_trampoline_near<br/>mmap within ±128 MB"]
    AllocAny["alloc_trampoline<br/>mmap anywhere"]
    Suspend["Suspend all other threads<br/>thread_suspend × N"]
    Relocate["Relocate 4 instructions (16 bytes)<br/>to trampoline — fix PC-relative refs"]
    RelocOK{"All 4 instrs<br/>relocated?"}
    ErrReloc(["MEM_ERR_RELOC<br/>free trampoline + resume"])
    AppendReturn["Append absolute branch<br/>back to target+16"]
    Protect["mprotect trampoline RX"]
    FlushCache["Flush caches<br/>dc cvau · dsb ish · ic ivau · dsb ish · isb"]
    WriteHook["Write 16-byte polymorphic branch<br/>at target via stealth_write"]
    WriteOK{"Write<br/>succeeded?"}
    ErrPatch(["MEM_ERR_PATCH<br/>free trampoline + resume"])
    RegisterCRC["Register CRC checksum<br/>for tamper detection"]
    Resume["Resume all threads"]
    Done(["return MEM_OK<br/>trampoline addr + handle"])

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

### Instruction relocation logic

```mermaid
flowchart TD
    Instr["ARM64 instruction at PC"]

    IsADR{"ADR / ADRP?"}
    EmitADR["LDR Xd, #8 · B +12 · .quad abs_target<br/>→ 16 bytes"]

    IsLDRLit{"LDR literal<br/>W / X / SW?"}
    EmitLDR["LDR X17, #12 · LDR Xd, X17 · B +12 · .quad abs_addr<br/>→ 20 bytes"]

    IsBL{"BL?"}
    EmitBL["ADR X30, #16 + absolute BR to resolved target<br/>→ 20 bytes"]

    IsB{"B?"}
    EmitB["Absolute BR to resolved target<br/>→ 16 bytes"]

    IsCond{"B.cond / CBZ<br/>CBNZ / TBZ / TBNZ?"}
    EmitCond["Invert condition (skip 2) · LDR X2, abs_target · BR X2<br/>→ 20 bytes"]

    Default["Copy verbatim<br/>→ 4 bytes"]

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

Each hook redirect is randomly varied on every install using `arc4random()` — two hooks to the same address installed at different times will produce different bytes.

```mermaid
flowchart LR
    arc4random -->|"bit 16 == 0"| VariantA
    arc4random -->|"bit 16 == 1"| VariantB
    arc4random -->|"reg = rand % 9"| Reg["scratch reg<br/>x9 – x17"]

    VariantA["Variant A — literal pool<br/>────────────────────────<br/>LDR Xn, #8<br/>BR  Xn<br/>.quad dest<br/>(16 bytes)"]
    VariantB["Variant B — immediate moves<br/>────────────────────────<br/>MOVZ Xn, dest[15:0]<br/>MOVK Xn, dest[31:16], lsl 16<br/>MOVK Xn, dest[47:32], lsl 32<br/>BR   Xn<br/>(16 bytes)"]

    Reg --> VariantA
    Reg --> VariantB
```

### Code-cave hook

```mermaid
flowchart TD
    Start(["mem_hook_install_cave"])
    ScanNOP["code_cave.rs: scan __TEXT<br/>for NOP run ≥ 256 bytes<br/>within ±128 MB of target"]
    Found{"Cave<br/>found?"}
    ErrAlloc(["MEM_ERR_ALLOC"])
    Suspend["Suspend all threads"]
    Relocate["Relocate 4 instrs into<br/>temp buffer"]
    CaveWrite["stealth_write:<br/>relocated instrs + return branch<br/>→ into NOP region inside __TEXT"]
    TargetWrite["stealth_write:<br/>16-byte branch at target<br/>→ jumps into cave"]
    Resume["Resume threads"]
    Done(["return MEM_OK<br/>trampoline = cave addr"])

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

> The trampoline lives **inside the image's own `__TEXT` segment**, invisible to scanners that enumerate anonymous `mmap` pages.

---

## Stealth patching (`src/memory/manipulation/patch.rs`)

The standard `vm_protect(RW) → write → vm_protect(RX)` sequence is observable by security frameworks that monitor permission changes on executable pages. Specter avoids it entirely.

### mach_vm_remap write path

```mermaid
sequenceDiagram
    participant Caller
    participant stealth_write
    participant Mach as Mach kernel
    participant CodePage as "__TEXT page (RX, unchanged)"
    participant Alias as "Alias page (fresh VA)"

    Caller->>stealth_write: stealth_write(address, bytes)

    stealth_write->>Mach: mach_vm_remap(task, &alias_va, page_len, task, page_start, share=false)
    Mach-->>stealth_write: KERN_SUCCESS, alias_va
    Note over CodePage,Alias: Kernel maps both VAs to the same physical frames

    stealth_write->>Mach: mach_vm_protect(task, alias_va, RW)
    Note over CodePage: __TEXT stays RX — no observable vm_protect on code

    stealth_write->>Alias: memcpy(alias_va + offset, bytes, len)
    Note over CodePage: Write appears in __TEXT because pages share physical memory

    stealth_write->>Mach: mach_vm_deallocate(task, alias_va, page_len)
    Note over Alias: Alias torn down immediately

    stealth_write->>stealth_write: dc cvau + dsb ish + ic ivau + dsb ish + isb
    Note over stealth_write: Cache flush on ORIGINAL address

    stealth_write-->>Caller: Ok(())
```

### Full patch lifecycle

```mermaid
flowchart TD
    ApplyFn(["mem_patch_apply(rva, hex_str)"])
    ParseHex["Parse hex string<br/>strip whitespace · hex::decode"]
    ResolveBase["Resolve image base<br/>address = base + rva"]
    Suspend["Suspend all threads"]
    SaveOrig["Read original bytes<br/>saved in Patch struct"]
    StealthWrite["stealth_write<br/>via mach_vm_remap alias"]
    Verify{"Re-read bytes<br/>match expected?"}
    ErrVerify(["MEM_ERR_PATCH + resume threads"])
    Resume["Resume threads"]
    StoreReg["Store Patch in PATCH_REGISTRY<br/>keyed by address"]
    Done(["return MEM_OK + address_out"])

    Revert(["mem_patch_revert(address)"])
    LookupReg{"Address in<br/>PATCH_REGISTRY?"}
    ErrNotFound(["MEM_ERR_NOT_FOUND"])
    SuspendR["Suspend all threads"]
    RestoreOrig["stealth_write original bytes"]
    ResumeR["Resume threads"]
    FreeReg["Remove from registry"]

    ApplyFn --> ParseHex --> ResolveBase --> Suspend --> SaveOrig
    SaveOrig --> StealthWrite --> Verify
    Verify -->|no| ErrVerify
    Verify -->|yes| Resume --> StoreReg --> Done

    Revert --> LookupReg
    LookupReg -->|no| ErrNotFound
    LookupReg -->|yes| SuspendR --> RestoreOrig --> ResumeR --> FreeReg
```

### Fallback path (when remap is unavailable)

```mermaid
flowchart LR
    Try["mach_vm_remap"]
    OK{"KERN_SUCCESS<br/>+ max_prot has W?"}
    Remap["Write via alias<br/>(preferred — stealthy)"]
    Fallback["fallback_write:<br/>vm_protect page RW+COPY<br/>memcpy<br/>vm_protect page back to RX<br/>icache flush"]

    Try --> OK
    OK -->|yes| Remap
    OK -->|no| Fallback
```

---

## Hardware breakpoints (`src/memory/platform/breakpoint.rs`)

```mermaid
sequenceDiagram
    participant C as C/C++ caller
    participant FFI as ffi.rs
    participant BM as HookManager
    participant Mach as Mach kernel
    participant CPU as ARM64 CPU
    participant EHT as exception_handler_thread

    Note over BM,EHT: One-time initialization (first mem_brk_install call)
    FFI->>Mach: task_get_exception_ports — save existing EXC_BREAKPOINT handler
    FFI->>Mach: mach_port_allocate — create receive port
    FFI->>Mach: task_set_exception_ports(EXC_MASK_BREAKPOINT, port, EXCEPTION_STATE)
    FFI->>EHT: pthread_create — start exception loop

    Note over C,CPU: Installing a breakpoint
    C->>FFI: mem_brk_install(rva, replacement, &handle)
    FFI->>BM: add_hook(target, replacement)
    FFI->>Mach: task_set_state(ARM_DEBUG_STATE64) BVR[n]=target, BCR[n]=0x1E5
    FFI->>Mach: thread_set_state × all running threads
    FFI-->>C: MEM_OK, handle

    Note over CPU,EHT: Runtime — execution reaches target
    CPU->>Mach: hardware debug exception (EXC_BREAKPOINT)
    Mach->>EHT: mach_msg id=2406 with ARM_THREAD_STATE64 (PC = target)
    EHT->>BM: find_hook(PC) → replacement
    EHT->>Mach: mach_msg reply — new_state.PC = replacement
    Mach->>CPU: resume with modified PC
    CPU->>CPU: executes replacement function
```

### Breakpoint slot management

```mermaid
flowchart LR
    sysctl["sysctlbyname<br/>hw.optional.breakpoint"] --> hw_count["hw_breakpoints<br/>(typically 6)"]
    install["mem_brk_install_at<br/>(target, replacement)"] --> check{"active_count<br/>>= hw_count?"}
    check -->|yes| err(["MEM_ERR_HW_LIMIT"])
    check -->|no| slot["add_hook to<br/>HookManager slot array"]
    slot --> dbg["apply_debug_state:<br/>BVR[n] = target<br/>BCR[n] = 0x1E5<br/>on task + all threads"]
```

---

## Read / Write (`src/memory/manipulation/rw.rs`)

```mermaid
flowchart TD
    subgraph DataPages["Data pages — readable / writable"]
        MemRead["mem_read(addr, out, size)<br/>─────────────────────────<br/>ptr::copy_nonoverlapping<br/>addr → out"]
        MemWrite["mem_write(addr, value, size)<br/>─────────────────────────<br/>ptr::copy_nonoverlapping<br/>value → addr"]
        MemReadRVA["mem_read_rva(rva, out, size)<br/>─────────────────────────<br/>addr = get_image_base() + rva<br/>mem_read(addr, ...)"]
        MemWriteRVA["mem_write_rva(rva, value, size)<br/>─────────────────────────<br/>addr = get_image_base() + rva<br/>mem_write(addr, ...)"]
    end

    subgraph CodePages["Code pages — executable"]
        MemWriteBytes["mem_write_bytes(addr, data, len)<br/>─────────────────────────<br/>stealth_write via mach_vm_remap<br/>+ icache flush"]
    end

    subgraph Chain["Pointer chain"]
        MemChain["mem_read_pointer_chain<br/>(base, offsets, count, &result)<br/>─────────────────────────<br/>cur = base<br/>for each offset:<br/>  cur = *(cur + offset)<br/>result = cur"]
    end
```

### Pointer chain traversal

```mermaid
flowchart LR
    base["base<br/>0x100200000"]
    deref1["*(base + 0x10)<br/>→ ptr_A"]
    deref2["*(ptr_A + 0x28)<br/>→ ptr_B"]
    deref3["*(ptr_B + 0x08)<br/>→ 0xDEADBEEF"]
    result["result_out<br/>= 0xDEADBEEF"]

    base -->|"+ 0x10, deref"| deref1
    deref1 -->|"+ 0x28, deref"| deref2
    deref2 -->|"+ 0x08, deref"| deref3
    deref3 --> result
```

---

## Symbol resolution (`src/memory/info/symbol.rs`)

```mermaid
flowchart LR
    Call["mem_resolve_symbol(name)"]
    Cache{"In DashMap<br/>cache?"}
    Hit["return cached address"]
    dlsym["dlsym(RTLD_DEFAULT, name)"]
    Found{"result<br/>non-NULL?"}
    Store["store in cache<br/>return address"]
    Err(["MEM_ERR_SYMBOL"])

    Call --> Cache
    Cache -->|yes| Hit
    Cache -->|no| dlsym
    dlsym --> Found
    Found -->|yes| Store
    Found -->|no| Err
```

---

## Concurrency model

```mermaid
flowchart TD
    subgraph Registries["Global registries — parking_lot::Mutex"]
        HR["HOOK_REGISTRY<br/>Mutex&lt;HashMap&lt;u64, Hook&gt;&gt;"]
        PR["PATCH_REGISTRY<br/>Mutex&lt;HashMap&lt;usize, Patch&gt;&gt;"]
        BR["BRK_REGISTRY<br/>Mutex&lt;HashMap&lt;u64, Breakpoint&gt;&gt;"]
        SR["SHELLCODE_REGISTRY<br/>Mutex&lt;HashMap&lt;usize, LoadedShellcode&gt;&gt;"]
    end

    subgraph Caches["Image & symbol caches — DashMap (lock-free per shard)"]
        IC["image cache<br/>DashMap&lt;String, usize&gt;"]
        SC["symbol cache<br/>DashMap&lt;String, usize&gt;"]
    end

    subgraph PatchWindow["Thread-safe patch window (hooks + patches)"]
        direction LR
        S["Suspend all<br/>other threads"] --> W["stealth_write<br/>+ icache flush"] --> R["Resume all<br/>threads"]
    end

    HR & PR --> PatchWindow
```

> All hook and patch operations bracket the write inside a Mach thread-suspension window. This eliminates any race where another thread could execute partially-written hook bytes or observe an inconsistent instruction stream.
