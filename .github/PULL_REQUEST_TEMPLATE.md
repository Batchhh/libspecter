## Summary

<!-- What does this PR do? Keep it to 2–3 sentences. Link any related issue with "Fixes #N" or "Closes #N". -->

## Changes

-
-

## Testing

<!-- Describe how you verified the change. Include a minimal C/Rust snippet if the change touches the FFI or a hook/patch/breakpoint path. -->

```c

```

## Checklist

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --lib -- -D warnings` passes
- [ ] `make` builds `libspecter.a` without errors
- [ ] `make check` reports no symbol mismatches
- [ ] Public API changes are reflected in `specter.h` and `docs/usage.md`
- [ ] No unrelated changes included
