# Specter

[![CI](https://github.com/Batchhh/libspecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Batchhh/libspecter/actions/workflows/ci.yml)

ARM64 memory manipulation framework for iOS/macOS. Compiled as a static library (`libspecter.a`) consumed via a plain C/C++ header (`specter.h`).

Provides inline function hooking, stealth code patching, hardware breakpoints, memory read/write, symbol resolution, and shellcode loading — all targeting `aarch64-apple-ios`.

## Build

```bash
rustup target add aarch64-apple-ios   # once
make                                   # release → target/aarch64-apple-ios/release/libspecter.a
make debug
make check                             # verify exported symbols match specter.h
```

## Integrate

```
-L<path> -lspectre -lc++ -framework Foundation -framework Security
```

## Docs

| | |
|---|---|
| [docs/usage.md](docs/usage.md) | Full API reference with C and C++ examples |
| [docs/architecture.md](docs/architecture.md) | Internals — hook engine, stealth patching, hardware breakpoints |
