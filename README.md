# Specter

[![CI](https://github.com/Batchhh/libspecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Batchhh/libspecter/actions/workflows/ci.yml)


ARM64 memory manipulation framework for iOS/macOS. Compiled as a static library (`libspecter.a`) consumed via a plain C/C++ header (`specter.h`).

Provides inline function hooking, stealth code patching, hardware breakpoints, memory read/write, symbol resolution, and shellcode loading — all targeting `aarch64-apple-ios`.

## Build

```bash
rustup target add aarch64-apple-ios   # once
make                                  # release → target/aarch64-apple-ios/release/libspecter.a
make debug
make check                            # verify exported symbols match specter.h
```

## Integrate

```
-L<path> -lspectre -lc++ -framework Foundation -framework Security
```

## Docs

[docs/usage.md](docs/usage.md) — C/C++ API reference and examples

[docs/architecture.md](docs/architecture.md) — Internal design and data flows

## Contributing

1. Fork the repo and create a branch from `main`.
2. Run `cargo fmt --all` and `cargo clippy --lib -- -D warnings` before pushing.
3. Keep PRs focused — one logical change per pull request.
4. Open an issue first for anything large or architectural.

Bug reports and feature requests are welcome via [GitHub Issues](https://github.com/Batchhh/libspecter/issues).

## Legal

This project is intended for **educational and research purposes only**. Use it only on devices and applications you own or have explicit authorization to test. The author is not responsible for any misuse or damage caused by this software.

## License

MIT — see [LICENSE](LICENSE).
