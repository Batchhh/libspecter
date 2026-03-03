# Makefile — build libspecter.a (Rust static library) for aarch64-apple-ios
# and optionally compile + link a C/C++ consumer against it.
#
# Usage:
#   make              — build libspecter.a (release)
#   make debug        — build libspecter.a (debug)
#   make clean        — remove build artefacts
#   make check        — build and run a quick symbol-presence sanity check
#
# Consumer targets (set CONSUMER_SRC):
#   make consumer CONSUMER_SRC=tests/test.c
#   make consumer CONSUMER_SRC=tests/test.cpp
#
# Override any variable on the command line, e.g.:
#   make CARGO_TARGET=aarch64-apple-macosx14.0

# Rust / Cargo
CARGO        := cargo
CARGO_TARGET := aarch64-apple-ios
RUST_PROFILE := release
CARGO_FLAGS  := --target $(CARGO_TARGET)

ifeq ($(RUST_PROFILE),release)
	CARGO_FLAGS += --release
endif

RUST_LIB_DIR := target/$(CARGO_TARGET)/$(RUST_PROFILE)
RUST_LIB     := $(RUST_LIB_DIR)/libspecter.a

# Apple SDK / toolchain
SDK          := iphoneos
SYSROOT      := $(shell xcrun --sdk $(SDK) --show-sdk-path 2>/dev/null)
CC           := $(shell xcrun --sdk $(SDK) --find clang   2>/dev/null)
CXX          := $(shell xcrun --sdk $(SDK) --find clang++ 2>/dev/null)
AR           := $(shell xcrun --sdk $(SDK) --find ar      2>/dev/null)

# Fall back to host tools if xcrun fails (e.g. macOS/Simulator builds)
ifeq ($(CC),)
	CC  := clang
	CXX := clang++
	AR  := ar
endif

ARCH         := arm64
MIN_IOS      := 14.0

CFLAGS := \
	-arch $(ARCH) \
	-isysroot $(SYSROOT) \
	-miphoneos-version-min=$(MIN_IOS) \
	-I. \
	-O2

CXXFLAGS := $(CFLAGS) -std=c++17

LDFLAGS := \
	-arch $(ARCH) \
	-isysroot $(SYSROOT) \
	-miphoneos-version-min=$(MIN_IOS) \
	-L$(RUST_LIB_DIR) \
	-lspectre \
	-lc++ \
	-framework Foundation \
	-framework Security

# Header
HEADER := specter.h

# Consumer (optional)
CONSUMER_SRC  ?=
CONSUMER_OUT  ?= build/consumer

.PHONY: all debug release consumer check clean help

all: release

release:
	$(CARGO) build $(CARGO_FLAGS)
	@echo "Built: $(RUST_LIB)"

debug: RUST_PROFILE := debug
debug: CARGO_FLAGS  := --target $(CARGO_TARGET)
debug: RUST_LIB_DIR := target/$(CARGO_TARGET)/debug
debug: RUST_LIB     := target/$(CARGO_TARGET)/debug/libspecter.a
debug:
	$(CARGO) build --target $(CARGO_TARGET)
	@echo "Built: target/$(CARGO_TARGET)/debug/libspecter.a"

# Compile + link a C or C++ consumer file
consumer: release
	@if [ -z "$(CONSUMER_SRC)" ]; then \
		echo "Error: set CONSUMER_SRC=path/to/file.{c,cpp}"; exit 1; \
	fi
	@mkdir -p build
	@EXT=$$(echo "$(CONSUMER_SRC)" | sed 's/.*\.//'); \
	if [ "$$EXT" = "cpp" ] || [ "$$EXT" = "cxx" ] || [ "$$EXT" = "cc" ]; then \
		COMPILER="$(CXX)"; CFLAGS_USED="$(CXXFLAGS)"; \
	else \
		COMPILER="$(CC)";  CFLAGS_USED="$(CFLAGS)"; \
	fi; \
	echo "$$COMPILER $$CFLAGS_USED $(CONSUMER_SRC) $(LDFLAGS) -o $(CONSUMER_OUT)"; \
	$$COMPILER $$CFLAGS_USED $(CONSUMER_SRC) $(LDFLAGS) -o $(CONSUMER_OUT)
	@echo "Linked: $(CONSUMER_OUT)"

# Sanity check: verify exported symbols are present in the static lib
check: release
	@echo "── Checking exported symbols in $(RUST_LIB) ──"
	@nm -gU $(RUST_LIB) | grep ' T _mem_' | sort
	@EXPECTED=$$(grep -E '^(int32_t|size_t|void)[[:space:]]+mem_[a-z]' $(HEADER) | wc -l | tr -d ' '); \
	FOUND=$$(nm -gU $(RUST_LIB) | grep -c ' T _mem_'); \
	echo "Declared in header: $$EXPECTED  |  Found in lib: $$FOUND"; \
	if [ "$$FOUND" -ge "$$EXPECTED" ]; then echo "OK"; else echo "MISMATCH — check ffi.rs"; exit 1; fi

clean:
	$(CARGO) clean
	rm -rf build

help:
	@echo "Targets:"
	@echo "  all / release   Build libspecter.a (release)"
	@echo "  debug           Build libspecter.a (debug)"
	@echo "  consumer        Compile + link CONSUMER_SRC against libspecter.a"
	@echo "  check           Verify exported symbols match memory.h declarations"
	@echo "  clean           Remove all build artefacts"
	@echo ""
	@echo "Variables:"
	@echo "  CARGO_TARGET    Default: aarch64-apple-ios"
	@echo "  SDK             Default: iphoneos  (use iphonesimulator for Simulator)"
	@echo "  MIN_IOS         Default: 14.0"
	@echo "  CONSUMER_SRC    Path to .c/.cpp file for the 'consumer' target"
	@echo "  CONSUMER_OUT    Output binary path (default: build/consumer)"
