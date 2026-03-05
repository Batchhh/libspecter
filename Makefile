# Makefile — build libspecter.a (Rust static library) for aarch64-apple-ios
# and aarch64-apple-darwin, and optionally compile + link a C/C++ consumer.
#
# Usage:
#   make              — build libspecter.a for both iOS and macOS (release)
#   make ios          — build for iOS only
#   make macos        — build for macOS only
#   make debug        — build for both (debug)
#   make clean        — remove build artefacts
#   make check        — build and run a quick symbol-presence sanity check
#
# Consumer targets (set CONSUMER_SRC):
#   make consumer CONSUMER_SRC=tests/test.c
#   make consumer CONSUMER_SRC=tests/test.cpp

# Rust / Cargo
CARGO        := cargo
RUST_PROFILE := release

IOS_TARGET   := aarch64-apple-ios
MACOS_TARGET := aarch64-apple-darwin

IOS_LIB_DIR   := target/$(IOS_TARGET)/$(RUST_PROFILE)
MACOS_LIB_DIR := target/$(MACOS_TARGET)/$(RUST_PROFILE)
IOS_LIB       := $(IOS_LIB_DIR)/libspecter.a
MACOS_LIB     := $(MACOS_LIB_DIR)/libspecter.a

CARGO_FLAGS_RELEASE := --release

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
	-L$(IOS_LIB_DIR) \
	-lspectre \
	-lc++ \
	-framework Foundation \
	-framework Security

# Header
HEADER := specter.h

# Consumer (optional)
CONSUMER_SRC  ?=
CONSUMER_OUT  ?= build/consumer

.PHONY: all ios macos debug debug-ios debug-macos release consumer check check-ios check-macos clean help

all: ios macos

release: all

ios:
	$(CARGO) build --target $(IOS_TARGET) $(CARGO_FLAGS_RELEASE)
	@echo "Built: $(IOS_LIB)"

macos:
	$(CARGO) build --target $(MACOS_TARGET) $(CARGO_FLAGS_RELEASE)
	@echo "Built: $(MACOS_LIB)"

debug: debug-ios debug-macos

debug-ios:
	$(CARGO) build --target $(IOS_TARGET)
	@echo "Built: target/$(IOS_TARGET)/debug/libspecter.a"

debug-macos:
	$(CARGO) build --target $(MACOS_TARGET)
	@echo "Built: target/$(MACOS_TARGET)/debug/libspecter.a"

# Compile + link a C or C++ consumer file (against iOS build)
consumer: ios
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

# Sanity check: verify exported symbols are present in both builds
check: check-ios check-macos

check-ios: ios
	@echo "── Checking exported symbols in $(IOS_LIB) ──"
	@nm -gU $(IOS_LIB) | grep ' T _mem_' | sort
	@EXPECTED=$$(grep -E '^(int32_t|size_t|void)[[:space:]]+mem_[a-z]' $(HEADER) | wc -l | tr -d ' '); \
	FOUND=$$(nm -gU $(IOS_LIB) | grep -c ' T _mem_'); \
	echo "Declared in header: $$EXPECTED  |  Found in lib: $$FOUND"; \
	if [ "$$FOUND" -ge "$$EXPECTED" ]; then echo "OK (iOS)"; else echo "MISMATCH — check ffi.rs"; exit 1; fi

check-macos: macos
	@echo "── Checking exported symbols in $(MACOS_LIB) ──"
	@nm -gU $(MACOS_LIB) | grep ' T _mem_' | sort
	@EXPECTED=$$(grep -E '^(int32_t|size_t|void)[[:space:]]+mem_[a-z]' $(HEADER) | wc -l | tr -d ' '); \
	FOUND=$$(nm -gU $(MACOS_LIB) | grep -c ' T _mem_'); \
	echo "Declared in header: $$EXPECTED  |  Found in lib: $$FOUND"; \
	if [ "$$FOUND" -ge "$$EXPECTED" ]; then echo "OK (macOS)"; else echo "MISMATCH — check ffi.rs"; exit 1; fi

clean:
	$(CARGO) clean
	rm -rf build

help:
	@echo "Targets:"
	@echo "  all / release   Build libspecter.a for iOS and macOS (release)"
	@echo "  ios             Build for aarch64-apple-ios only"
	@echo "  macos           Build for aarch64-apple-darwin only"
	@echo "  debug           Build both targets (debug)"
	@echo "  consumer        Compile + link CONSUMER_SRC against libspecter.a"
	@echo "  check           Verify exported symbols for both targets"
	@echo "  clean           Remove all build artefacts"
	@echo ""
	@echo "Variables:"
	@echo "  SDK             Default: iphoneos  (use iphonesimulator for Simulator)"
	@echo "  MIN_IOS         Default: 14.0"
	@echo "  CONSUMER_SRC    Path to .c/.cpp file for the 'consumer' target"
	@echo "  CONSUMER_OUT    Output binary path (default: build/consumer)"
