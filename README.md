# age-ffi

A Rust FFI wrapper for the [age](https://github.com/str4d/rage) encryption library, with Zig bindings.

## Overview

This library provides C-compatible FFI bindings for the age encryption library, making it easy to use age encryption from other languages. It includes comprehensive Zig bindings and examples.

## Features

- Encryption and decryption with age public keys
- Passphrase-based encryption
- Support for multiple recipients
- Armor (ASCII) format support
- Memory-safe API with proper error handling
- Comprehensive test suite

## Building

### Rust Library

```bash
cargo build --release
```

### Zig Bindings

```bash
cd zig
zig build
```

Run the example:

```bash
cd zig
zig build run
```

Run tests:

```bash
cd zig
zig build test
```

## License

This project uses the same license as the age library.
