[![build](https://github.com/zen-eth/multiformats-zig/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/zen-eth/multiformats-zig/actions/workflows/check.yml)

# Multiformats zig 
This is the zig implementation of the multiformats [spec](https://github.com/multiformats/multiformats).

## Build
```bash
git clone --recurse-submodules git@github.com:zen-eth/multiformats-zig.git
cd multiformats-zig
zig build test --summary all
```

## Generate the code
```bash
zig build-exe src/generate.zig
./generate
```

## Add to your project
```bash
zig fetch --save https://github.com/zen-eth/multiformats-zig/archive/main.tar.gz
```

## Usage
```zig
const multiformats = @import("multiformats-zig");
```

## Benchmark
```bash
git clone --recurse-submodules git@github.com:zen-eth/multiformats-zig.git
cd multiformats-zig
zig build bench --release=fast -Dcode=7
```
tip: The `code` parameter in the command can refer to the declaration in the `MultiBaseCodec.fromCode()` in the source file `src/multibase.zig`.

## License
MIT
