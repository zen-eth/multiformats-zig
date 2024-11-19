# Multiformats zig 
This is the zig implementation of the multiformats [spec](https://github.com/multiformats/multiformats).

## Build
```bash
zig build
```

## Generate the code
```bash
zig build-exe src/generate.zig
./generate
```

## Add to your project
```bash
zig fetch --save https://github.com/optimism-java/multiformats-zig/archive/main.tar.gz
```

## Usage
```zig
const multicodec = @import("multiformats-zig");
```

## License
MIT
