# Multicodec zig 
This is the zig implementation of the multicodec [spec](https://github.com/multiformats/multicodec).

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
zig fetch --save https://github.com/optimism-java/multicodec-zig/archive/main.tar.gz
```

## Usage
```zig
const multicodec = @import("multicodec-zig");
```

## License
MIT
