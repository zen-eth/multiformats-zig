const std = @import("std");
const Multihash = @import("multihash.zig").Multihash;
const Multicodec = @import("multicodec.zig").Multicodec;
const testing = std.testing;

pub fn MultihashDigest(comptime T: type, comptime alloc_size: usize) type {
    return struct {
        pub fn digest(code: T, input: []const u8) !Multihash(alloc_size) {
            var hasher = Hasher.init(code);
            try hasher.update(input);
            const digest_bytes = switch (hasher) {
                inline else => |*h| h.finalize()[0..],
            };
            return try Multihash(alloc_size).wrap(try Multicodec.fromCode(@intFromEnum(code)), digest_bytes);
        }
    };
}

const Hasher = union(enum) {
    sha2_256: Sha2_256,
    sha2_512: Sha2_512,
    sha3_224: Sha3_224,
    sha3_256: Sha3_256,
    sha3_384: Sha3_384,
    sha3_512: Sha3_512,
    keccak_256: Keccak_256,
    keccak_512: Keccak_512,

    pub fn init(code: MultihashCodecs) Hasher {
        return switch (code) {
            .SHA2_256 => .{ .sha2_256 = Sha2_256.init() },
            .SHA2_512 => .{ .sha2_512 = Sha2_512.init() },
            .SHA3_224 => .{ .sha3_224 = Sha3_224.init() },
            .SHA3_256 => .{ .sha3_256 = Sha3_256.init() },
            .SHA3_384 => .{ .sha3_384 = Sha3_384.init() },
            .SHA3_512 => .{ .sha3_512 = Sha3_512.init() },
            .KECCAK_256 => .{ .keccak_256 = Keccak_256.init() },
            .KECCAK_512 => .{ .keccak_512 = Keccak_512.init() },
        };
    }

    pub fn update(self: *Hasher, data: []const u8) !void {
        switch (self.*) {
            inline else => |*h| try h.update(data),
        }
    }
};

pub const MultihashCodecs = enum(u64) {
    SHA2_256 = Multicodec.SHA2_256.getCode(),
    SHA2_512 = Multicodec.SHA2_512.getCode(),
    SHA3_224 = Multicodec.SHA3_224.getCode(),
    SHA3_256 = Multicodec.SHA3_256.getCode(),
    SHA3_384 = Multicodec.SHA3_384.getCode(),
    SHA3_512 = Multicodec.SHA3_512.getCode(),
    KECCAK_256 = Multicodec.KECCAK_256.getCode(),
    KECCAK_512 = Multicodec.KECCAK_512.getCode(),
    // Keccak224 = 0x1a, // Not supported by std.crypto.hash.sha3
    // Keccak384 = 0x1c, // Not supported by std.crypto.hash.sha3
    // Blake2b256 = 0xb220,
    // Blake2b512 = 0xb240,
    // Blake2s128 = 0xb250,
    // Blake2s256 = 0xb260,
    // Blake3_256 = 0x1e,

    pub usingnamespace MultihashDigest(@This(), 64);
};

pub const Sha2_256 = struct {
    ctx: std.crypto.hash.sha2.Sha256,

    pub fn init() Sha2_256 {
        return .{ .ctx = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *Sha2_256, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Sha2_256) [32]u8 {
        return self.ctx.finalResult();
    }
};

pub const Sha2_512 = struct {
    ctx: std.crypto.hash.sha2.Sha512,

    pub fn init() Sha2_512 {
        return .{ .ctx = std.crypto.hash.sha2.Sha512.init(.{}) };
    }

    pub fn update(self: *Sha2_512, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Sha2_512) [64]u8 {
        return self.ctx.finalResult();
    }
};

pub const Sha3_224 = struct {
    ctx: std.crypto.hash.sha3.Sha3_224,

    pub fn init() Sha3_224 {
        return .{ .ctx = std.crypto.hash.sha3.Sha3_224.init(.{}) };
    }

    pub fn update(self: *Sha3_224, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Sha3_224) [28]u8 {
        var out = [_]u8{0} ** 28;
        self.ctx.final(&out);
        return out;
    }
};

pub const Sha3_256 = struct {
    ctx: std.crypto.hash.sha3.Sha3_256,

    pub fn init() Sha3_256 {
        return .{ .ctx = std.crypto.hash.sha3.Sha3_256.init(.{}) };
    }

    pub fn update(self: *Sha3_256, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Sha3_256) [32]u8 {
        var out = [_]u8{0} ** 32;
        self.ctx.final(&out);
        return out;
    }
};

pub const Sha3_384 = struct {
    ctx: std.crypto.hash.sha3.Sha3_384,

    pub fn init() Sha3_384 {
        return .{ .ctx = std.crypto.hash.sha3.Sha3_384.init(.{}) };
    }

    pub fn update(self: *Sha3_384, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Sha3_384) [48]u8 {
        var out = [_]u8{0} ** 48;
        self.ctx.final(&out);
        return out;
    }
};

pub const Sha3_512 = struct {
    ctx: std.crypto.hash.sha3.Sha3_512,

    pub fn init() Sha3_512 {
        return .{ .ctx = std.crypto.hash.sha3.Sha3_512.init(.{}) };
    }

    pub fn update(self: *Sha3_512, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Sha3_512) [64]u8 {
        var out = [_]u8{0} ** 64;
        self.ctx.final(&out);
        return out;
    }
};

pub const Keccak_256 = struct {
    ctx: std.crypto.hash.sha3.Keccak256,

    pub fn init() Keccak_256 {
        return .{ .ctx = std.crypto.hash.sha3.Keccak256.init(.{}) };
    }

    pub fn update(self: *Keccak_256, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Keccak_256) [32]u8 {
        var out = [_]u8{0} ** 32;
        self.ctx.final(&out);
        return out;
    }
};

pub const Keccak_512 = struct {
    ctx: std.crypto.hash.sha3.Keccak512,

    pub fn init() Keccak_512 {
        return .{ .ctx = std.crypto.hash.sha3.Keccak512.init(.{}) };
    }

    pub fn update(self: *Keccak_512, data: []const u8) !void {
        self.ctx.update(data);
    }

    pub fn finalize(self: *Keccak_512) [64]u8 {
        var out = [_]u8{0} ** 64;
        self.ctx.final(&out);
        return out;
    }
};

pub const Blake2b256 = struct {
    ctx: std.crypto.hash.blake2.Blake2b256,
    pub fn init() Blake2b256 {
        return .{ .ctx = std.crypto.hash.blake2.Blake2b256.init(.{}) };
    }

    pub fn update(self: *Blake2b256, data: []const u8) !void {
        self.ctx.update(data);
    }
    pub fn finalize(self: *Blake2b256) [32]u8 {
        return self.ctx.finalResult();
    }
};

test "sha256 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.SHA2_256.digest(input);
    try testing.expectEqual(@as(u64, 0x12), hash.code.getCode());
    try testing.expectEqual(@as(usize, 32), hash.getSize());

    var hash1 = std.crypto.hash.sha2.Sha256.init(.{});
    hash1.update(input);
    const hash_bytes = hash1.finalResult();
    try testing.expectEqualSlices(u8, &hash_bytes, hash.getDigest());
}

test "sha512 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.SHA2_512.digest(input);
    try testing.expectEqual(@as(u64, 0x13), hash.code.getCode());
    try testing.expectEqual(@as(usize, 64), hash.getSize());

    var hash1 = std.crypto.hash.sha2.Sha512.init(.{});
    hash1.update(input);
    const hash_bytes = hash1.finalResult();
    try testing.expectEqualSlices(u8, &hash_bytes, hash.getDigest());
}

test "sha3_224 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.SHA3_224.digest(input);
    try testing.expectEqual(@as(u64, 0x17), hash.code.getCode());
    try testing.expectEqual(@as(usize, 28), hash.getSize());

    var hash1 = std.crypto.hash.sha3.Sha3_224.init(.{});
    hash1.update(input);
    var out = [_]u8{0} ** 28;
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_256 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.SHA3_256.digest(input);
    try testing.expectEqual(@as(u64, 0x16), hash.code.getCode());
    try testing.expectEqual(@as(usize, 32), hash.getSize());

    var hash1 = std.crypto.hash.sha3.Sha3_256.init(.{});
    hash1.update(input);
    var out = [_]u8{0} ** 32;
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_384 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.SHA3_384.digest(input);
    try testing.expectEqual(@as(u64, 0x15), hash.code.getCode());
    try testing.expectEqual(@as(usize, 48), hash.getSize());

    var hash1 = std.crypto.hash.sha3.Sha3_384.init(.{});
    hash1.update(input);
    var out = [_]u8{0} ** 48;
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_512 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.SHA3_512.digest(input);
    try testing.expectEqual(@as(u64, 0x14), hash.code.getCode());
    try testing.expectEqual(@as(usize, 64), hash.getSize());

    var hash1 = std.crypto.hash.sha3.Sha3_512.init(.{});
    hash1.update(input);
    var out = [_]u8{0} ** 64;
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "keccak_256 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.KECCAK_256.digest(input);
    try testing.expectEqual(@as(u64, 0x1b), hash.code.getCode());
    try testing.expectEqual(@as(usize, 32), hash.getSize());

    var hash1 = std.crypto.hash.sha3.Keccak256.init(.{});
    hash1.update(input);
    var out = [_]u8{0} ** 32;
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "keccak_512 hash operations" {
    const input = "hello world";
    const hash = try MultihashCodecs.KECCAK_512.digest(input);
    try testing.expectEqual(@as(u64, 0x1d), hash.code.getCode());
    try testing.expectEqual(@as(usize, 64), hash.getSize());

    var hash1 = std.crypto.hash.sha3.Keccak512.init(.{});
    hash1.update(input);
    var out = [_]u8{0} ** 64;
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}
