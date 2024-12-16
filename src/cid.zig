const std = @import("std");
const Allocator = std.mem.Allocator;
const Multicodec = @import("multicodec.zig").Multicodec;
const multihash = @import("multihash.zig");
const Multihash = multihash.Multihash;
const varint = @import("unsigned_varint.zig");
const multibase = @import("multibase.zig");
const MultiBaseCodec = multibase.MultiBaseCodec;

pub const Error = error{
    UnknownCodec,
    InputTooShort,
    ParsingError,
    InvalidCidVersion,
    InvalidCidV0Codec,
    InvalidCidV0Multihash,
    InvalidCidV0Base,
    VarIntDecodeError,
    InvalidExplicitCidV0,
};

pub const CidVersion = enum(u64) {
    V0 = 0,
    V1 = 1,

    pub fn isV0Str(data: []const u8) bool {
        return data.len == 46 and std.mem.startsWith(u8, data, "Qm");
    }

    pub fn isV0Binary(data: []const u8) bool {
        return data.len == 34 and std.mem.startsWith(u8, data, &[_]u8{ 0x12, 0x20 });
    }

    pub fn fromInt(value: u64) Error!CidVersion {
        return switch (value) {
            0 => .V0,
            1 => .V1,
            else => Error.InvalidCidVersion,
        };
    }

    pub fn toInt(self: CidVersion) u64 {
        return @as(u64, @intFromEnum(self));
    }
};

pub fn Cid(comptime S: usize) type {
    return struct {
        version: CidVersion,
        codec: u64,
        hash: Multihash(S),
        allocator: Allocator,

        const Self = @This();

        pub fn newV0(allocator: Allocator, hash: Multihash(32)) !Self {
            if (hash.getCode() != Multicodec.SHA2_256 or hash.getSize() != 32) {
                return Error.InvalidCidV0Multihash;
            }

            return Cid(32){
                .version = .V0,
                .codec = Multicodec.DAG_PB.getCode(),
                .hash = hash,
                .allocator = allocator,
            };
        }

        pub fn newV1(allocator: Allocator, codec: u64, hash: Multihash(S)) !Self {
            return Cid(S){
                .version = .V1,
                .codec = codec,
                .hash = hash,
                .allocator = allocator,
            };
        }

        pub fn init(allocator: Allocator, version: CidVersion, codec: u64, hash: Multihash(S)) !Self {
            switch (version) {
                .V0 => {
                    if (codec != Multicodec.DAG_PB.getCode()) {
                        return Error.InvalidCidV0Codec;
                    }

                    return newV0(allocator, hash);
                },
                .V1 => {
                    return newV1(allocator, codec, hash);
                },
            }
        }

        /// Checks if two CIDs are equal by comparing version, codec and hash
        pub fn isEqual(self: *const Self, other: *const Self) bool {
            return self.version == other.version and
                self.codec == other.codec and
                std.mem.eql(u8, self.hash.getDigest(), other.hash.getDigest());
        }

        pub fn writeBytesV1(self: *const Self, writer: anytype) !usize {
            const version_written = try varint.encode_stream(writer, u64, self.version.toInt());
            const codec_written = try varint.encode_stream(writer, u64, self.codec);

            var written: usize = version_written + codec_written;
            written += try self.hash.write(writer);
            return written;
        }

        pub fn intoV1(self: Self) !Self {
            return switch (self.version) {
                .V0 => {
                    if (self.codec != @intFromEnum(Multicodec.DAG_PB)) {
                        return Error.InvalidCidV0Codec;
                    }
                    return newV1(self.allocator, self.codec, self.hash);
                },
                .V1 => self,
            };
        }

        pub fn readBytes(allocator: Allocator, reader: anytype) !Self {
            const version = try varint.decode_stream(reader, u64);
            const codec = try varint.decode_stream(reader, u64);

            if (version == 0x12 and codec == 0x20) {
                var digest: [32]u8 = undefined;
                try reader.readNoEof(&digest);
                const version_codec = try Multicodec.fromCode(version);
                const mh = try Multihash(32).wrap(version_codec, &digest);
                return newV0(allocator, mh);
            }

            const ver = try CidVersion.fromInt(version);
            switch (ver) {
                .V0 => return Error.InvalidExplicitCidV0,
                .V1 => {
                    const mh = try Multihash(32).read(reader);
                    return Self.init(allocator, ver, codec, mh);
                },
            }
        }

        pub fn writeBytes(self: *const Self, writer: anytype) !usize {
            return switch (self.version) {
                .V0 => try self.hash.write(writer),
                .V1 => try self.writeBytesV1(writer),
            };
        }

        pub fn encodedLen(self: Self) usize {
            return switch (self.version) {
                .V0 => self.hash.encodedLen(),
                .V1 => {
                    var version_buf: [varint.bufferSize(u64)]u8 = undefined;
                    const version = varint.encode(u64, self.version.toInt(), &version_buf);

                    var codec_buf: [varint.bufferSize(u64)]u8 = undefined;
                    const codec = varint.encode(u64, self.codec, &codec_buf);

                    return version.len + codec.len + self.hash.encodedLen();
                },
            };
        }

        pub fn toBytes(self: *const Self) ![]u8 {
            var bytes = std.ArrayList(u8).init(self.allocator);
            errdefer bytes.deinit();

            const written = try self.writeBytes(bytes.writer());
            std.debug.assert(written == bytes.items.len);

            return bytes.toOwnedSlice();
        }

        pub fn getHash(self: *const Self) []const u8 {
            return self.hash.getDigest();
        }

        pub fn getCodec(self: *const Self) u64 {
            return self.codec;
        }

        pub fn getVersion(self: *const Self) CidVersion {
            return self.version;
        }

        fn toStringV0(self: *const Self) ![]const u8 {
            const bytes = try self.toBytes();
            defer self.allocator.free(bytes);

            const needed_size = MultiBaseCodec.Base58Btc.calcSize(bytes) - 1; // -1 for remove the multibase prefix 'z'
            const dest = try self.allocator.alloc(u8, needed_size);
            const encoded = MultiBaseCodec.base58.encodeBtc(dest, bytes);

            if (encoded.len < dest.len) {
                // Shrink allocation to exact size if needed
                return self.allocator.realloc(dest, encoded.len);
            }
            return dest;
        }

        fn toStringV1(self: *const Self) ![]const u8 {
            const bytes = try self.toBytes();
            defer self.allocator.free(bytes);

            const needed_size = MultiBaseCodec.Base32Lower.calcSize(bytes);
            const dest = try self.allocator.alloc(u8, needed_size);
            const encoded = MultiBaseCodec.Base32Lower.encode(dest, bytes);
            if (encoded.len < dest.len) {
                // Shrink allocation to exact size if needed
                return self.allocator.realloc(dest, encoded.len);
            }
            return dest;
        }

        pub fn toString(self: Self) ![]const u8 {
            switch (self.version) {
                .V0 => {
                    // For V0, always use Base58BTC
                    return try self.toStringV0();
                },
                .V1 => {
                    // For V1, use Base32Lower
                    return try self.toStringV1();
                },
            }
        }

        pub fn toStringOfBase(self: *const Self, base: MultiBaseCodec) ![]const u8 {
            return switch (self.version) {
                .V0 => {
                    if (base != .Base58Btc) {
                        return Error.InvalidCidV0Base;
                    }
                    return self.toStringV0();
                },
                .V1 => {
                    const bytes = try self.toBytes();
                    defer self.allocator.free(bytes);

                    const needed_size = base.calcSize(bytes);
                    const dest = try self.allocator.alloc(u8, needed_size);
                    const encoded = base.encode(dest, bytes);
                    if (encoded.len < dest.len) {
                        // Shrink allocation to exact size if needed
                        return self.allocator.realloc(dest, encoded.len);
                    }
                    return dest;
                },
            };
        }
    };
}

test "Cid" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test CIDv0
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const cid = try Cid(32).newV0(allocator, hash);
        try testing.expectEqual(cid.version, .V0);
        try testing.expectEqual(cid.codec, Multicodec.DAG_PB.getCode());
    }

    // Test CIDv1
    {
        const hash = try Multihash(64).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const cid = try Cid(64).newV1(allocator, Multicodec.RAW.getCode(), hash);
        try testing.expectEqual(cid.version, .V1);
        try testing.expectEqual(cid.codec, Multicodec.RAW.getCode());
    }

    // Test encoding/decoding
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const original = try Cid(32).newV1(allocator, Multicodec.RAW.getCode(), hash);

        const bytes = try original.toBytes();
        defer allocator.free(bytes);

        var fbs = std.io.fixedBufferStream(bytes);
        const decoded = try Cid(32).readBytes(allocator, fbs.reader());

        try testing.expect(original.isEqual(&decoded));
    }
}

test "Cid conversion and comparison" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test V0 to V1 conversion
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const v0 = try Cid(32).newV0(allocator, hash);
        const v1 = try v0.intoV1();

        try testing.expectEqual(v1.version, .V1);
        try testing.expectEqual(v1.codec, v0.codec);
        try testing.expect(std.mem.eql(u8, v1.getHash(), v0.getHash()));
    }

    // Test encoded length
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const cid = try Cid(32).newV1(allocator, Multicodec.RAW.getCode(), hash);
        const bytes = try cid.toBytes();
        defer allocator.free(bytes);

        try testing.expectEqual(cid.encodedLen(), bytes.len);
    }
}

test "to_string_of_base32" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const expected_cid = "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy";
    const hash = try multihash.MultihashCodecs.SHA2_256.digest("foo");
    const cid = try Cid(32).newV1(allocator, Multicodec.RAW.getCode(), hash);

    const result = try cid.toStringOfBase(.Base32Lower);
    defer allocator.free(result);

    try testing.expectEqualStrings(expected_cid, result);
}

test "Cid string representations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test V0 string representation with Base58BTC
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{1} ** 32);
        const cid = try Cid(32).newV0(allocator, hash);
        const str = try cid.toString();
        defer allocator.free(str);
        std.debug.print("V0 string: {s}\n", .{str});
        try testing.expect(CidVersion.isV0Str(str));
    }

    // Test V1 string representation with different bases
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{1} ** 32);
        const cid = try Cid(32).newV1(allocator, Multicodec.RAW.getCode(), hash);

        const str_default = try cid.toString();
        defer allocator.free(str_default);

        const str_base58 = try cid.toStringOfBase(.Base58Btc);
        defer allocator.free(str_base58);

        try testing.expect(!std.mem.eql(u8, str_default, str_base58));
    }
}

test "Cid error cases" {
    const testing = std.testing;
    const allocator = testing.allocator;

    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        try testing.expectError(Error.InvalidCidV0Codec, Cid(32).init(allocator, .V0, Multicodec.RAW.getCode(), hash));
    }

    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_512, &[_]u8{0} ** 32);
        try testing.expectError(Error.InvalidCidV0Multihash, Cid(32).newV0(allocator, hash));
    }

    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        var cid = try Cid(32).newV0(allocator, hash);
        defer {
            if (cid.toStringOfBase(.Base32Lower)) |str| {
                allocator.free(str);
            } else |_| {}
        }
        try testing.expectError(Error.InvalidCidV0Base, cid.toStringOfBase(.Base32Lower));
    }
}
