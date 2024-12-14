const std = @import("std");
const Allocator = std.mem.Allocator;
const Multicodec = @import("multicodec.zig").Multicodec;
const Multihash = @import("multihash.zig").Multihash;
const varint = @import("unsigned_varint.zig");

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

        pub fn newV0(allocator: Allocator, hash: Multihash(32)) !Cid {
            if (hash.getCode() != Multicodec.SHA2_256 or hash.getSize() != 32) {
                return Error.InvalidCidV0Multihash;
            }

            return Cid{
                .version = .V0,
                .codec = Multicodec.DAG_PB.getCode(),
                .hash = hash,
                .allocator = allocator,
            };
        }

        pub fn newV1(allocator: Allocator, codec: u64, hash: Multihash(S)) !Cid {
            return Cid{
                .version = .V1,
                .codec = codec,
                .hash = hash,
                .allocator = allocator,
            };
        }

        pub fn init(allocator: Allocator, version: CidVersion, codec: u64, hash: Multihash(S)) !@This() {
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

        pub fn readBytes(allocator: Allocator, reader: anytype) !Cid {
            const version = try varint.decode_stream(reader, u64);
            const codec = try varint.decode_stream(reader, u64);

            // CIDv0 has the fixed `0x12 0x20` prefix
            if (version == 0x12 and codec == 0x20) {
                var digest: [32]u8 = undefined;
                try reader.readNoEof(&digest);
                const mh = try Multihash(32).wrap(version, &digest);
                return newV0(allocator, mh);
            }

            const ver = try CidVersion.fromInt(version);
            switch (ver) {
                .V0 => return Error.InvalidExplicitCidV0,
                .V1 => {
                    const mh = try Multihash(32).read(reader);
                    return Cid.init(allocator, ver, codec, mh.getDigest());
                },
            }
        }

        fn writeBytesV1(self: *const Cid, writer: anytype) !usize {
            const version_written=try varint.encode_stream(writer,u64,self.version.toInt());
            const codec_written=try varint.encode_stream(writer,u64,self.codec);

            const written: usize = version_written + codec_written;

            return written;
        }

    };
}

// test "CID basic operations" {
//     const testing = std.testing;
//     const allocator = testing.allocator;
//
//     // Test CIDv0
//     {
//         var hash = [_]u8{ 0x12, 0x20 } ++ [_]u8{1} ** 32;
//         var cid = try Cid.init(allocator, .V0, .DagPb, hash[2..]);
//         defer cid.deinit();
//
//         try testing.expect(cid.version == .V0);
//         try testing.expect(cid.codec == .DagPb);
//         try testing.expectEqualSlices(u8, hash[2..], cid.hash);
//
//         // Test toBytes
//         const bytes = try cid.toBytes();
//         defer allocator.free(bytes);
//         try testing.expectEqualSlices(u8, &hash, bytes);
//     }
//
//     // Test CIDv1
//     {
//         var hash = [_]u8{1} ** 32;
//         var cid = try Cid.init(allocator, .V1, .DagCbor, &hash);
//         defer cid.deinit();
//
//         try testing.expect(cid.version == .V1);
//         try testing.expect(cid.codec == .DagCbor);
//         try testing.expectEqualSlices(u8, &hash, cid.hash);
//     }
// }
//
// test "CID fromBytes" {
//     const testing = std.testing;
//     const allocator = testing.allocator;
//
//     // Test CIDv0 parsing
//     {
//         var input = [_]u8{ 0x12, 0x20 } ++ [_]u8{1} ** 32;
//         var cid = try Cid.fromBytes(allocator, &input);
//         defer cid.deinit();
//
//         try testing.expect(cid.version == .V0);
//         try testing.expect(cid.codec == .DagPb);
//         try testing.expectEqualSlices(u8, input[2..], cid.hash);
//     }
//
//     // Test CIDv1 parsing
//     {
//         var input = [_]u8{ 1, @intFromEnum(Codec.DagCbor) } ++ [_]u8{1} ** 32;
//         var cid = try Cid.fromBytes(allocator, &input);
//         defer cid.deinit();
//
//         try testing.expect(cid.version == .V1);
//         try testing.expect(cid.codec == .DagCbor);
//         try testing.expectEqualSlices(u8, input[2..], cid.hash);
//     }
// }
//
// test "CID error cases" {
//     const testing = std.testing;
//     const allocator = testing.allocator;
//
//     // Test invalid V0 codec
//     {
//         var hash = [_]u8{1} ** 32;
//         try testing.expectError(Error.InvalidCidV0Codec, Cid.init(allocator, .V0, .DagCbor, &hash));
//     }
//
//     // Test input too short
//     {
//         var input = [_]u8{1};
//         try testing.expectError(Error.InputTooShort, Cid.fromBytes(allocator, &input));
//     }
//
//     // Test unknown codec
//     {
//         var input = [_]u8{ 1, 0xFF } ++ [_]u8{1} ** 32;
//         try testing.expectError(Error.UnknownCodec, Cid.fromBytes(allocator, &input));
//     }
// }
//
// test "CID version checks" {
//     const testing = std.testing;
//
//     // Test V0 string detection
//     {
//         const v0_str = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";
//         try testing.expect(CidVersion.isV0Str(v0_str));
//
//         const invalid_str = "invalid";
//         try testing.expect(!CidVersion.isV0Str(invalid_str));
//     }
//
//     // Test V0 binary detection
//     {
//         var valid_bytes = [_]u8{ 0x12, 0x20 } ++ [_]u8{1} ** 32;
//         try testing.expect(CidVersion.isV0Binary(&valid_bytes));
//
//         var invalid_bytes = [_]u8{ 0x00, 0x00 } ++ [_]u8{1} ** 32;
//         try testing.expect(!CidVersion.isV0Binary(&invalid_bytes));
//     }
// }
