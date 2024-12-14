const std = @import("std");
const Allocator = std.mem.Allocator;
const Multicodec = @import("multicodec.zig").Multicodec;
const Multihash = @import("multihash.zig").Multihash;

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

        // pub fn fromBytes(allocator: Allocator, bytes: []const u8) !@This() {
        //     if (CidVersion.isV0Binary(bytes)) {
        //         return @This().init(allocator, .V0, 0x70, bytes[2..]);
        //     }
        //
        //     if (bytes.len < 2) {
        //         return Error.InputTooShort;
        //     }
        //
        //     const version = try std.meta.intToEnum(CidVersion, bytes[0]);
        //     const codec = bytes[1];
        //
        //     return @This().init(allocator, version, codec, bytes[2..]);
        // }



        // pub fn toBytes(self: @This()) ![]u8 {
        //     var buf = try self.allocator.alloc(u8, 2 + self.hash.len);
        //
        //     switch (self.version) {
        //         .V0 => {
        //             buf[0] = 0x12;
        //             buf[1] = 0x20;
        //         },
        //         .V1 => {
        //             buf[0] = @as(u8, @intCast(@intFromEnum(self.version)));
        //             buf[1] = @as(u8, @intCast(self.codec));
        //         },
        //     }
        //
        //     @memcpy(buf[2..], &self.hash);
        //     return buf;
        // }
    };
}
// pub const Codec = enum(u64) {
//     Raw = 0x55,
//     DagPb = 0x70,
//     DagCbor = 0x71,
//
//     pub fn fromInt(value: u64) Error!Codec {
//         return switch (value) {
//             0x55 => .Raw,
//             0x70 => .DagPb,
//             0x71 => .DagCbor,
//             else => Error.UnknownCodec,
//         };
//     }
// };
//
// pub const Cid = struct {
//     version: CidVersion,
//     codec: Codec,
//     hash: []const u8,
//     allocator: Allocator,
//
//     pub fn init(allocator: Allocator, version: CidVersion, codec: Codec, hash: []const u8) !Cid {
//         if (version == .V0 and codec != .DagPb) {
//             return Error.InvalidCidV0Codec;
//         }
//
//         const hash_copy = try allocator.dupe(u8, hash);
//         return Cid{
//             .version = version,
//             .codec = codec,
//             .hash = hash_copy,
//             .allocator = allocator,
//         };
//     }
//
//     pub fn fromBytes(allocator: Allocator, bytes: []const u8) !Cid {
//         if (CidVersion.isV0Binary(bytes)) {
//             return Cid.init(allocator, .V0, .DagPb, bytes[2..]);
//         }
//
//         if (bytes.len < 2) {
//             return Error.InputTooShort;
//         }
//
//         const version = try std.meta.intToEnum(CidVersion, bytes[0]);
//         const codec = try Codec.fromInt(bytes[1]);
//
//         return Cid.init(allocator, version, codec, bytes[2..]);
//     }
//
//     pub fn deinit(self: *Cid) void {
//         self.allocator.free(self.hash);
//     }
//
//     pub fn toBytes(self: Cid) ![]u8 {
//         var buf = try self.allocator.alloc(u8, 2 + self.hash.len);
//
//         switch (self.version) {
//             .V0 => {
//                 buf[0] = 0x12;
//                 buf[1] = 0x20;
//             },
//             .V1 => {
//                 buf[0] = @as(u8, @intCast(@intFromEnum(self.version)));
//                 buf[1] = @as(u8, @intCast(@intFromEnum(self.codec)));
//             },
//         }
//
//         std.mem.copyForwards(u8, buf[2..], self.hash);
//         return buf;
//     }
// };
//
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
