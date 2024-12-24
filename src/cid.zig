const std = @import("std");
const Allocator = std.mem.Allocator;
const Multicodec = @import("multicodec.zig").Multicodec;
const multihash = @import("multihash.zig");
const Multihash = multihash.Multihash;
const varint = @import("unsigned_varint.zig");
const multibase = @import("multibase.zig");
const MultiBaseCodec = multibase.MultiBaseCodec;

const IPFS_DELIMITER = "/ipfs/";

/// Constants for CID implementation
const MULTIHASH_VERSION = 0x12;
const MULTIHASH_CODEC = 0x20;
const DIGEST_SIZE = 32;
const MIN_CID_LENGTH = 2;

/// CidError represents an error that occurred during CID parsing.
pub const ParseError = error{
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

/// CID version enum representing different versions of Content Identifiers
pub const CidVersion = enum(u64) {
    /// Version 0 CID format
    V0 = 0,
    /// Version 1 CID format
    V1 = 1,

    /// Length of a V0 CID string representation
    const V0_STRING_LENGTH = 46;
    /// Length of a V0 CID binary representation
    const V0_BINARY_LENGTH = 34;
    /// Expected prefix for V0 CID strings
    const V0_STRING_PREFIX = "Qm";
    /// Expected prefix bytes for V0 binary format
    const V0_BINARY_PREFIX = [_]u8{ 0x12, 0x20 };

    /// Checks if the given data is a valid V0 CID string.
    /// The string must be exactly 46 characters long and start with "Qm".
    pub fn isV0Str(data: []const u8) bool {
        return data.len == V0_STRING_LENGTH and std.mem.startsWith(u8, data, V0_STRING_PREFIX);
    }

    /// Checks if the given data is a valid V0 CID binary.
    /// The binary must be exactly 34 bytes long and start with [0x12, 0x20].
    pub fn isV0Binary(data: []const u8) bool {
        return data.len == V0_BINARY_LENGTH and std.mem.startsWith(u8, data, &V0_BINARY_PREFIX);
    }

    /// Converts a u64 to a CidVersion.
    pub fn fromInt(value: u64) ParseError!CidVersion {
        return switch (value) {
            0 => .V0,
            1 => .V1,
            else => ParseError.InvalidCidVersion,
        };
    }

    /// Converts a CidVersion to a u64.
    pub fn toInt(self: CidVersion) u64 {
        return @as(u64, @intFromEnum(self));
    }
};

/// Cid represents a Content Identifier.
pub fn Cid(comptime S: usize) type {
    return struct {
        version: CidVersion,
        codec: Multicodec,
        hash: Multihash(S),

        const Self = @This();

        /// Creates a new V0 CID with the given allocator and hash.
        pub fn newV0(hash: Multihash(32)) !Self {
            if (hash.getCode() != Multicodec.SHA2_256 or hash.getSize() != 32) {
                return ParseError.InvalidCidV0Multihash;
            }

            return Cid(32){
                .version = .V0,
                .codec = Multicodec.DAG_PB,
                .hash = hash,
            };
        }

        /// Creates a new V1 CID with the given allocator, codec, and hash.
        pub fn newV1(codec: Multicodec, hash: Multihash(S)) !Self {
            return Cid(S){
                .version = .V1,
                .codec = codec,
                .hash = hash,
            };
        }

        /// Initializes a new CID with the given allocator, version, codec, and hash.
        pub fn init(version: CidVersion, codec: Multicodec, hash: Multihash(S)) !Self {
            switch (version) {
                .V0 => {
                    if (codec != Multicodec.DAG_PB) {
                        return ParseError.InvalidCidV0Codec;
                    }

                    return newV0(hash);
                },
                .V1 => {
                    return newV1(codec, hash);
                },
            }
        }

        /// Checks if two CIDs are equal by comparing version, codec and hash
        pub fn isEqual(self: *const Self, other: *const Self) bool {
            return self.version == other.version and
                self.codec == other.codec and
                std.mem.eql(u8, self.hash.getDigest(), other.hash.getDigest());
        }

        /// writes the CID to the given writer.
        pub fn writeBytesV1(self: *const Self, writer: anytype) !usize {
            const version_written = try varint.encodeStream(writer, u64, self.version.toInt());
            const codec_written = try varint.encodeStream(writer, u64, self.codec.getCode());

            var written: usize = version_written + codec_written;
            written += try self.hash.write(writer);
            return written;
        }

        /// Converts a V0 CID to a V1 CID.
        pub fn intoV1(self: *const Self) !Self {
            return switch (self.version) {
                .V0 => {
                    if (self.codec != Multicodec.DAG_PB) {
                        return ParseError.InvalidCidV0Codec;
                    }
                    return newV1(self.codec, self.hash);
                },
                .V1 => self.*,
            };
        }

        /// Reads a CID from the given reader.
        pub fn readStream(reader: anytype) !Self {
            const version = try varint.decodeStream(reader, u64);
            const codec = try varint.decodeStream(reader, u64);

            if (version == 0x12 and codec == 0x20) {
                var digest: [32]u8 = undefined;
                try reader.readNoEof(&digest);
                const version_codec = try Multicodec.fromCode(version);
                const mh = try Multihash(32).wrap(version_codec, &digest);
                return newV0(mh);
            }

            const ver = try CidVersion.fromInt(version);
            switch (ver) {
                .V0 => return ParseError.InvalidExplicitCidV0,
                .V1 => {
                    const mh = try Multihash(32).read(reader);
                    return Self.init(ver, try Multicodec.fromCode(codec), mh);
                },
            }
        }

        /// Writes the CID to the given writer.
        pub fn writeStream(self: *const Self, writer: anytype) !usize {
            return switch (self.version) {
                .V0 => try self.hash.write(writer),
                .V1 => try self.writeBytesV1(writer),
            };
        }

        /// Returns the length of the CID in bytes.
        pub fn encodedLen(self: *const Self) usize {
            return switch (self.version) {
                .V0 => self.hash.encodedLen(),
                .V1 => {
                    var version_buf: [varint.bufferSize(u64)]u8 = undefined;
                    const version = varint.encode(u64, self.version.toInt(), &version_buf);

                    var codec_buf: [varint.bufferSize(u64)]u8 = undefined;
                    const codec = varint.encode(u64, self.codec.getCode(), &codec_buf);

                    return version.len + codec.len + self.hash.encodedLen();
                },
            };
        }

        pub fn encodedStringLen(self: *const Self) usize {
            return self.encodedBaseStringLen(.Base32Lower);
        }

        pub fn encodedBaseStringLen(self: *const Self, base: MultiBaseCodec) usize {
            return switch (self.version) {
                .V0 => CidVersion.V0_STRING_LENGTH,
                .V1 => {
                    var version_buf: [varint.bufferSize(u64)]u8 = undefined;
                    const version = varint.encode(u64, self.version.toInt(), &version_buf);

                    var codec_buf: [varint.bufferSize(u64)]u8 = undefined;
                    const codec = varint.encode(u64, self.codec.getCode(), &codec_buf);

                    const byte_len = version.len + codec.len + self.hash.encodedLen();
                    return base.calcSizeBySize(byte_len);
                },
            };
        }

        /// Converts the CID to a byte slice.
        pub fn toBytes(self: *const Self, dest: []u8) ![]u8 {
            var stream = std.io.fixedBufferStream(dest);

            const written = try self.writeStream(stream.writer());
            return dest[0..written];
        }

        /// Returns the hash of the CID.
        pub fn getHash(self: *const Self) []const u8 {
            return self.hash.getDigest();
        }

        /// Returns the codec of the CID.
        pub fn getCodec(self: Self) Multicodec {
            return self.codec;
        }

        /// Returns the version of the CID.
        pub fn getVersion(self: Self) CidVersion {
            return self.version;
        }

        /// Returns the CID as a string.
        pub fn toString(self: *const Self, dest: []u8, source: []const u8) ![]const u8 {
            return switch (self.version) {
                .V0 => try toStringV0(dest, source),
                .V1 => try toStringV1(dest, source),
            };
        }

        /// Returns the CID as a string with the given base.
        pub fn toStringOfBase(self: *const Self, base: MultiBaseCodec, dest: []u8, source: []const u8) ![]const u8 {
            return switch (self.version) {
                .V0 => {
                    if (base != .Base58Btc) {
                        return ParseError.InvalidCidV0Base;
                    }
                    return toStringV0(dest, source);
                },
                .V1 => {
                    const encoded = base.encode(dest, source);
                    return encoded;
                },
            };
        }

        pub fn fromBytes(bytes: []const u8) !Self {
            var fbs = std.io.fixedBufferStream(bytes);
            return try Self.readStream(fbs.reader());
        }

        // pub fn calcDecodedSize(cid_str: []const u8) !usize {
        //     const hash = if (std.mem.indexOf(u8, cid_str, IPFS_DELIMITER)) |index|
        //         cid_str[index + IPFS_DELIMITER.len ..]
        //     else
        //         cid_str;
        //
        //     return if (CidVersion.isV0Str(hash))
        //         MultiBaseCodec.Base58Btc.calcSizeForDecode(hash)
        //     else
        //        multibase.MultiBaseCodec.calcDecodedSize(hash);
        // }
        //
        // pub fn fromString(allocator: Allocator, cid_str: []const u8, buffer: []u8) !Self {
        //     // Find IPFS delimiter if present
        //     const hash = if (std.mem.indexOf(u8, cid_str, IPFS_DELIMITER)) |index|
        //         cid_str[index + IPFS_DELIMITER.len ..]
        //     else
        //         cid_str;
        //
        //     if (hash.len < 2) return CidError.InputTooShort;
        //
        //     // Handle CIDv0 vs CIDv1
        //     const decoded = if (CidVersion.isV0Str(hash))
        //         try MultiBaseCodec.Base58Btc.decode(buffer, hash)
        //     else
        //         try multibase
        //
        //     return try Self.fromBytes(allocator, decoded);
        // }

        // pub fn fromString(allocator: Allocator, cid_str: []const u8) !Self {
        //     // Find IPFS delimiter if present
        //     const hash = if (std.mem.indexOf(u8, cid_str, IPFS_DELIMITER)) |index|
        //         cid_str[index + IPFS_DELIMITER.len ..]
        //     else
        //         cid_str;
        //
        //     if (hash.len < 2) return CidError.InputTooShort;
        //
        //     // Handle CIDv0 vs CIDv1
        //     const decoded = if (CidVersion.isV0Str(hash)) blk: {
        //         const needed_size = MultiBaseCodec.Base58Btc.calcSizeForDecode(hash);
        //         var dest = try allocator.alloc(u8, needed_size);
        //         errdefer allocator.free(dest);
        //
        //         const result = try MultiBaseCodec.Base58Btc.decode(dest, hash);
        //         if (result.len < dest.len) {
        //             dest = try allocator.realloc(dest, result.len);
        //         }
        //         break :blk dest[0..result.len];
        //     } else blk: {
        //         const decoded_result = try multibase.decode(allocator, hash);
        //         break :blk decoded_result.data;
        //     };
        //
        //     defer allocator.free(decoded);
        //     return try Self.fromBytes(allocator, decoded);
        // }
    };
}

fn toStringV0(dest: []u8, source: []const u8) ![]const u8 {
    const encoded = MultiBaseCodec.Base58Impl.encodeBtc(dest, source);

    return encoded;
}

fn toStringV1(dest: []u8, source: []const u8) ![]const u8 {
    const encoded = MultiBaseCodec.Base32Lower.encode(dest, source);

    return encoded;
}

test "Cid" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test CIDv0
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const cid = try Cid(32).newV0(hash);
        try testing.expectEqual(cid.version, .V0);
        try testing.expectEqual(cid.codec, Multicodec.DAG_PB);
    }

    // Test CIDv1
    {
        const hash = try Multihash(64).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const cid = try Cid(64).newV1(Multicodec.RAW, hash);
        try testing.expectEqual(cid.version, .V1);
        try testing.expectEqual(cid.codec, Multicodec.RAW);
    }

    // Test encoding/decoding
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const original = try Cid(32).newV1(Multicodec.RAW, hash);

        const needed_size = original.encodedLen();
        const buffer = try allocator.alloc(u8, needed_size);
        const bytes = try original.toBytes(buffer);
        defer allocator.free(buffer);

        var fbs = std.io.fixedBufferStream(bytes);
        const decoded = try Cid(32).readStream(fbs.reader());

        try testing.expect(original.isEqual(&decoded));
    }
}

test "Cid conversion and comparison" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test V0 to V1 conversion
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const v0 = try Cid(32).newV0(hash);
        const v1 = try v0.intoV1();

        try testing.expectEqual(v1.version, .V1);
        try testing.expectEqual(v1.codec, v0.codec);
        try testing.expect(std.mem.eql(u8, v1.getHash(), v0.getHash()));
    }

    // Test encoded length
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        const cid = try Cid(32).newV1(Multicodec.RAW, hash);
        const needed_size = cid.encodedLen();
        const buffer = try allocator.alloc(u8, needed_size);
        defer allocator.free(buffer);
        const bytes = try cid.toBytes(buffer);

        try testing.expectEqual(cid.encodedLen(), bytes.len);
    }
}

test "to_string_of_base32" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const expected_cid = "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy";
    const hash = try multihash.MultihashCodecs.SHA2_256.digest("foo");
    const cid = try Cid(32).newV1(Multicodec.RAW, hash);
    const needed_size = cid.encodedLen();
    const buffer = try allocator.alloc(u8, needed_size);
    defer allocator.free(buffer);
    const source = try cid.toBytes(buffer);

    const needed_size_str = cid.encodedBaseStringLen(.Base32Lower);
    const buffer_str = try allocator.alloc(u8, needed_size_str);
    defer allocator.free(buffer_str);
    const result_str = try cid.toStringOfBase(.Base32Lower, buffer_str, source);

    try testing.expectEqualStrings(expected_cid, result_str);
}

test "Cid string representations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test V0 string representation with Base58BTC
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{1} ** 32);
        const cid = try Cid(32).newV0(hash);
        const needed_size = cid.encodedLen();
        const buffer = try allocator.alloc(u8, needed_size);
        defer allocator.free(buffer);
        const source = try cid.toBytes(buffer);

        const needed_size_str = cid.encodedStringLen();
        const buffer_str = try allocator.alloc(u8, needed_size_str);
        defer allocator.free(buffer_str);

        const str = try cid.toString(buffer_str, source);

        try testing.expect(CidVersion.isV0Str(str));
    }

    // Test V1 string representation with different bases
    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{1} ** 32);
        const cid = try Cid(32).newV1(Multicodec.RAW, hash);
        const needed_size = cid.encodedLen();
        const buffer = try allocator.alloc(u8, needed_size);
        defer allocator.free(buffer);
        const source = try cid.toBytes(buffer);

        const needed_size_str = cid.encodedStringLen();
        const buffer_str = try allocator.alloc(u8, needed_size_str);
        defer allocator.free(buffer_str);
        const str_default = try cid.toString(buffer_str, source);

        const needed_size_str_base58 = cid.encodedBaseStringLen(.Base58Btc);
        const buffer_str_base58 = try allocator.alloc(u8, needed_size_str_base58);
        defer allocator.free(buffer_str_base58);
        const str_base58 = try cid.toStringOfBase(.Base58Btc, buffer_str_base58, source);

        try testing.expect(!std.mem.eql(u8, str_default, str_base58));
    }
}

test "Cid error cases" {
    const testing = std.testing;
    const allocator = testing.allocator;

    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        try testing.expectError(ParseError.InvalidCidV0Codec, Cid(32).init(.V0, Multicodec.RAW, hash));
    }

    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_512, &[_]u8{0} ** 32);
        try testing.expectError(ParseError.InvalidCidV0Multihash, Cid(32).newV0(hash));
    }

    {
        const hash = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{0} ** 32);
        var cid = try Cid(32).newV0(hash);

        const needed_size = cid.encodedLen();
        const buffer = try allocator.alloc(u8, needed_size);
        defer allocator.free(buffer);
        const source = try cid.toBytes(buffer);

        const needed_size_str = cid.encodedBaseStringLen(.Base32Lower);
        const buffer_str = try allocator.alloc(u8, needed_size_str);
        defer allocator.free(buffer_str);
        try testing.expectError(ParseError.InvalidCidV0Base, cid.toStringOfBase(.Base32Lower, buffer_str, source));
    }
}

// test "Cid fromString1" {
//     const testing = std.testing;
//     const allocator = testing.allocator;
//
//     // Test CIDv0
//     {
//         const cidstr = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";
//         const cid = try Cid(32).fromString(allocator, cidstr);
//
//         try testing.expectEqual(cid.version, .V0);
//         try testing.expectEqual(cid.codec, Multicodec.DAG_PB.getCode());
//     }
//
//     // Test CIDv1
//     {
//         const cidstr = "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy";
//         const cid = try Cid(32).fromString(allocator, cidstr);
//
//         try testing.expectEqual(cid.version, .V1);
//         try testing.expectEqual(cid.codec, Multicodec.RAW.getCode());
//         const hash = try multihash.MultihashCodecs.SHA2_256.digest("foo");
//         try testing.expectEqualSlices(u8, hash.getDigest(), cid.getHash());
//     }
//
//     // Test with IPFS path
//     {
//         const cidstr = "/ipfs/QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";
//         const cid = try Cid(32).fromString(allocator, cidstr);
//
//         try testing.expectEqual(cid.version, .V0);
//         try testing.expectEqual(cid.codec, Multicodec.DAG_PB.getCode());
//     }
//
//     // Test error cases
//     {
//         // Too short
//         try testing.expectError(CidError.InputTooShort, Cid(32).fromString(allocator, "a"));
//
//         // Invalid base encoding
//         try testing.expectError(multibase.ParseError.InvalidChar, Cid(32).fromString(allocator, "bafybeig@#$%"));
//     }
// }
