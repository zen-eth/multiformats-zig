const std = @import("std");
const varint = @import("unsigned_varint.zig");
const Multicodec = @import("multicodec.zig").Multicodec;
const testing = std.testing;

pub fn Multihash(comptime S: usize) type {
    return struct {
        code: Multicodec,
        size: u8,
        digest: [S]u8,

        const Self = @This();

        pub fn wrap(code: Multicodec, input_digest: []const u8) !Self {
            if (input_digest.len > S) {
                return error.InvalidSize;
            }

            var digest = [_]u8{0} ** S;
            @memcpy(digest[0..input_digest.len], input_digest[0..input_digest.len]); // Specify exact length

            return Self{
                .code = code,
                .size = @intCast(input_digest.len),
                .digest = digest,
            };
        }

        pub fn getCode(self: Self) Multicodec {
            return self.code;
        }

        pub fn getSize(self: Self) u8 {
            return self.size;
        }

        pub fn getDigest(self: Self) []const u8 {
            return self.digest[0..self.size];
        }

        pub fn truncate(self: Self, new_size: u8) Self {
            return Self{
                .code = self.code,
                .size = @min(self.size, new_size),
                .digest = self.digest,
            };
        }

        pub fn resize(self: Self, comptime R: usize) !Multihash(R) {
            if (self.size > R) {
                return error.InvalidSize;
            }

            var new_digest = [_]u8{0} ** R;
            @memcpy(new_digest[0..self.size], self.digest[0..self.size]);

            return Multihash(R){
                .code = self.code,
                .size = self.size,
                .digest = new_digest,
            };
        }

        pub fn encodedLen(self: Self) usize {
            var code_buf: [10]u8 = undefined;
            const code_encoded = varint.encode(u64, self.code.getCode(), &code_buf);

            var size_buf: [1]u8 = undefined;
            const size_encoded = varint.encode(u8, self.size, &size_buf);

            return code_encoded.len + size_encoded.len + self.size;
        }

        pub fn write(self: Self, writer: anytype) !usize {
            var code_buf: [10]u8 = undefined;
            const code_encoded = varint.encode(u64, self.code.getCode(), &code_buf);
            try writer.writeAll(code_encoded);

            var size_buf: [1]u8 = undefined;
            const size_encoded = varint.encode(u8, self.size, &size_buf);
            try writer.writeAll(size_encoded);

            try writer.writeAll(self.digest[0..self.size]);

            return code_encoded.len + size_encoded.len + self.size;
        }

        pub fn read(reader: anytype) !Self {
            const code = try varint.decode_stream(reader, u64);
            const size = try varint.decode_stream(reader, u8);

            if (size > S) {
                return error.InvalidSize;
            }

            var digest = [_]u8{0} ** S;
            try reader.readNoEof(digest[0..size]);

            return Self{
                .code = try Multicodec.fromCode(code),
                .size = size,
                .digest = digest,
            };
        }

        pub fn toBytes(self: Self, allocator: std.mem.Allocator) ![]u8 {
            const bytes = try allocator.alloc(u8, self.encodedLen());
            var stream = std.io.fixedBufferStream(bytes);
            _ = try self.write(stream.writer());
            return bytes;
        }
    };
}

test "basic multihash operations" {
    const expected_digest = [_]u8{
        0xB9, 0x4D, 0x27, 0xB9, 0x93, 0x4D, 0x3E, 0x08,
        0xA5, 0x2E, 0x52, 0xD7, 0xDA, 0x7D, 0xAB, 0xFA,
        0xC4, 0x84, 0xEF, 0xE3, 0x7A, 0x53, 0x80, 0xEE,
        0x90, 0x88, 0xF7, 0xAC, 0xE2, 0xEF, 0xCD, 0xE9,
    };

    var mh = try Multihash(32).wrap(Multicodec.SHA2_256, &expected_digest);
    try testing.expectEqual(mh.getCode(), Multicodec.SHA2_256);
    try testing.expectEqual(mh.getSize(), expected_digest.len);
    try testing.expectEqualSlices(u8, mh.getDigest(), &expected_digest);
}
test "multihash resize" {
    const input = "test data";
    var mh = try Multihash(32).wrap(Multicodec.CIDV1, input);

    // Resize up
    var larger = try mh.resize(64);
    try testing.expectEqual(larger.getSize(), input.len);
    try testing.expectEqualSlices(u8, larger.getDigest(), input);

    // Resize down should fail
    try testing.expectError(error.InvalidSize, mh.resize(4));
}

test "multihash serialization" {
    const expected_bytes = [_]u8{ 0x12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var mh = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const written = try mh.write(fbs.writer());
    try testing.expectEqual(written, expected_bytes.len);
    try testing.expectEqualSlices(u8, buf[0..written], &expected_bytes);
}

test "multihash deserialization" {
    const input = [_]u8{ 0x12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var fbs = std.io.fixedBufferStream(&input);
    var mh = try Multihash(32).read(fbs.reader());

    try testing.expectEqual(mh.getCode().getCode(), 0x12);
    try testing.expectEqual(mh.getSize(), 10);
    try testing.expectEqualSlices(u8, mh.getDigest(), input[2..]);
}

test "multihash truncate" {
    var mh = try Multihash(32).wrap(Multicodec.CIDV1, "hello world");
    const truncated = mh.truncate(5);
    try testing.expectEqual(truncated.getSize(), 5);
    try testing.expectEqualSlices(u8, truncated.getDigest(), "hello");
}
