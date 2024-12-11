const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const CidVersion = enum(u64) {
    V0 = 0,
    V1 = 1,
};

pub const Codec = enum(u64) {
    Raw = 0x55,
    DagPb = 0x70,
    DagCbor = 0x71,
};

pub const Cid = struct {
    version: CidVersion,
    codec: Codec,
    hash: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, version: CidVersion, codec: Codec, hash: []const u8) !Cid {
        const hash_copy = try allocator.dupe(u8, hash);
        return Cid{
            .version = version,
            .codec = codec,
            .hash = hash_copy,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Cid) void {
        self.allocator.free(self.hash);
    }

    pub fn format(self: Cid, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        switch (self.version) {
            .V0 => {
                if (self.codec != .DagPb) {
                    return error.InvalidV0Codec;
                }
                try writer.writeAll(try std.fmt.allocPrint(self.allocator, "Qm{}", .{std.fmt.fmtSliceHexLower(self.hash)}));
            },
            .V1 => {
                try writer.writeAll(try std.fmt.allocPrint(
                    self.allocator,
                    "b{}{}{}",
                    .{
                        @intFromEnum(self.version),
                        @intFromEnum(self.codec),
                        std.fmt.fmtSliceHexLower(self.hash),
                    },
                ));
            },
        }
    }
};

test "CID v0" {
    const allocator = testing.allocator;

    var hash = [_]u8{ 1, 2, 3, 4, 5 };
    var cid = try Cid.init(allocator, .V0, .DagPb, &hash);
    defer cid.deinit();

    try testing.expect(cid.version == .V0);
    try testing.expect(cid.codec == .DagPb);
    try testing.expectEqualSlices(u8, &hash, cid.hash);
}

test "CID v1" {
    const allocator = testing.allocator;

    var hash = [_]u8{ 1, 2, 3, 4, 5 };
    var cid = try Cid.init(allocator, .V1, .DagCbor, &hash);
    defer cid.deinit();

    try testing.expect(cid.version == .V1);
    try testing.expect(cid.codec == .DagCbor);
    try testing.expectEqualSlices(u8, &hash, cid.hash);
}
