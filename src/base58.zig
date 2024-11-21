const std = @import("std");

pub const flickr = struct {
    const ALPHABET = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

    pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        var result = std.ArrayList(u8).init(allocator);
        errdefer result.deinit();

        var value = try std.math.big.int.Managed.init(allocator);
        defer value.deinit();

        try value.setBytes(input, .big);

        // Handle zero case
        if (value.eqlZero()) {
            try result.append(ALPHABET[0]);
            return result.toOwnedSlice();
        }

        while (!value.eqlZero()) {
            const digit = try value.divFloor(&value, 58);
            try result.append(ALPHABET[digit]);
        }

        // Add leading zeros from input
        for (input) |byte| {
            if (byte != 0) break;
            try result.append(ALPHABET[0]);
        }

        std.mem.reverse(u8, result.items);
        return result.toOwnedSlice();
    }
};
