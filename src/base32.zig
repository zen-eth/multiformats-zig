const std = @import("std");
const multibase = @import("multibase.zig");

pub const standard = struct {
    const ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz234567";
    const ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const PADDING = '=';

    pub const lower = struct {
        pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |byte| {
                bits = (bits << 8) | byte;
                bit_count += 8;

                while (bit_count >= 5) {
                    bit_count -= 5;
                    const index = (bits >> bit_count) & 0x1F;
                    try result.append(ALPHABET_LOWER[index]);
                }
            }

            if (bit_count > 0) {
                const index = (bits << (5 - bit_count)) & 0x1F;
                try result.append(ALPHABET_LOWER[index]);
            }

            return result.toOwnedSlice();
        }

        pub fn encodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = try encode(allocator, input);
            const padding_len = (5 - (input.len % 5)) % 5;

            var i: usize = 0;
            while (i < padding_len) : (i += 1) {
                try result.append(PADDING);
            }

            return result;
        }
    };

    pub const upper = struct {
        pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |byte| {
                bits = (bits << 8) | byte;
                bit_count += 8;

                while (bit_count >= 5) {
                    bit_count -= 5;
                    const index = (bits >> bit_count) & 0x1F;
                    try result.append(ALPHABET_UPPER[index]);
                }
            }

            if (bit_count > 0) {
                const index = (bits << (5 - bit_count)) & 0x1F;
                try result.append(ALPHABET_UPPER[index]);
            }

            return result.toOwnedSlice();
        }

        pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |c| {
                const value = std.mem.indexOfScalar(u8, ALPHABET_UPPER, c) orelse return multibase.Error.InvalidBaseString;
                bits = (bits << 5) | @as(u16, @intCast(value));
                bit_count += 5;

                while (bit_count >= 8) {
                    bit_count -= 8;
                    try result.append(@as(u8, @intCast((bits >> bit_count) & 0xFF)));
                }
            }

            return result.toOwnedSlice();
        }

        pub fn encodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = try encode(allocator, input);
            const padding_len = (8 - (result.len % 8)) % 8;

            var i: usize = 0;
            while (i < padding_len) : (i += 1) {
                try result.append(PADDING);
            }

            return result;
        }

        pub fn decodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var end: usize = input.len;
            while (end > 0 and input[end - 1] == PADDING) : (end -= 1) {}

            return decode(allocator, input[0..end]);
        }
    };
};

pub const hex = struct {
    const ALPHABET_HEX_LOWER = "0123456789abcdefghijklmnopqrstuv";
    const ALPHABET_HEX_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const PADDING = '=';

    pub const lower = struct {
        pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |byte| {
                bits = (bits << 8) | byte;
                bit_count += 8;

                while (bit_count >= 5) {
                    bit_count -= 5;
                    const index = (bits >> bit_count) & 0x1F;
                    try result.append(ALPHABET_HEX_LOWER[index]);
                }
            }

            if (bit_count > 0) {
                const index = (bits << (5 - bit_count)) & 0x1F;
                try result.append(ALPHABET_HEX_LOWER[index]);
            }

            return result.toOwnedSlice();
        }

        pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |c| {
                const value = std.mem.indexOfScalar(u8, ALPHABET_HEX_LOWER, c) orelse return multibase.Error.InvalidBaseString;
                bits = (bits << 5) | @as(u16, @intCast(value));
                bit_count += 5;

                while (bit_count >= 8) {
                    bit_count -= 8;
                    try result.append(@as(u8, @intCast((bits >> bit_count) & 0xFF)));
                }
            }

            return result.toOwnedSlice();
        }

        pub fn encodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = try encode(allocator, input);
            const padding_len = (8 - (result.len % 8)) % 8;

            var i: usize = 0;
            while (i < padding_len) : (i += 1) {
                try result.append(PADDING);
            }

            return result;
        }

        pub fn decodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            // Remove padding
            var end: usize = input.len;
            while (end > 0 and input[end - 1] == PADDING) : (end -= 1) {}

            return decode(allocator, input[0..end]);
        }
    };

    pub const upper = struct {
        pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |byte| {
                bits = (bits << 8) | byte;
                bit_count += 8;

                while (bit_count >= 5) {
                    bit_count -= 5;
                    const index = (bits >> bit_count) & 0x1F;
                    try result.append(ALPHABET_HEX_UPPER[index]);
                }
            }

            if (bit_count > 0) {
                const index = (bits << (5 - bit_count)) & 0x1F;
                try result.append(ALPHABET_HEX_UPPER[index]);
            }

            return result.toOwnedSlice();
        }

        pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = std.ArrayList(u8).init(allocator);
            errdefer result.deinit();

            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (input) |c| {
                const value = std.mem.indexOfScalar(u8, ALPHABET_HEX_UPPER, c) orelse return multibase.Error.InvalidBaseString;
                bits = (bits << 5) | @as(u16, @intCast(value));
                bit_count += 5;

                while (bit_count >= 8) {
                    bit_count -= 8;
                    try result.append(@as(u8, @intCast((bits >> bit_count) & 0xFF)));
                }
            }

            return result.toOwnedSlice();
        }

        pub fn encodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            var result = try encode(allocator, input);
            const padding_len = (8 - (result.len % 8)) % 8;

            var i: usize = 0;
            while (i < padding_len) : (i += 1) {
                try result.append(PADDING);
            }

            return result;
        }

        pub fn decodePadded(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
            // Remove padding
            var end: usize = input.len;
            while (end > 0 and input[end - 1] == PADDING) : (end -= 1) {}

            return decode(allocator, input[0..end]);
        }
    };
};
