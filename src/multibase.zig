// const std = @import("std");
// const base32= @import("base32.zig");
// const base58= @import("base58.zig");
//
// pub const Base = enum {
//     Identity, // 8-bit binary (encoder and decoder keeps data unmodified)
//     Base2, // Base2 (alphabet: 01)
//     Base8, // Base8 (alphabet: 01234567)
//     Base10, // Base10 (alphabet: 0123456789)
//     Base16Lower, // Base16 lower hexadecimal (alphabet: 0123456789abcdef)
//     Base16Upper, // Base16 upper hexadecimal (alphabet: 0123456789ABCDEF)
//     Base32Lower, // Base32, rfc4648 no padding (alphabet: abcdefghijklmnopqrstuvwxyz234567)
//     Base32Upper, // Base32, rfc4648 no padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567)
//     Base32PadLower, // Base32, rfc4648 with padding (alphabet: abcdefghijklmnopqrstuvwxyz234567)
//     Base32PadUpper, // Base32, rfc4648 with padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567)
//     Base32HexLower, // Base32hex, rfc4648 no padding (alphabet: 0123456789abcdefghijklmnopqrstuv)
//     Base32HexUpper, // Base32hex, rfc4648 no padding (alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUV)
//     Base32HexPadLower, // Base32hex, rfc4648 with padding (alphabet: 0123456789abcdefghijklmnopqrstuv)
//     Base32HexPadUpper, // Base32hex, rfc4648 with padding (alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUV)
//     Base32Z, // z-base-32 (used by Tahoe-LAFS) (alphabet: ybndrfg8ejkmcpqxot1uwisza345h769)
//     Base36Lower, // Base36, [0-9a-z] no padding
//     Base36Upper, // Base36, [0-9A-Z] no padding
//     Base58Flickr, // Base58 flicker
//     Base58Btc, // Base58 bitcoin
//     Base64, // Base64, rfc4648 no padding
//     Base64Pad, // Base64, rfc4648 with padding
//     Base64Url, // Base64 url, rfc4648 no padding
//     Base64UrlPad, // Base64 url, rfc4648 with padding
//     Base256Emoji, // Base256Emoji
//
//     pub fn code(self: Base) u8 {
//         return switch (self) {
//             .Identity => 0x00,
//             .Base2 => '0',
//             .Base8 => '7',
//             .Base10 => '9',
//             .Base16Lower => 'f',
//             .Base16Upper => 'F',
//             .Base32Lower => 'b',
//             .Base32Upper => 'B',
//             .Base32PadLower => 'c',
//             .Base32PadUpper => 'C',
//             .Base32HexLower => 'v',
//             .Base32HexUpper => 'V',
//             .Base32HexPadLower => 't',
//             .Base32HexPadUpper => 'T',
//             .Base32Z => 'h',
//             .Base36Lower => 'k',
//             .Base36Upper => 'K',
//             .Base58Flickr => 'Z',
//             .Base58Btc => 'z',
//             .Base64 => 'm',
//             .Base64Pad => 'M',
//             .Base64Url => 'u',
//             .Base64UrlPad => 'U',
//             .Base256Emoji => '🚀',
//         };
//     }
// };
//
// pub const Error = error{
//     UnknownBase,
//     InvalidBaseString,
// };
//
// pub fn encode(allocator: std.mem.Allocator, base: Base, input: []const u8) ![]u8 {
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     try result.append(base.code());
//
//     const encoded = switch (base) {
//         .Identity => try allocator.dupe(u8, input),
//         .Base2 => try encodeBase2(allocator, input),
//         .Base8 => try encodeBase8(allocator, input),
//         .Base10 => try encodeBase10(allocator, input),
//         .Base16Lower => try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(input)}),
//         .Base16Upper => try std.fmt.allocPrint(allocator, "{X}", .{std.fmt.fmtSliceHexUpper(input)}),
//         .Base32Lower => try base32.standard.lower.encode(allocator, input),
//         .Base32Upper => try base32.standard.upper.encode(allocator, input),
//         .Base32PadLower => try base32.standard.lower.encodePadded(allocator, input),
//         .Base32PadUpper => try base32.standard.upper.encodePadded(allocator, input),
//         .Base32HexLower => try base32.hex.lower.encode(allocator, input),
//         .Base32HexUpper => try base32.hex.upper.encode(allocator, input),
//         .Base32HexPadLower => try base32.hex.lower.encodePadded(allocator, input),
//         .Base32HexPadUpper => try base32.hex.upper.encodePadded(allocator, input),
//         .Base32Z => try encodeBase32Z(allocator, input),
//         .Base36Lower => try encodeBase36(allocator, input, false),
//         .Base36Upper => try encodeBase36(allocator, input, true),
//         .Base58Flickr => try base58.flickr.encode(allocator, input),
//         .Base58Btc => try base58.btc.encode(allocator, input),
//         .Base64 => try std.base64.standard_no_pad.Encoder.encode(allocator, input),
//         .Base64Pad => try std.base64.standard.Encoder.encode(allocator, input),
//         .Base64Url => try std.base64.url_safe_no_pad.Encoder.encode(allocator, input),
//         .Base64UrlPad => try std.base64.url_safe.Encoder.encode(allocator, input),
//         .Base256Emoji => try encodeBase256Emoji(allocator, input),
//     };
//
//     try result.appendSlice(encoded);
//     return result.toOwnedSlice();
// }
//
// fn encodeBase2(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     for (input) |byte| {
//         var i: u3 = 7;
//         while (true) {
//             try result.append('0' + ((byte >> i) & 1));
//             if (i == 0) break;
//             i -= 1;
//         }
//     }
//     return result.toOwnedSlice();
// }
//
// fn encodeBase8(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     for (input) |byte| {
//         var i: u3 = 6;
//         while (true) {
//             try result.append('0' + ((byte >> i) & 0x7));
//             if (i < 3) break;
//             i -= 3;
//         }
//     }
//     return result.toOwnedSlice();
// }
//
// fn encodeBase32Z(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
//     const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     var bit_len: usize = 0;
//     var bits: u16 = 0;
//
//     for (input) |byte| {
//         bits = (bits << 8) | byte;
//         bit_len += 8;
//
//         while (bit_len >= 5) {
//             bit_len -= 5;
//             const index = (bits >> bit_len) & 0x1F;
//             try result.append(ALPHABET[index]);
//         }
//     }
//
//     if (bit_len > 0) {
//         const index = (bits << (5 - bit_len)) & 0x1F;
//         try result.append(ALPHABET[index]);
//     }
//
//     return result.toOwnedSlice();
// }
//
// fn encodeBase10(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     var value = std.math.big.int.Managed.init(allocator);
//     defer value.deinit();
//
//     // Convert bytes to big integer
//     try value.setBytes(input, .big);
//
//     // Handle zero case
//     if (value.eqlZero()) {
//         try result.append('0');
//         return result.toOwnedSlice();
//     }
//
//     // Convert to decimal string
//     while (!value.eqlZero()) {
//         const digit = try value.divFloor(&value, 10);
//         try result.append('0' + @as(u8, @intCast(digit)));
//     }
//
//     // Reverse the result since we built it backwards
//     std.mem.reverse(u8, result.items);
//     return result.toOwnedSlice();
// }
//
// pub fn encodeBase36(allocator: std.mem.Allocator, input: []const u8, upper: bool) ![]u8 {
//     const ALPHABET_LOWER = "0123456789abcdefghijklmnopqrstuvwxyz";
//     const ALPHABET_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
//     const alphabet = if (upper) ALPHABET_UPPER else ALPHABET_LOWER;
//
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     // Convert input bytes to big integer
//     var value = try std.math.big.int.Managed.init(allocator);
//     defer value.deinit();
//
//     try value.setBytes(input, .big);
//
//     // Handle zero case
//     if (value.eqlZero()) {
//         try result.append('0');
//         return result.toOwnedSlice();
//     }
//
//     // Convert to base36
//     while (!value.eqlZero()) {
//         const digit = try value.divFloor(&value, 36);
//         try result.append(alphabet[digit]);
//     }
//
//     // Reverse the result since we built it backwards
//     std.mem.reverse(u8, result.items);
//     return result.toOwnedSlice();
// }
//
// pub fn decodeBase36(allocator: std.mem.Allocator, input: []const u8, upper: bool) ![]u8 {
//     const ALPHABET_LOWER = "0123456789abcdefghijklmnopqrstuvwxyz";
//     const ALPHABET_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
//     const alphabet = if (upper) ALPHABET_UPPER else ALPHABET_LOWER;
//
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     var value = try std.math.big.int.Managed.init(allocator);
//     defer value.deinit();
//
//     for (input) |c| {
//         const digit = std.mem.indexOfScalar(u8, alphabet, c) orelse return Error.InvalidBaseString;
//         try value.mul(&value, 36);
//         try value.add(&value, digit);
//     }
//
//     const bytes = try value.toBytes(allocator, .big);
//     try result.appendSlice(bytes);
//
//     return result.toOwnedSlice();
// }
//
// fn encodeBase256Emoji(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
//     const EMOJI_ALPHABET = "🚀🪐☄🛰🌌🌑🌒🌓🌔🌕🌖🌗🌘🌍🌏🌎🐉☀💻🖥💾💿😂❤😍🤣😊🙏💕😭😘👍😅👏😁🔥🥰💔💖💙😢🤔😆🙄💪😉☺👌🤗💜😔😎😇🌹🤦🎉💞✌✨🤷😱😌🌸🙌😋💗💚😏💛🙂💓🤩😄😀🖤😃💯🙈👇🎶😒🤭❣😜💋👀😪😑💥🙋😞😩😡🤪👊🥳😥🤤👉💃😳✋😚😝😴🌟😬🙃🍀🌷😻😓⭐✅🥺🌈😈🤘💦✔😣🏃💐☹🎊💘😠☝😕🌺🎂🌻😐🖕💝🙊😹🗣💫💀👑🎵🤞😛🔴😤🌼😫⭐🤙☕🏆🤫👈😮🙆🍻🍃🐶💁😲🌿🧡🎁⚡🌞🎈❌✊👋😰🤨😶🤝🚶💰🍓💢🤟🙁🚨💨🤬✈🎀🍺🤓😙💟🌱😖👶🥴▶➡❓💎💸⬇😨🌚🦋😷🕺⚠🙅😟😵👎🤲🤠🤧📌🔵💅🧐🐾🍒😗🤑🌊🤯🐷☎💧😯💆👆🎤🙇🍑❄🌴💣🐸💌📍🥀🤢👅💡💩👐📸👻🤐🤮🎼🥵🚩🍎🍊👼💍📣🥂";
//
//     var result = std.ArrayList(u8).init(allocator);
//     errdefer result.deinit();
//
//     for (input) |byte| {
//         const emoji = EMOJI_ALPHABET[byte];
//         try result.appendSlice(emoji);
//     }
//
//     return result.toOwnedSlice();
// }

const std = @import("std");

pub const DecodeError = error{
    InvalidChar,
};

pub const Base = enum {
    Identity,
    Base2,
    Base8,
    Base10,
    Base16Lower,
    Base16Upper,
    Base32Lower,
    Base32Upper,
    Base32PadLower,
    Base32PadUpper,
    Base32HexLower,
    Base32HexUpper,
    Base32HexPadLower,
    Base32HexPadUpper,
    Base32Z,
    Base36Lower,
    Base36Upper,
    Base58Flickr,
    Base58Btc,
    Base64,
    Base64Pad,
    Base64Url,
    Base64UrlPad,
    Base256Emoji,

    pub fn code(self: Base) []const u8 {
        return switch (self) {
            .Identity => "\x00",
            .Base2 => "0",
            .Base8 => "7",
            .Base10 => "9",
            .Base16Lower => "f",
            .Base16Upper => "F",
            .Base32Lower => "b",
            .Base32Upper => "B",
            .Base32PadLower => "c",
            .Base32PadUpper => "C",
            .Base32HexLower => "v",
            .Base32HexUpper => "V",
            .Base32HexPadLower => "t",
            .Base32HexPadUpper => "T",
            .Base32Z => "h",
            .Base36Lower => "k",
            .Base36Upper => "K",
            .Base58Flickr => "Z",
            .Base58Btc => "z",
            .Base64 => "m",
            .Base64Pad => "M",
            .Base64Url => "u",
            .Base64UrlPad => "U",
            .Base256Emoji => "🚀",
        };
    }

    pub fn encode(self: Base, dest: []u8, source: []const u8) []const u8 {
        const code_str = self.code();
        @memcpy(dest[0..code_str.len], code_str);

        const encoded = switch (self) {
            .Identity => identity.encode(dest[code_str.len..], source),
            .Base2 => base2.encode(dest[code_str.len..], source),
            .Base8 => base8.encode(dest[code_str.len..], source),
            .Base10 => base10.encode(dest[code_str.len..], source),
            .Base16Lower => base16.encodeLower(dest[code_str.len..], source),
            .Base16Upper => base16.encodeUpper(dest[code_str.len..], source),
            .Base32Lower => base32.encode(dest[code_str.len..], source, base32.ALPHABET_LOWER, false),
            .Base32Upper => base32.encode(dest[code_str.len..], source, base32.ALPHABET_UPPER, false),
            .Base32HexLower => base32.encode(dest[code_str.len..], source, base32.ALPHABET_HEX_LOWER, false),
            .Base32HexUpper => base32.encode(dest[code_str.len..], source, base32.ALPHABET_HEX_UPPER, false),
            .Base32PadLower => base32.encode(dest[code_str.len..], source, base32.ALPHABET_LOWER, true),
            .Base32PadUpper => base32.encode(dest[code_str.len..], source, base32.ALPHABET_UPPER, true),
            .Base32HexPadLower => base32.encode(dest[code_str.len..], source, base32.ALPHABET_HEX_LOWER, true),
            .Base32HexPadUpper => base32.encode(dest[code_str.len..], source, base32.ALPHABET_HEX_UPPER, true),
            .Base32Z => base32.encode(dest[code_str.len..], source, base32.ALPHABET_Z, false),
            .Base36Lower => base36.encodeLower(dest[code_str.len..], source),
            .Base36Upper => base36.encodeUpper(dest[code_str.len..], source),
            .Base58Flickr => base58.encodeFlickr(dest[code_str.len..], source),
            .Base58Btc => base58.encodeBtc(dest[code_str.len..], source),
            else => unreachable,
            // Add other encodings
        };

        return dest[0 .. code_str.len + encoded.len];
    }

    pub fn decode(self: Base, dest: []u8, source: []const u8) ![]const u8 {
        return switch (self) {
            .Identity => identity.decode(dest, source),
            .Base2 => base2.decode(dest, source),
            .Base8 => base8.decode(dest, source),
            .Base10 => base10.decode(dest, source),
            .Base16Lower => base16.decode(dest, source),
            .Base16Upper => base16.decode(dest, source),
            .Base32Lower => base32.decode(dest, source, base32.ALPHABET_LOWER),
            .Base32Upper => base32.decode(dest, source, base32.ALPHABET_UPPER),
            .Base32HexLower => base32.decode(dest, source, base32.ALPHABET_HEX_LOWER),
            .Base32HexUpper => base32.decode(dest, source, base32.ALPHABET_HEX_UPPER),
            .Base32PadLower => base32.decode(dest, source, base32.ALPHABET_LOWER),
            .Base32PadUpper => base32.decode(dest, source, base32.ALPHABET_UPPER),
            .Base32HexPadLower => base32.decode(dest, source, base32.ALPHABET_HEX_LOWER),
            .Base32HexPadUpper => base32.decode(dest, source, base32.ALPHABET_HEX_UPPER),
            .Base32Z => base32.decode(dest, source, base32.ALPHABET_Z),
            .Base36Lower => base36.decode(dest, source, base36.ALPHABET_LOWER),
            .Base36Upper => base36.decode(dest, source, base36.ALPHABET_UPPER),
            .Base58Flickr => base58.decodeFlickr(dest, source),
            .Base58Btc => base58.decodeBtc(dest, source),
            else => unreachable,
            // Add other decodings
        };
    }

    const identity = struct {
        pub fn encode(dest: []u8, source: []const u8) []const u8 {
            @memcpy(dest[0..source.len], source);
            return dest[0..source.len];
        }

        pub fn decode(dest: []u8, source: []const u8) ![]const u8 {
            @memcpy(dest[0..source.len], source);
            return dest[0..source.len];
        }
    };

    const base2 = struct {
        pub fn encode(dest: []u8, source: []const u8) []const u8 {
            var dest_index: usize = 0;
            for (source) |byte| {
                var i: u3 = 7;
                while (true) {
                    dest[dest_index] = '0' + @as(u8, @truncate((byte >> i) & 1));
                    dest_index += 1;
                    if (i == 0) break;
                    i -= 1;
                }
            }
            return dest[0..dest_index];
        }

        pub fn decode(dest: []u8, source: []const u8) ![]const u8 {
            var dest_index: usize = 0;
            var current_byte: u8 = 0;
            var bits: u4 = 0;

            for (source) |c| {
                current_byte = (current_byte << 1) | (c - '0');
                bits += 1;
                if (bits == 8) {
                    dest[dest_index] = current_byte;
                    dest_index += 1;
                    bits = 0;
                    current_byte = 0;
                }
            }
            if (bits > 0) {
                dest[dest_index] = current_byte << @as(u3, @intCast(8 - bits));
                dest_index += 1;
            }
            return dest[0..dest_index];
        }
    };

    const base8 = struct {
        pub fn encode(dest: []u8, source: []const u8) []const u8 {
            var dest_index: usize = 0;
            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (source) |byte| {
                bits = (bits << 8) | byte;
                bit_count += 8;

                while (bit_count >= 3) {
                    bit_count -= 3;
                    const index = (bits >> bit_count) & 0x7;
                    dest[dest_index] = '0' + @as(u8, @truncate(index));
                    dest_index += 1;
                }
            }

            if (bit_count > 0) {
                const index = (bits << (3 - bit_count)) & 0x7;
                dest[dest_index] = '0' + @as(u8, @truncate(index));
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn decode(dest: []u8, source: []const u8) DecodeError![]const u8 {
            var dest_index: usize = 0;
            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (source) |c| {
                if (c < '0' or c > '7') return DecodeError.InvalidChar;

                bits = (bits << 3) | (c - '0');
                bit_count += 3;

                if (bit_count >= 8) {
                    bit_count -= 8;
                    dest[dest_index] = @truncate(bits >> bit_count);
                    dest_index += 1;
                }
            }

            return dest[0..dest_index];
        }
    };

    const base10 = struct {
        pub fn encode(dest: []u8, source: []const u8) []const u8 {
            if (source.len == 0) {
                dest[0] = '0';
                return dest[0..1];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Count leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == 0) {
                leading_zeros += 1;
            }

            // Add leading zeros to output
            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = '0';
                dest_index += 1;
            }

            // Convert bytes to decimal
            for (source) |byte| {
                var carry: u16 = byte;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) << 8;
                    }
                    num[j] = @truncate(carry % 10);
                    carry /= 10;
                }
                num_len = j;
            }

            // Convert to ASCII and reverse
            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = '0' + num[i - 1];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn decode(dest: []u8, source: []const u8) DecodeError![]const u8 {
            if (source.len == 0) {
                return dest[0..0];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Count leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == '0') {
                leading_zeros += 1;
            }

            // Add leading zeros to output
            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = 0;
                dest_index += 1;
            }

            // Convert decimal to bytes
            for (source) |c| {
                if (c < '0' or c > '9') return DecodeError.InvalidChar;

                var carry: u16 = c - '0';
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) * 10;
                    }
                    num[j] = @truncate(carry);
                    carry >>= 8;
                }
                num_len = j;
            }

            // Copy and reverse
            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = num[i - 1];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }
    };

    const base16 = struct {
        const ALPHABET_LOWER = "0123456789abcdef";
        const ALPHABET_UPPER = "0123456789ABCDEF";

        pub fn encodeLower(dest: []u8, source: []const u8) []const u8 {
            var dest_index: usize = 0;
            for (source) |byte| {
                dest[dest_index] = ALPHABET_LOWER[byte >> 4];
                dest[dest_index + 1] = ALPHABET_LOWER[byte & 0x0F];
                dest_index += 2;
            }
            return dest[0..dest_index];
        }

        pub fn encodeUpper(dest: []u8, source: []const u8) []const u8 {
            var dest_index: usize = 0;
            for (source) |byte| {
                dest[dest_index] = ALPHABET_UPPER[byte >> 4];
                dest[dest_index + 1] = ALPHABET_UPPER[byte & 0x0F];
                dest_index += 2;
            }
            return dest[0..dest_index];
        }

        pub fn decode(dest: []u8, source: []const u8) DecodeError![]const u8 {
            if (source.len % 2 != 0) return DecodeError.InvalidChar;

            var dest_index: usize = 0;
            var i: usize = 0;
            while (i < source.len) : (i += 2) {
                const high = try decodeChar(source[i]);
                const low = try decodeChar(source[i + 1]);
                dest[dest_index] = (high << 4) | low;
                dest_index += 1;
            }
            return dest[0..dest_index];
        }

        fn decodeChar(c: u8) DecodeError!u8 {
            return switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => DecodeError.InvalidChar,
            };
        }
    };

    const base32 = struct {
        const ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz234567";
        const ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const ALPHABET_HEX_LOWER = "0123456789abcdefghijklmnopqrstuv";
        const ALPHABET_HEX_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
        const ALPHABET_Z = "ybndrfg8ejkmcpqxot1uwisza345h769";
        const PADDING = '=';

        pub fn encode(dest: []u8, source: []const u8, alphabet: []const u8, pad: bool) []const u8 {
            var dest_index: usize = 0;
            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (source) |byte| {
                bits = (bits << 8) | byte;
                bit_count += 8;

                while (bit_count >= 5) {
                    bit_count -= 5;
                    const index = (bits >> bit_count) & 0x1F;
                    dest[dest_index] = alphabet[index];
                    dest_index += 1;
                }
            }

            if (bit_count > 0) {
                const index = (bits << (5 - bit_count)) & 0x1F;
                dest[dest_index] = alphabet[index];
                dest_index += 1;
            }

            if (pad) {
                const padding = (8 - dest_index % 8) % 8;
                var i: usize = 0;
                while (i < padding) : (i += 1) {
                    dest[dest_index] = PADDING;
                    dest_index += 1;
                }
            }

            return dest[0..dest_index];
        }

        pub fn decode(dest: []u8, source: []const u8, alphabet: []const u8) DecodeError![]const u8 {
            var dest_index: usize = 0;
            var bits: u16 = 0;
            var bit_count: u4 = 0;

            for (source) |c| {
                if (c == PADDING) continue;

                const value = indexOf(alphabet, c) orelse return DecodeError.InvalidChar;
                bits = (bits << 5) | value;
                bit_count += 5;

                if (bit_count >= 8) {
                    bit_count -= 8;
                    dest[dest_index] = @truncate(bits >> bit_count);
                    dest_index += 1;
                }
            }

            return dest[0..dest_index];
        }

        fn indexOf(alphabet: []const u8, c: u8) ?u8 {
            for (alphabet, 0..) |char, i| {
                if (char == c) return @truncate(i);
            }
            return null;
        }
    };

    const base36 = struct {
        const ALPHABET_LOWER = "0123456789abcdefghijklmnopqrstuvwxyz";
        const ALPHABET_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        pub fn encodeLower(dest: []u8, source: []const u8) []const u8 {
            if (source.len == 0) {
                dest[0] = '0';
                return dest[0..1];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == 0) {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = '0';
                dest_index += 1;
            }

            // Convert bytes to base36
            for (source) |byte| {
                var carry: u16 = byte;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) << 8;
                    }
                    num[j] = @truncate(carry % 36);
                    carry /= 36;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = ALPHABET_LOWER[num[i - 1]];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn encodeUpper(dest: []u8, source: []const u8) []const u8 {
            if (source.len == 0) {
                dest[0] = '0';
                return dest[0..1];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == 0) {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = '0';
                dest_index += 1;
            }

            // Convert bytes to base36
            for (source) |byte| {
                var carry: u16 = byte;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) << 8;
                    }
                    num[j] = @truncate(carry % 36);
                    carry /= 36;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = ALPHABET_UPPER[num[i - 1]];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn decode(dest: []u8, source: []const u8, alphabet: []const u8) DecodeError![]const u8 {
            if (source.len == 0) {
                return dest[0..0];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == '0') {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = 0;
                dest_index += 1;
            }

            // Convert base36 to bytes
            for (source) |c| {
                const value = indexOf(alphabet, c) orelse return DecodeError.InvalidChar;
                var carry: u16 = value;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) * 36;
                    }
                    num[j] = @truncate(carry);
                    carry >>= 8;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = num[i - 1];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        fn indexOf(alphabet: []const u8, c: u8) ?u8 {
            for (alphabet, 0..) |char, i| {
                if (char == c) return @truncate(i);
            }
            return null;
        }
    };

    const base58 = struct {
        const ALPHABET_FLICKR = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
        const ALPHABET_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        pub fn encodeBtc(dest: []u8, source: []const u8) []const u8 {
            if (source.len == 0) {
                dest[0] = ALPHABET_BTC[0];
                return dest[0..1];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == 0) {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = ALPHABET_BTC[0];
                dest_index += 1;
            }

            // Convert bytes to base58
            for (source) |byte| {
                var carry: u16 = byte;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) << 8;
                    }
                    num[j] = @truncate(carry % 58);
                    carry /= 58;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = ALPHABET_BTC[num[i - 1]];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn encodeFlickr(dest: []u8, source: []const u8) []const u8 {
            if (source.len == 0) {
                dest[0] = ALPHABET_FLICKR[0];
                return dest[0..1];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == 0) {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = ALPHABET_FLICKR[0];
                dest_index += 1;
            }

            // Convert bytes to base58
            for (source) |byte| {
                var carry: u16 = byte;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) << 8;
                    }
                    num[j] = @truncate(carry % 58);
                    carry /= 58;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = ALPHABET_FLICKR[num[i - 1]];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn decodeBtc(dest: []u8, source: []const u8) DecodeError![]const u8 {
            if (source.len == 0) {
                return dest[0..0];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == ALPHABET_BTC[0]) {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = 0;
                dest_index += 1;
            }

            // Convert base58 to bytes
            for (source) |c| {
                const value = indexOf(ALPHABET_BTC, c) orelse return DecodeError.InvalidChar;
                var carry: u16 = value;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) * 58;
                    }
                    num[j] = @truncate(carry);
                    carry >>= 8;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = num[i - 1];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        pub fn decodeFlickr(dest: []u8, source: []const u8) DecodeError![]const u8 {
            if (source.len == 0) {
                return dest[0..0];
            }

            var dest_index: usize = 0;
            var num: [1024]u8 = undefined;
            var num_len: usize = 0;

            // Handle leading zeros
            var leading_zeros: usize = 0;
            while (leading_zeros < source.len and source[leading_zeros] == ALPHABET_FLICKR[0]) {
                leading_zeros += 1;
            }

            while (leading_zeros > 0) : (leading_zeros -= 1) {
                dest[dest_index] = 0;
                dest_index += 1;
            }

            // Convert base58 to bytes
            for (source) |c| {
                const value = indexOf(ALPHABET_FLICKR, c) orelse return DecodeError.InvalidChar;
                var carry: u16 = value;
                var j: usize = 0;
                while (j < num_len or carry > 0) : (j += 1) {
                    if (j < num_len) {
                        carry += @as(u16, num[j]) * 58;
                    }
                    num[j] = @truncate(carry);
                    carry >>= 8;
                }
                num_len = j;
            }

            var i: usize = num_len;
            while (i > 0) : (i -= 1) {
                dest[dest_index] = num[i - 1];
                dest_index += 1;
            }

            return dest[0..dest_index];
        }

        fn indexOf(alphabet: []const u8, c: u8) ?u8 {
            for (alphabet, 0..) |char, i| {
                if (char == c) return @truncate(i);
            }
            return null;
        }
    };
};

test "Base.encode/decode base2" {
    const testing = std.testing;
    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base2.encode(dest[0..], source);
        try testing.expectEqualStrings("0000000000000000001111001011001010111001100100000011011010110000101101110011010010010000000100001", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "0000000000000000001111001011001010111001100100000011011010110000101101110011010010010000000100001";
        const decoded = try Base.Base2.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base2.encode(dest[0..], source);
        try testing.expectEqualStrings("00000000001111001011001010111001100100000011011010110000101101110011010010010000000100001", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "00000000001111001011001010111001100100000011011010110000101101110011010010010000000100001";
        const decoded = try Base.Base2.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base2.encode(dest[0..], source);
        try testing.expectEqualStrings("001111001011001010111001100100000011011010110000101101110011010010010000000100001", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "001111001011001010111001100100000011011010110000101101110011010010010000000100001";
        const decoded = try Base.Base2.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }
}

test "Base.encode/decode identity" {
    const testing = std.testing;

    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Identity.encode(dest[0..], source);
        try testing.expectEqualStrings("\x00yes mani !", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const decoded = try Base.Identity.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Identity.encode(dest[0..], source);
        try testing.expectEqualStrings("\x00\x00yes mani !", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const decoded = try Base.Identity.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Identity.encode(dest[0..], source);
        try testing.expectEqualStrings("\x00\x00\x00yes mani !", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00\x00yes mani !";
        const decoded = try Base.Identity.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}

test "Base.encode/decode base8" {
    const testing = std.testing;
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base8.encode(dest[0..], source);
        try testing.expectEqualStrings("7362625631006654133464440102", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "7362625631006654133464440102";
        const decoded = try Base.Base8.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base8.encode(dest[0..], source);
        try testing.expectEqualStrings("7000745453462015530267151100204", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "7000745453462015530267151100204";
        const decoded = try Base.Base8.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base8.encode(dest[0..], source);
        try testing.expectEqualStrings("700000171312714403326055632220041", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "700000171312714403326055632220041";
        const decoded = try Base.Base8.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}

test "Base.encode/decode base10" {
    const testing = std.testing;

    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base10.encode(dest[0..], source);
        try testing.expectEqualStrings("9573277761329450583662625", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "9573277761329450583662625";
        const decoded = try Base.Base10.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base10.encode(dest[0..], source);
        try testing.expectEqualStrings("90573277761329450583662625", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "90573277761329450583662625";
        const decoded = try Base.Base10.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base10.encode(dest[0..], source);
        try testing.expectEqualStrings("900573277761329450583662625", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "900573277761329450583662625";
        const decoded = try Base.Base10.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}

test "Base.encode/decode base16" {
    const testing = std.testing;

    // Test Base16Lower
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base16Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("f796573206d616e692021", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "f796573206d616e692021";
        const decoded = try Base.Base16Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base16Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("f00796573206d616e692021", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "f00796573206d616e692021";
        const decoded = try Base.Base16Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base16Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("f0000796573206d616e692021", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "f0000796573206d616e692021";
        const decoded = try Base.Base16Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base16Upper
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base16Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("F796573206D616E692021", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "F796573206D616E692021";
        const decoded = try Base.Base16Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base16Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("F00796573206D616E692021", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "F00796573206D616E692021";
        const decoded = try Base.Base16Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base16Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("F0000796573206D616E692021", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "F0000796573206D616E692021";
        const decoded = try Base.Base16Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}

test "Base.encode/decode base32" {
    const testing = std.testing;

    // Test Base32Lower
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("bpfsxgidnmfxgsibb", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "bpfsxgidnmfxgsibb";
        const decoded = try Base.Base32Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("bab4wk4zanvqw42jaee", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "bab4wk4zanvqw42jaee";
        const decoded = try Base.Base32Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("baaahszltebwwc3tjeaqq", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "baaahszltebwwc3tjeaqq";
        const decoded = try Base.Base32Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32Upper
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("BPFSXGIDNMFXGSIBB", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "BPFSXGIDNMFXGSIBB";
        const decoded = try Base.Base32Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("BAB4WK4ZANVQW42JAEE", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "BAB4WK4ZANVQW42JAEE";
        const decoded = try Base.Base32Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("BAAAHSZLTEBWWC3TJEAQQ", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "BAAAHSZLTEBWWC3TJEAQQ";
        const decoded = try Base.Base32Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32HexLower
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32HexLower.encode(dest[0..], source);
        try testing.expectEqualStrings("vf5in683dc5n6i811", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "vf5in683dc5n6i811";
        const decoded = try Base.Base32HexLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32HexLower.encode(dest[0..], source);
        try testing.expectEqualStrings("v01smasp0dlgmsq9044", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "v01smasp0dlgmsq9044";
        const decoded = try Base.Base32HexLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32HexLower.encode(dest[0..], source);
        try testing.expectEqualStrings("v0007ipbj41mm2rj940gg", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "v0007ipbj41mm2rj940gg";
        const decoded = try Base.Base32HexLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32HexUpper
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32HexUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("VF5IN683DC5N6I811", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "VF5IN683DC5N6I811";
        const decoded = try Base.Base32HexUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32HexUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("V01SMASP0DLGMSQ9044", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "V01SMASP0DLGMSQ9044";
        const decoded = try Base.Base32HexUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32HexUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("V0007IPBJ41MM2RJ940GG", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "V0007IPBJ41MM2RJ940GG";
        const decoded = try Base.Base32HexUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32PadLower
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32PadLower.encode(dest[0..], source);
        try testing.expectEqualStrings("cpfsxgidnmfxgsibb", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "cpfsxgidnmfxgsibb";
        const decoded = try Base.Base32PadLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32PadLower.encode(dest[0..], source);
        try testing.expectEqualStrings("cab4wk4zanvqw42jaee======", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "cab4wk4zanvqw42jaee======";
        const decoded = try Base.Base32PadLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32PadLower.encode(dest[0..], source);
        try testing.expectEqualStrings("caaahszltebwwc3tjeaqq====", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "caaahszltebwwc3tjeaqq====";
        const decoded = try Base.Base32PadLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32PadUpper
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32PadUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("CPFSXGIDNMFXGSIBB", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "CPFSXGIDNMFXGSIBB";
        const decoded = try Base.Base32PadUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32PadUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("CAB4WK4ZANVQW42JAEE======", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "CAB4WK4ZANVQW42JAEE======";
        const decoded = try Base.Base32PadUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32PadUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("CAAAHSZLTEBWWC3TJEAQQ====", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "CAAAHSZLTEBWWC3TJEAQQ====";
        const decoded = try Base.Base32PadUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32HexPadLower
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32HexPadLower.encode(dest[0..], source);
        try testing.expectEqualStrings("tf5in683dc5n6i811", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "tf5in683dc5n6i811";
        const decoded = try Base.Base32HexPadLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32HexPadLower.encode(dest[0..], source);
        try testing.expectEqualStrings("t01smasp0dlgmsq9044======", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "t01smasp0dlgmsq9044======";
        const decoded = try Base.Base32HexPadLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32HexPadLower.encode(dest[0..], source);
        try testing.expectEqualStrings("t0007ipbj41mm2rj940gg====", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "t0007ipbj41mm2rj940gg====";
        const decoded = try Base.Base32HexPadLower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32HexPadUpper
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32HexPadUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("TF5IN683DC5N6I811", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "TF5IN683DC5N6I811";
        const decoded = try Base.Base32HexPadUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32HexPadUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("T01SMASP0DLGMSQ9044======", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "T01SMASP0DLGMSQ9044======";
        const decoded = try Base.Base32HexPadUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32HexPadUpper.encode(dest[0..], source);
        try testing.expectEqualStrings("T0007IPBJ41MM2RJ940GG====", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "T0007IPBJ41MM2RJ940GG====";
        const decoded = try Base.Base32HexPadUpper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base32Z
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base32Z.encode(dest[0..], source);
        try testing.expectEqualStrings("hxf1zgedpcfzg1ebb", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "hxf1zgedpcfzg1ebb";
        const decoded = try Base.Base32Z.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base32Z.encode(dest[0..], source);
        try testing.expectEqualStrings("hybhskh3ypiosh4jyrr", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "hybhskh3ypiosh4jyrr";
        const decoded = try Base.Base32Z.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base32Z.encode(dest[0..], source);
        try testing.expectEqualStrings("hyyy813murbssn5ujryoo", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "hyyy813murbssn5ujryoo";
        const decoded = try Base.Base32Z.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}

test "Base.encode/decode base36" {
    const testing = std.testing;

    // Test Base36Lower
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base36Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("k2lcpzo5yikidynfl", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "k2lcpzo5yikidynfl";
        const decoded = try Base.Base36Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base36Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("k02lcpzo5yikidynfl", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "k02lcpzo5yikidynfl";
        const decoded = try Base.Base36Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base36Lower.encode(dest[0..], source);
        try testing.expectEqualStrings("k002lcpzo5yikidynfl", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "k002lcpzo5yikidynfl";
        const decoded = try Base.Base36Lower.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base36Upper
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base36Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("K2LCPZO5YIKIDYNFL", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "K2LCPZO5YIKIDYNFL";
        const decoded = try Base.Base36Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base36Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("K02LCPZO5YIKIDYNFL", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "K02LCPZO5YIKIDYNFL";
        const decoded = try Base.Base36Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base36Upper.encode(dest[0..], source);
        try testing.expectEqualStrings("K002LCPZO5YIKIDYNFL", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "K002LCPZO5YIKIDYNFL";
        const decoded = try Base.Base36Upper.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}

test "Base.encode/decode base58" {
    const testing = std.testing;

    // Test Base58Btc
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base58Btc.encode(dest[0..], source);
        try testing.expectEqualStrings("z7paNL19xttacUY", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "z7paNL19xttacUY";
        const decoded = try Base.Base58Btc.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base58Btc.encode(dest[0..], source);
        try testing.expectEqualStrings("z17paNL19xttacUY", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "z17paNL19xttacUY";
        const decoded = try Base.Base58Btc.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base58Btc.encode(dest[0..], source);
        try testing.expectEqualStrings("z117paNL19xttacUY", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "z117paNL19xttacUY";
        const decoded = try Base.Base58Btc.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }

    // Test Base58Flickr
    {
        var dest: [256]u8 = undefined;
        const source = "yes mani !";
        const encoded = Base.Base58Flickr.encode(dest[0..], source);
        try testing.expectEqualStrings("Z7Pznk19XTTzBtx", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "Z7Pznk19XTTzBtx";
        const decoded = try Base.Base58Flickr.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00yes mani !";
        const encoded = Base.Base58Flickr.encode(dest[0..], source);
        try testing.expectEqualStrings("Z17Pznk19XTTzBtx", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "Z17Pznk19XTTzBtx";
        const decoded = try Base.Base58Flickr.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00yes mani !", decoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "\x00\x00yes mani !";
        const encoded = Base.Base58Flickr.encode(dest[0..], source);
        try testing.expectEqualStrings("Z117Pznk19XTTzBtx", encoded);
    }

    {
        var dest: [256]u8 = undefined;
        const source = "Z117Pznk19XTTzBtx";
        const decoded = try Base.Base58Flickr.decode(dest[0..], source[1..]);
        try testing.expectEqualStrings("\x00\x00yes mani !", decoded);
    }
}
