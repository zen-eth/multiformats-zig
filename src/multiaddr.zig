const std = @import("std");
const testing = std.testing;
const uvarint = @import("unsigned_varint.zig");

pub const Error = error{
    DataLessThanLen,
    InvalidMultiaddr,
    InvalidProtocolString,
    InvalidUvar,
    ParsingError,
    UnknownProtocolId,
    UnknownProtocolString,
};

// Protocol code constants
const DCCP: u32 = 33;
const DNS: u32 = 53;
const DNS4: u32 = 54;
const DNS6: u32 = 55;
const DNSADDR: u32 = 56;
const HTTP: u32 = 480;
const HTTPS: u32 = 443;
const IP4: u32 = 4;
const IP6: u32 = 41;
const TCP: u32 = 6;
const UDP: u32 = 273;
const UTP: u32 = 302;
const UNIX: u32 = 400;
const P2P: u32 = 421;
const ONION: u32 = 444;
const ONION3: u32 = 445;
const QUIC: u32 = 460;
const WS: u32 = 477;
const WSS: u32 = 478;
pub const Protocol = union(enum) {
    Dccp: u16,
    Dns: []const u8,
    Dns4: []const u8,
    Dns6: []const u8,
    Dnsaddr: []const u8,
    Http,
    Https,
    Ip4: std.net.Ip4Address,
    Ip6: std.net.Ip6Address,
    Tcp: u16,
    Udp: u16,  // Added UDP protocol

    pub fn tag(self: Protocol) []const u8 {
        return switch (self) {
            .Dccp => "dccp",
            .Dns => "dns",
            .Dns4 => "dns4",
            .Dns6 => "dns6",
            .Dnsaddr => "dnsaddr",
            .Http => "http",
            .Https => "https",
            .Ip4 => "ip4",
            .Ip6 => "ip6",
            .Tcp => "tcp",
            .Udp => "udp",
        };
    }

    pub fn fromBytes(bytes: []const u8) !struct { proto: Protocol, rest: []const u8 } {
        if (bytes.len < 1) return Error.DataLessThanLen;

        const decoded = try uvarint.decode(u32, bytes);
        const id = decoded.value;
        var rest = decoded.remaining;

        return switch (id) {
            4 => { // IP4
                if (rest.len < 4) return Error.DataLessThanLen;
                const addr = std.net.Ip4Address.init(rest[0..4].*, 0);
                return .{ .proto = .{ .Ip4 = addr }, .rest = rest[4..] };
            },
            6 => { // TCP
                if (rest.len < 2) return Error.DataLessThanLen;
                const port = std.mem.readInt(u16, rest[0..2], .big);
                return .{ .proto = .{ .Tcp = port }, .rest = rest[2..] };
            },
            else => Error.UnknownProtocolId,
        };
    }    pub fn writeBytes(self: Protocol, writer: anytype) !void {
        switch (self) {
            .Ip4 => |addr| {
                _ = try uvarint.encode_stream(writer, u32, IP4);
                const bytes = std.mem.asBytes(&addr.sa.addr);
                try writer.writeAll(bytes);
            },
            .Tcp => |port| {
                _ = try uvarint.encode_stream(writer, u32, TCP);
                var port_bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &port_bytes, port, .big);
                try writer.writeAll(&port_bytes);
            },
            .Udp => |port| {
                _ = try uvarint.encode_stream(writer, u32, UDP);
                var port_bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &port_bytes, port, .big);
                try writer.writeAll(&port_bytes);
            },
            // Temporary catch-all case
            else => {},
        }
    }

    pub fn toString(self: Protocol) []const u8 {
        return switch (self) {
            .Dccp => "dccp",
            .Dns => "dns",
            .Dns4 => "dns4",
            .Dns6 => "dns6",
            .Dnsaddr => "dnsaddr",
            .Http => "http",
            .Https => "https",
            .Ip4 => "ip4",
            .Ip6 => "ip6",
            .Tcp => "tcp",
            .Udp => "udp",
        };
    }
};

pub const Onion3Addr = struct {
    hash: [35]u8,
    port: u16,

    pub fn init(hash: [35]u8, port: u16) Onion3Addr {
        return .{
            .hash = hash,
            .port = port,
        };
    }
};

pub const Multiaddr = struct {
    bytes: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Multiaddr {
        return .{
            .bytes = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Multiaddr) void {
        self.bytes.deinit();
    }

    pub fn len(self: Multiaddr) usize {
        return self.bytes.items.len;
    }

    pub fn isEmpty(self: Multiaddr) bool {
        return self.bytes.items.len == 0;
    }

    pub fn toSlice(self: Multiaddr, allocator: std.mem.Allocator) ![]u8 {
        const vec = try allocator.alloc(u8, self.bytes.items.len);
        @memcpy(vec, self.bytes.items);
        return vec;
    }

    pub fn startsWith(self: Multiaddr, other: Multiaddr) bool {
        if (self.bytes.items.len < other.bytes.items.len) return false;
        return std.mem.eql(u8, self.bytes.items[0..other.bytes.items.len], other.bytes.items);
    }

    pub fn endsWith(self: Multiaddr, other: Multiaddr) bool {
        if (self.bytes.items.len < other.bytes.items.len) return false;
        const start = self.bytes.items.len - other.bytes.items.len;
        return std.mem.eql(u8, self.bytes.items[start..], other.bytes.items);
    }

    pub fn push(self: *Multiaddr, p: Protocol) !void {
        try p.writeBytes(self.bytes.writer());
    }

    pub fn pop(self: *Multiaddr) !?Protocol {
        if (self.bytes.items.len == 0) return null;

        // Find the start of the last protocol
        var offset: usize = 0;
        var last_start: usize = 0;
        var rest:[]const u8 = self.bytes.items;

        while (rest.len > 0) {
            const decoded = try Protocol.fromBytes(rest);
            if (decoded.rest.len == 0) {
                // This is the last protocol
                const result = decoded.proto;
                self.bytes.shrinkRetainingCapacity(last_start);
                return result;
            }
            last_start = offset + (rest.len - decoded.rest.len);
            offset += rest.len - decoded.rest.len;
            rest = decoded.rest;
        }

        return Error.InvalidMultiaddr;
    }

    pub fn toString(self: Multiaddr, allocator: std.mem.Allocator) ![]u8 {
        var result = std.ArrayList(u8).init(allocator);
        errdefer result.deinit();

        var rest_bytes: []const u8 = self.bytes.items;
        while (rest_bytes.len > 0) {
            const decoded = try Protocol.fromBytes(rest_bytes);
            switch (decoded.proto) {
                .Ip4 => |addr| {
                    const bytes = @as([4]u8, @bitCast(addr.sa.addr));
                    try result.writer().print("/ip4/{}.{}.{}.{}", .{
                        bytes[0], bytes[1], bytes[2], bytes[3]
                    });
                },
                .Tcp => |port| try result.writer().print("/tcp/{}", .{port}),
                else => try result.writer().print("/{s}", .{@tagName(@as(@TypeOf(decoded.proto), decoded.proto))}),
            }
            rest_bytes = decoded.rest;
        }

        return result.toOwnedSlice();
    }

    pub fn fromString(allocator: std.mem.Allocator, s: []const u8) !Multiaddr {
        var ma = Multiaddr.init(allocator);
        errdefer ma.deinit();

        var parts = std.mem.splitScalar(u8, s, '/');
        const first = parts.first();
        if (first.len != 0) return Error.InvalidMultiaddr;

        while (parts.next()) |part| {
            if (part.len == 0) continue;

            const proto = try parseProtocol(&parts, part);
            try ma.push(proto);
        }

        return ma;
    }

    fn parseProtocol(parts: *std.mem.SplitIterator(u8, .scalar), proto_name: []const u8) !Protocol {
        return switch (std.meta.stringToEnum(enum { ip4, tcp, udp, dns, dns4, dns6, http, https, ws, wss, p2p, unix }, proto_name) orelse return Error.UnknownProtocolString) {
            .ip4 => blk: {
                const addr_str = parts.next() orelse return Error.InvalidProtocolString;
                var addr: [4]u8 = undefined;
                try parseIp4(addr_str, &addr);
                break :blk Protocol{ .Ip4 = std.net.Ip4Address.init(addr, 0) };
            },
            .tcp, .udp => blk: {
                const port_str = parts.next() orelse return Error.InvalidProtocolString;
                const port = try std.fmt.parseInt(u16, port_str, 10);
                break :blk if (proto_name[0] == 't')
                    Protocol{ .Tcp = port }
                else
                    Protocol{ .Udp = port };
            },
            // Add other protocol parsing as needed
            else => Error.UnknownProtocolString,
        };
    }

    fn parseIp4(s: []const u8, out: *[4]u8) !void {
        var it = std.mem.splitScalar(u8, s, '.');
        var i: usize = 0;
        while (it.next()) |num_str| : (i += 1) {
            if (i >= 4) return Error.InvalidProtocolString;
            out[i] = try std.fmt.parseInt(u8, num_str, 10);
        }
        if (i != 4) return Error.InvalidProtocolString;
    }

};

pub fn empty() Multiaddr {
    return Multiaddr.init(std.heap.page_allocator);
}

pub fn withCapacity(allocator: std.mem.Allocator, capacity: usize) Multiaddr {
    var ma = Multiaddr.init(allocator);
    ma.bytes.ensureTotalCapacity(capacity) catch unreachable;
    return ma;
}

test "multiaddr push and pop" {
    var ma = Multiaddr.init(testing.allocator);
    defer ma.deinit();

    const ip4 = Protocol{ .Ip4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 0) };
    const tcp = Protocol{ .Tcp = 8080 };

    try ma.push(ip4);
    std.debug.print("\nAfter IP4 push, buffer: ", .{});
    for (ma.bytes.items) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }

    try ma.push(tcp);
    std.debug.print("\nAfter TCP push, buffer: ", .{});
    for (ma.bytes.items) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }

    const popped_tcp = try ma.pop();
    std.debug.print("\nAfter TCP pop, buffer: ", .{});
    for (ma.bytes.items) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\nPopped TCP: {any}", .{popped_tcp});

    const popped_ip4 = try ma.pop();
    std.debug.print("\nAfter IP4 pop, buffer: ", .{});
    for (ma.bytes.items) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\nPopped IP4: {any}", .{popped_ip4});

    try testing.expectEqual(tcp, popped_tcp.?);
    try testing.expectEqual(ip4, popped_ip4.?);
    try testing.expectEqual(@as(?Protocol, null), try ma.pop());
}

test "basic multiaddr creation" {
    var ma = Multiaddr.init(testing.allocator);
    defer ma.deinit();

    try testing.expect(ma.bytes.items.len == 0);
}

test "onion3addr basics" {
    const hash = [_]u8{1} ** 35;
    const addr = Onion3Addr.init(hash, 1234);

    try testing.expectEqual(@as(u16, 1234), addr.port);
    try testing.expectEqualSlices(u8, &hash, &addr.hash);
}

test "multiaddr empty" {
    var ma = Multiaddr.init(testing.allocator);
    defer ma.deinit();

    try testing.expect(ma.bytes.items.len == 0);
}

test "protocol encoding/decoding" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    const ip4 = Protocol{ .Ip4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 0) };
    try ip4.writeBytes(writer);

    const decoded = try Protocol.fromBytes(fbs.getWritten());
    try testing.expect(decoded.proto == .Ip4);
}

test "multiaddr from string" {
    const cases = .{
        "/ip4/127.0.0.1/tcp/8080",
        "/ip4/127.0.0.1",
        "/tcp/8080",
    };

    inline for (cases) |case| {
        var ma = try Multiaddr.fromString(testing.allocator, case);
        defer ma.deinit();

        const str = try ma.toString(testing.allocator);
        defer testing.allocator.free(str);

        try testing.expectEqualStrings(case, str);
    }
}

test "debug protocol bytes" {
    var ma = Multiaddr.init(testing.allocator);
    defer ma.deinit();

    const ip4 = Protocol{ .Ip4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 0) };
    try ma.push(ip4);

    std.debug.print("\nBuffer contents: ", .{});
    for (ma.bytes.items) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\n", .{});
}

test "debug tcp write" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const tcp = Protocol{ .Tcp = 8080 };
    try tcp.writeBytes(fbs.writer());

    std.debug.print("\nTCP write buffer: ", .{});
    for (buf[0..fbs.pos]) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\n", .{});
}

test "multiaddr basic operations" {
    var ma = empty();
    defer ma.deinit();
    try testing.expect(ma.isEmpty());
    try testing.expectEqual(@as(usize, 0), ma.len());

    var ma_cap = withCapacity(testing.allocator, 32);
    defer ma_cap.deinit();
    try testing.expect(ma_cap.isEmpty());

    const ip4 = Protocol{ .Ip4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 0) };
    try ma_cap.push(ip4);
    try testing.expect(!ma_cap.isEmpty());

    const vec = try ma_cap.toSlice(testing.allocator);
    defer testing.allocator.free(vec);
    try testing.expectEqualSlices(u8, ma_cap.bytes.items, vec);
}

test "multiaddr starts and ends with" {
    var ma1 = Multiaddr.init(testing.allocator);
    defer ma1.deinit();
    var ma2 = Multiaddr.init(testing.allocator);
    defer ma2.deinit();

    const ip4 = Protocol{ .Ip4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 0) };
    const tcp = Protocol{ .Tcp = 8080 };

    try ma1.push(ip4);
    try ma1.push(tcp);
    try ma2.push(ip4);

    try testing.expect(ma1.startsWith(ma2));
    try ma2.push(tcp);
    try testing.expect(ma1.endsWith(ma2));
}

test "protocol tag strings" {
    const p1 = Protocol{ .Dccp = 1234 };
    try testing.expectEqualStrings("Dccp", @tagName(@as(@TypeOf(p1), p1)));

    const p2 = Protocol.Http;
    try testing.expectEqualStrings("Http", @tagName(@as(@TypeOf(p2), p2)));
}
