//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;
const multicodec = @import("multicodec.zig");
const multihash_impls = @import("multihash.zig");
const unsigned_varint = @import("unsigned_varint.zig");
const multibase = @import("multibase.zig");
const multiaddr = @import("multiaddr.zig");
const cid = @import("cid.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
    _ = @import("unsigned_varint.zig");
    _ = @import("multicodec.zig");
    _ = @import("multihash.zig");
    _ = @import("multibase.zig");
    _ = @import("multiaddr.zig");
    _ = @import("cid.zig");
}
