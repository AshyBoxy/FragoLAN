//! uuid bytes should be stored big endian in memory
const std = @import("std");
const util = @import("util.zig");
const UUID = @This();
const rand = @import("random.zig");

pub const MAX = UUID{ .bytes = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
pub const NIL = UUID{};

bytes: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },

/// probably just use `UUID{.bytes = bytes}` instead of this
pub fn createBytes(allocator: std.mem.Allocator, bytes: [16]u8) !*UUID {
    const u = try allocator.create(UUID);
    u.bytes = bytes;
    return u;
}

pub fn createRandom(allocator: std.mem.Allocator) !*UUID {
    var u = try allocator.create(UUID);
    u.setRandom();
    return u;
}

pub noinline fn setRandom(self: *UUID) void {
    rand.bytes(&self.bytes);

    // osf dce version 4
    self.bytes[6] = (4 << 4) | (self.bytes[6] & 0x0F);
    // osf dce variant 1
    self.bytes[8] = (0b10 << 6) | (self.bytes[8] & 0x3F);
}

pub fn format(value: *const UUID, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;

    for (0..16) |i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) try writer.writeAll("-");
        try writer.writeAll(&util.byteToHex(value.bytes[i]));
    }
}

test "format" {
    const allocator = std.heap.c_allocator;

    const str = try std.fmt.allocPrint(allocator, "{}", .{MAX});
    try std.testing.expectEqualStrings("ffffffff-ffff-ffff-ffff-ffffffffffff", str);
}

pub fn eql(self: *const UUID, other: UUID) bool {
    return std.mem.eql(u8, &self.bytes, &other.bytes);
}
