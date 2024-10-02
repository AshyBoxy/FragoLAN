pub const Error = error{InvalidLength};

pub fn copy(dest: []u8, source: *const [*]u8, size: usize) !void {
    if (dest.len < size or source.len < size) return Error.InvalidLength;

    for (0..size) |i| {
        dest[i] = source[i];
    }
}

// i will kms
pub fn copy16(dest: *[16]u8, source: [16]u8) void {
    for (0..16) |i| {
        dest[i] = source[i];
    }
}

pub fn copy12(dest: *[12]u8, source: [12]u8) void {
    for (0..12) |i| {
        dest[i] = source[i];
    }
}

pub fn byteToHex(b: u8) [2]u8 {
    const chars = "0123456789abcdef";
    var result: [2]u8 = undefined;
    result[0] = chars[b >> 4];
    result[1] = chars[b & 15];
    return result;
}

pub fn panic(comptime msg: []const u8, err: anyerror) void {
    @import("std").debug.panic("{s}: {!}\n", .{msg, err});
}
