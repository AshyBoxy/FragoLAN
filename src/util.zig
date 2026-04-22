const std = @import("std");
const log = @import("./log.zig");

pub const Error = error{ InvalidLength, InvalidCharacter };

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

pub fn hexToNib(c: u8) !u4 {
    if (c < 0x30) return Error.InvalidCharacter;
    if (c < 0x3A) return @intCast(c - 0x30);
    if (c < 0x41) return Error.InvalidCharacter;
    if (c < 0x47) return @intCast(c - 0x41 + 10);
    if (c < 0x61) return Error.InvalidCharacter;
    if (c < 0x67) return @intCast(c - 0x61 + 10);
    return Error.InvalidCharacter;
}

pub inline fn panic(comptime msg: []const u8, err: anyerror) void {
    log.wait();
    @import("std").debug.panic("{s}: {}\n", .{ msg, err });
}

pub inline fn asCStr(val: []u8) [*c]u8 {
    return @ptrCast(val.ptr);
}

pub inline fn makeString(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}", .{str});
}

pub inline fn getenv(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    const env = std.process.getEnvVarOwned(allocator, key) catch |e| {
        if (e == error.EnvironmentVariableNotFound) return null;
        return e;
    };
    return env;
}

pub inline fn streq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub const RawData = struct {
    pub fn readBe(comptime T: type, data: []const u8, offset: *usize) !T {
        const n = @sizeOf(T);
        if (data.len < offset.* + n) return Error.InvalidLength;

        const v = std.mem.readInt(T, data[offset.*..][0..n], .big);
        offset.* += n;
        return v;
    }

    pub fn writeBe(comptime T: type, data: []u8, offset: *usize, value: T) !void {
        const n = @sizeOf(T);
        if (data.len < offset.* + n) return Error.InvalidLength;

        std.mem.writeInt(T, data[offset.*..][0..n], value, .big);
        offset.* += n;
    }

    pub fn hexToBytes(out: []u8, hex: []const u8) !void {
        if (hex.len != out.len * 2) return Error.InvalidLength;
        _ = try std.fmt.hexToBytes(out, hex);
    }
};

pub const comp = struct {
    pub fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
        if (hex.len % 2 != 0) @compileError("Hex string must have an even length");
        var out: [hex.len / 2]u8 = undefined;
        @setEvalBranchQuota(7000); // what?
        RawData.hexToBytes(&out, hex) catch @compileError("Invalid hex string");
        return out;
    }
};
