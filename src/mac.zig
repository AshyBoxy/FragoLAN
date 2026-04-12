const std = @import("std");
const util = @import("./util.zig");

// pub const macAddress = [6]u8;
pub const MacAddress = u48; //hmm

pub const Error = error{InvalidLength};

pub const Broadcast: MacAddress = 0xffffffffffff;

pub fn fromByteSlice(bytes: []u8) !MacAddress {
    // sorry 64 bit mac address people
    if (bytes.len != 6) return Error.InvalidLength;

    return std.mem.readInt(u48, bytes[0..6], std.builtin.Endian.big);
}

/// writes the mac address into the given slice
pub fn toByteSlice(mac: MacAddress, slice: *[6]u8) void {
    slice[0] = @intCast(mac >> 40);
    slice[1] = @intCast(mac << 8 >> 40);
    slice[2] = @intCast(mac << 16 >> 40);
    slice[3] = @intCast(mac << 24 >> 40);
    slice[4] = @intCast(mac << 32 >> 40);
    slice[5] = @intCast(mac << 40 >> 40);
}

pub fn fromString(str: []const u8) !MacAddress {
    if (str.len != 12 and str.len != 17) return Error.InvalidLength;

    var mac: MacAddress = 0;

    var p: u6 = 0;
    for (str, 0..str.len) |value, _| {
        if (value == ':') continue;
        const nib: MacAddress = try util.hexToNib(value);
        mac |= (nib << 44 - p);
        p += 4;
    }

    return mac;
}
