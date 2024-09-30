const std = @import("std");

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
