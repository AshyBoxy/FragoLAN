const std = @import("std");

const ipv4 = @import("../ipv4.zig");
const util = @import("../util.zig");
const UUID = @import("../UUID.zig");

// pub const UUID = [16]u8;
// pub const MAX_UUID: UUID = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

pub const Packet = struct {
    pub const MinLength = (16 * 2) + 12;

    // actual contents
    source: UUID,
    dest: UUID,
    /// the checksum here is not useful anymore
    header: [12]u8,
    options: []u8,
    payload: []u8,

    pub fn serialize(self: *Packet, allocator: std.mem.Allocator) ![]u8 {
        const payload = try allocator.alloc(u8, Packet.MinLength + self.options.len + self.payload.len);

        util.copy16(payload[0..16], self.source.bytes);
        util.copy16(payload[16..32], self.dest.bytes);
        util.copy12(payload[32..44], self.header);
        @memcpy(payload[44 .. 44 + self.options.len], self.options);
        @memcpy(payload[44 + self.options.len ..], self.payload);

        return payload;
    }

    pub fn free(self: *Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.options);
        allocator.free(self.payload);
    }
};

pub const Error = error{InvalidLength};

pub fn createPacket(allocator: std.mem.Allocator, source: UUID, dest: UUID, header: [12]u8, options: []u8, payload: []u8) !*Packet {
    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);

    packet.source = source;
    packet.dest = dest;

    // ...?
    // packet.header = (try allocator.create([12]u8)).*;
    // errdefer allocator.destroy(&packet.header);
    // util.copy12(&packet.header, header);
    packet.header = header;
    // blank the checksum
    @memcpy(packet.header[10..12], &[2]u8{ 0, 0 });

    packet.options = try allocator.dupe(u8, options);
    errdefer allocator.free(packet.options);
    packet.payload = try allocator.dupe(u8, payload);

    return packet;
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: []u8) !*Packet {
    if (rawPacket.len < Packet.MinLength) return Error.InvalidLength;

    // const source = try allocator.create(UUID);
    // errdefer allocator.destroy(source);
    // const dest = try allocator.create(UUID);
    // errdefer allocator.destroy(dest);
    const packet = try allocator.create(Packet);

    // const header = try allocator.alloc(u8, 12);
    // errdefer allocator.free(header);

    // @memcpy(source, rawPacket);
    // @memcpy(dest, rawPacket[16..]);

    @memcpy(packet.source.bytes[0..16], rawPacket[0..16]);
    @memcpy(packet.dest.bytes[0..16], rawPacket[16..32]);

    @memcpy(packet.header[0..12], rawPacket[32..44]);

    // we need to find out specifically ihl for the options length
    const ihl: u4 = @intCast(packet.header[0] & 0x0F);
    if (ihl < 5) return Error.InvalidLength;
    const optionsSize: u32 = (ihl - 5) * 4;

    const options = try allocator.alloc(u8, optionsSize);
    errdefer allocator.free(options);
    @memcpy(options, rawPacket[44 .. 44 + optionsSize]);

    const payload = try allocator.alloc(u8, rawPacket.len - Packet.MinLength + optionsSize);
    errdefer allocator.free(payload);
    @memcpy(payload, rawPacket[44 + optionsSize ..]);

    // packet.source = source;
    // packet.dest = dest;
    // packet.header = header;
    packet.options = options;
    packet.payload = payload;

    return packet;
}
