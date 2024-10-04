const std = @import("std");

pub const keepalive = @import("./keepalive.zig");
pub const ipv4 = @import("./ipv4.zig");

const BigEndian = std.builtin.Endian.big;

pub const Error = error{InvalidLength};

pub const Type = enum(u16) {
    KeepAlive = 1,
    IPv4 = 2,
    _,

    pub fn name(self: Type) ?[]const u8 {
        return switch (self) {
            .KeepAlive => "KeepAlive",
            .IPv4 => "IPv4",
            _ => null,
        };
    }
};

pub const Packet = struct {
    type: Type,
    payload: []u8,

    pub fn serialize(self: *Packet, allocator: std.mem.Allocator) ![]u8 {
        const payload = try allocator.alloc(u8, 2 + self.payload.len);
        std.mem.writeInt(u16, payload[0..2], @intFromEnum(self.type), BigEndian);
        @memcpy(payload[2..], self.payload);
        return payload;
    }

    pub fn free(self: *Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};

// TODO: interface

pub fn createPacket(allocator: std.mem.Allocator, packetType: Type, payload: []u8) !*Packet {
    const packet = try allocator.create(Packet);
    packet.type = packetType;
    packet.payload = try allocator.alloc(u8, payload.len);
    errdefer allocator.free(packet.payload);
    @memcpy(packet.payload, payload);
    return packet;
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: []u8) !*Packet {
    if (rawPacket.len < 2) return Error.InvalidLength;

    const packetTypeNum = std.mem.readInt(u16, rawPacket[0..2], BigEndian);
    const packetType: Type = @enumFromInt(packetTypeNum);
    // @import("../log.zig").debug("Packet has first two bytes: {d}, {any}\n", .{ packetTypeNum, packetType });
    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);

    packet.type = packetType;
    if (rawPacket.len < 3) {
        packet.payload = &.{};
        return packet;
    }

    packet.payload = try allocator.alloc(u8, rawPacket[2..].len);
    @memcpy(packet.payload, rawPacket[2..]);

    return packet;
}
