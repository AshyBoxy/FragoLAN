const std = @import("std");

pub const Packet = struct {
    clients: u8,
    uuids: []u8,

    pub fn serialize(self: *Packet, allocator: std.mem.Allocator) ![]u8 {
        const payload = try allocator.alloc(u8, 1 + self.uuids.len);
        payload[0] = self.clients;
        @memcpy(payload[1..], self.uuids);
        return payload;
    }
};

pub const Error = error{ InvalidLength };

pub fn createPacket(allocator: std.mem.Allocator, clients: u8) !*Packet {
    const packet = try allocator.create(Packet);
    packet.clients = clients;
    packet.uuids = &.{};
    return packet;
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: []u8) !*Packet {
    if (rawPacket.len < 1) return Error.InvalidLength;
    // everything after the count must some multiple of 16
    if ((rawPacket.len - 1) % 16 > 0) return Error.InvalidLength;

    const count = rawPacket[0];
    const clients = rawPacket[1..];

    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);
    packet.clients = count;
    packet.uuids = try allocator.alloc(u8, clients.len);
    @memcpy(packet.uuids, clients);

    return packet;
}
