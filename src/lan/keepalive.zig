const std = @import("std");
const peer = @import("peer.zig");
const log = @import("../log.zig");

pub const Packet = struct {
    clients: u8,
    peers: []peer.Peer,

    pub fn serialize(self: *Packet, allocator: std.mem.Allocator) ![]u8 {
        const payload = try allocator.alloc(u8, 1 + (self.peers.len * 16));
        payload[0] = self.clients;
        for (self.peers, 0..) |p, i| {
            @memcpy(payload[1 + (i * 16)..], p.uuid.bytes[0..16]);
        }
        return payload;
    }

    pub fn free(self: *Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.peers);
        self.* = undefined;
    }
};

pub const Error = error{InvalidLength};

pub fn createPacket(allocator: std.mem.Allocator, peers: []const peer.Peer) !*Packet {
    const packet = try allocator.create(Packet);
    packet.clients = @intCast(peers.len);
    packet.peers = try allocator.dupe(peer.Peer, peers);
    return packet;
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: []u8) !*Packet {
    if (rawPacket.len < 1) return Error.InvalidLength;
    // everything after the count must some multiple of 16
    if ((rawPacket.len - 1) % 16 > 0) return Error.InvalidLength;

    const count = rawPacket[0];
    const clients = rawPacket[1..];
    const clientsLen = clients.len / 16;
    if (clientsLen != count) return Error.InvalidLength;

    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);
    packet.clients = count;

    packet.peers = try allocator.alloc(peer.Peer, count);
    for (0..packet.peers.len) |i| {
        packet.peers[i].ip = 0;
        @memcpy(packet.peers[i].uuid.bytes[0..16], clients[i * 16 .. (i + 1) * 16]);
    }

    return packet;
}
