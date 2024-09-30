const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});
const log = @import("log.zig");
const arp = @import("arp.zig");
const mac = @import("mac.zig");
const ipv4 = @import("ipv4.zig");

const BigEndian = std.builtin.Endian.big;

/// not including the payload
// pub const ethernetFrameSize = (@sizeOf(macAddress) * 2) + @sizeOf([2]u8); // + @sizeOf([4]u8);
pub const ethernetFrameSize = (6 * 2) + 2; // + @sizeOf([4]u8);
pub const PacketPayload = []u8;
pub const EthernetPacket = struct {
    dest: mac.MacAddress,
    src: mac.MacAddress,
    etherType: EtherType,
    payload: PacketPayload,
    // doesn't seem to exist sometimes?
    // checksum: [4]u8,

    pub fn serialize(self: *EthernetPacket, allocator: std.mem.Allocator) ![]u8 {
        const size = ethernetFrameSize + self.payload.len;
        const payload = try allocator.alloc(u8, size);
        std.mem.writeInt(u48, payload[0..6], self.dest, BigEndian);
        std.mem.writeInt(u48, payload[6..12], self.src, BigEndian);
        std.mem.writeInt(u16, payload[12..14], @intFromEnum(self.etherType), BigEndian);
        @memcpy(payload[14..], self.payload);
        return payload;
    }
};

pub const EtherType = enum(u16) {
    invalid = 0,
    ipv4 = 0x0800,
    arp = 0x0806,
    vlan = 0x8100,
    ipv6 = 0x86DD,
    _,

    pub fn fromU16(value: u16) EtherType {
        // ethertypes must be above 1536 (0x0600)
        if (value < 1536) return EtherType.invalid;
        return @enumFromInt(value);
    }

    pub fn name(self: EtherType) ?[]const u8 {
        return switch (self) {
            .invalid => "Invalid",
            .ipv4 => "IPv4",
            .arp => "ARP",
            .vlan => "VLAN",
            .ipv6 => "IPv6",
            _ => null,
        };
    }
};

/// only works with ethernet ii frames for now
// TODO: validate checksum?
// might be more work than just letting other systems handle it
pub fn captureEthernet(allocator: std.mem.Allocator, header: *const c.struct_pcap_pkthdr, cRawPacket: [*c]const u8) !void {
    if (header.len < ethernetFrameSize) return log.debugS("Tried to capture a too short ethernet frame\n");
    const rawPacket: [*]const u8 = @ptrCast(cRawPacket);
    const packet = rawPacket[0..header.caplen];

    const pack = try parsePacket(allocator, packet);

    log.debug("Caught ethernet frame to {x}, from {x}, with ethertype ", .{ pack.dest, pack.src });
    if (pack.etherType.name()) |name| {
        log.debug("{s}", .{name});
    } else {
        log.debug("0x{x:0>4}", .{@intFromEnum(pack.etherType)});
    }
    log.debug(", payload length {d}\n", .{pack.payload.len});

    // log.debugS("Payload: ");
    // for (pack.payload) |byte| {
    //     log.debug("{x:0>2}", .{byte});
    // }
    // log.debugS("\n");

    try processPacketPayload(allocator, pack);
}

pub fn processPacketPayload(allocator: std.mem.Allocator, packet: *EthernetPacket) !void {
    _ = switch (packet.etherType) {
        else => null, // do nothing
        .arp => try arp.processPacket(allocator, packet.payload),
        .ipv4 => try ipv4.processPacket(allocator, packet.payload),
    };
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: []u8) !*EthernetPacket {
    const pack = try allocator.create(EthernetPacket);
    errdefer allocator.destroy(pack);

    pack.dest = std.mem.readInt(u48, rawPacket[0..6], BigEndian);
    pack.src = std.mem.readInt(u48, rawPacket[6..12], BigEndian);
    pack.etherType = EtherType.fromU16(std.mem.readInt(u16, rawPacket[12..14], BigEndian));
    pack.payload = try allocator.alloc(u8, rawPacket[14..].len);
    @memcpy(pack.payload, rawPacket[14..]);

    return pack;
}

pub fn createPacket(allocator: std.mem.Allocator, dest: mac.MacAddress, src: mac.MacAddress, etherType: EtherType, payload: PacketPayload) !*EthernetPacket {
    const packet = try allocator.create(EthernetPacket);
    errdefer allocator.destroy(packet);
    packet.dest = dest;
    packet.src = src;
    packet.etherType = etherType;
    packet.payload = try allocator.alloc(u8, payload.len);
    errdefer allocator.free(packet.payload);
    @memcpy(packet.payload, payload);
    return packet;
}

pub fn serialize(allocator: std.mem.Allocator, packet: *EthernetPacket) ![]u8 {
    return packet.serialize(allocator);
}
