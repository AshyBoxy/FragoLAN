const std = @import("std");
const log = @import("log.zig");
const ethernet = @import("ethernet.zig");
const mac = @import("mac.zig");
const ipv4 = @import("ipv4.zig");

const BigEndian = std.builtin.Endian.big;

// size of everything but the addresses
pub const MinimumArpSize = 2 + 2 + 1 + 1 + 2;

pub const ProtocolType = ethernet.EtherType;
pub const HardwareType = enum(u16) {
    ethernet = 1,
    _,

    pub fn name(self: HardwareType) ?[]const u8 {
        return switch (self) {
            .ethernet => "Ethernet",
            _ => null,
        };
    }
};

pub const Operation = enum(u16) {
    request = 1,
    reply = 2,

    pub fn name(self: Operation) []const u8 {
        return switch (self) {
            .request => "request",
            .reply => "reply",
        };
    }
};

pub const Packet = struct {
    hardwareType: HardwareType,
    protocolType: ProtocolType,
    /// Hardware Address Length
    hwAddrLen: u8,
    /// Protocol Address Length
    prAddrLen: u8,
    operation: Operation,
    // TODO: these should be some address interface
    /// Sender Hardware Address
    sHwAddr: []u8,
    /// Sender Protocol Address
    sPrAddr: []u8,
    /// Target Hardware Address
    tHwAddr: []u8,
    /// Target Protocol Address
    tPrAddr: []u8,

    /// frees the packet's members
    ///
    /// the packet itself must still be freed
    ///
    /// the given allocator must be the one used to create it
    pub fn free(self: Packet, allocator: std.mem.Allocator) void {
        // this segfaults?
        // pretty sure not doing it leaks memory.
        _ = self;
        _ = allocator;
        // allocator.free(self.sHwAddr);
        // allocator.free(self.sPrAddr);
        // allocator.free(self.tHwAddr);
        // allocator.free(self.tPrAddr);
    }
};

pub const ArpParseError = error{InvalidPacket};

pub fn processPacket(allocator: std.mem.Allocator, rawPacket: ethernet.PacketPayload) !void {
    const packet = try parsePacket(allocator, rawPacket);
    if (packet.hardwareType != .ethernet) {
        log.debug("Caught ARP packet with unsupported hardware type: 0x{x:0>4}\n", .{packet.hardwareType});
        return;
    }

    const srcMac = try mac.fromByteSlice(packet.sHwAddr);
    const destMac = try mac.fromByteSlice(packet.tHwAddr);

    log.debug("Caught Ethernet ARP {s} packet from {x} to {x} for protocol ", .{ packet.operation.name(), srcMac, destMac });
    if (packet.protocolType.name()) |name| {
        log.debug("{s}", .{name});
    } else {
        log.debug("0x{x:0>4}", .{@intFromEnum(packet.protocolType)});
    }
    log.debugS("\n");

    if (packet.protocolType != .ipv4) return;

    const srcIp = try ipv4.fromByteSlice(packet.sPrAddr);
    const destIp = try ipv4.fromByteSlice(packet.tPrAddr);
    const srcIpStr = try ipv4.format(allocator, srcIp);
    defer allocator.free(srcIpStr);
    const destIpStr = try ipv4.format(allocator, destIp);
    defer allocator.free(destIpStr);

    if (packet.operation == .request) {
        log.debug("{s} asking where {s} is\n", .{ srcIpStr, destIpStr });
    } else {
        log.debug("{s} responding to {s}\n", .{ srcIpStr, destIpStr });
    }
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: ethernet.PacketPayload) !*Packet {
    if (rawPacket.len < MinimumArpSize) return ArpParseError.InvalidPacket;

    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);

    packet.hardwareType = @enumFromInt(std.mem.readInt(u16, @ptrCast(rawPacket.ptr), BigEndian));
    packet.protocolType = @enumFromInt(std.mem.readInt(u16, @ptrCast(rawPacket.ptr + 2), BigEndian));
    packet.hwAddrLen = rawPacket[4];
    packet.prAddrLen = rawPacket[5];
    packet.operation = @enumFromInt(std.mem.readInt(u16, @ptrCast(rawPacket.ptr + 6), BigEndian));

    var offset: u16 = 8;
    packet.sHwAddr = rawPacket[offset .. offset + packet.hwAddrLen];
    offset += packet.hwAddrLen;
    packet.sPrAddr = rawPacket[offset .. offset + packet.prAddrLen];
    offset += packet.prAddrLen;
    packet.tHwAddr = rawPacket[offset .. offset + packet.hwAddrLen];
    offset += packet.hwAddrLen;
    packet.tPrAddr = rawPacket[offset .. offset + packet.prAddrLen];

    return packet;
}

/// creates an ethernet arp ipv4 packet
pub fn createIpv4Packet(allocator: std.mem.Allocator, srcMac: mac.MacAddress, destMac: mac.MacAddress, srcIp: *const [4]u8, destIp: *const [4]u8, operation: Operation) !*Packet {
    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);
    packet.hardwareType = HardwareType.ethernet;
    packet.protocolType = ProtocolType.ipv4;
    packet.hwAddrLen = 6;
    packet.prAddrLen = 4;
    packet.operation = operation;

    const srcMacSlice = try allocator.create([6]u8);
    errdefer allocator.free(srcMacSlice);
    const destMacSlice = try allocator.create([6]u8);
    errdefer allocator.free(destMacSlice);
    mac.toByteSlice(srcMac, srcMacSlice);
    mac.toByteSlice(destMac, destMacSlice);
    packet.sHwAddr = srcMacSlice;
    packet.tHwAddr = destMacSlice;

    packet.sPrAddr = try allocator.dupe(u8, srcIp);
    errdefer allocator.free(packet.sPrAddr);
    packet.tPrAddr = try allocator.dupe(u8, destIp);

    return packet;
}

/// serializes an arp packet
pub fn serialize(allocator: std.mem.Allocator, packet: *Packet) ![]u8 {
    const size = MinimumArpSize + (packet.hwAddrLen * 2) + (packet.prAddrLen * 2);
    const payload = try allocator.alloc(u8, size);

    std.mem.writeInt(u16, payload[0..2], @intFromEnum(packet.hardwareType), BigEndian);
    std.mem.writeInt(u16, payload[2..4], @intFromEnum(packet.protocolType), BigEndian);
    std.mem.writeInt(u8, payload[4..5], packet.hwAddrLen, BigEndian);
    std.mem.writeInt(u8, payload[5..6], packet.prAddrLen, BigEndian);
    std.mem.writeInt(u16, payload[6..8], @intFromEnum(packet.operation), BigEndian);

    var offset: u16 = 8;
    @memcpy(payload.ptr + offset, packet.sHwAddr);
    offset += packet.hwAddrLen;
    @memcpy(payload.ptr + offset, packet.sPrAddr);
    offset += packet.prAddrLen;
    @memcpy(payload.ptr + offset, packet.tHwAddr);
    offset += packet.hwAddrLen;
    @memcpy(payload.ptr + offset, packet.tPrAddr);

    return payload;
}
