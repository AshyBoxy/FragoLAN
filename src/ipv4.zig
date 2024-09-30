const std = @import("std");
const ethernet = @import("ethernet.zig");
const log = @import("log.zig");

const BigEndian = std.builtin.Endian.big;

pub const Address = u32;

pub const Error = error{ InvalidLength, WrongVersion };

pub const Protocol = enum(u8) {
    invalid = 0,
    icmp = 1,
    igmp = 2,
    tcp = 6,
    udp = 17,
    _,

    pub fn name(self: Protocol) ?[]const u8 {
        return switch (self) {
            .invalid => "Invalid",
            .icmp => "ICMP",
            .igmp => "IGMP",
            .tcp => "TCP",
            .udp => "UDP",
            _ => null,
        };
    }
};

// whoever decided on these sizes, i know you were trying
// to save space decades ago, but i hate you
pub const Packet = struct {
    version: u4,
    ihl: u4,
    dscp: u6,
    ecn: u2,
    length: u16,
    id: u16,
    flags: u3,
    fragOffset: u13,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    source: Address,
    dest: Address,
    options: []u8,
    payload: []u8,

    pub fn serializeHeader(self: *Packet, allocator: std.mem.Allocator) !*[12]u8 {
        const header = try allocator.create([12]u8);

        header[0] = (@as(u8, self.version) << 4) | self.ihl;
        header[1] = (@as(u8, self.dscp) << 2) | self.ecn;
        std.mem.writeInt(u16, header[2..4], self.length, BigEndian);
        std.mem.writeInt(u16, header[4..6], self.id, BigEndian);

        const flagsFragoff = (@as(u16, self.flags) << 13) | self.fragOffset;
        std.mem.writeInt(u16, header[6..8], flagsFragoff, BigEndian);

        header[8] = self.ttl;
        header[9] = @intFromEnum(self.protocol);

        std.mem.writeInt(u16, header[10..12], self.checksum, BigEndian);

        // hmm yes
        return header;
    }
};

pub fn fromByteSlice(bytes: []u8) !Address {
    if (bytes.len != 4) return Error.InvalidLength;

    return std.mem.readInt(u32, bytes[0..4], std.builtin.Endian.big);
}

/// writes the ipv4 address into the given slice
pub fn toByteSlice(ip: Address, slice: *[4]u8) void {
    slice[0] = @intCast(ip >> 24);
    slice[1] = @intCast(ip << 8 >> 24);
    slice[2] = @intCast(ip << 16 >> 24);
    slice[3] = @intCast(ip << 24 >> 24);
}

pub fn format(allocator: std.mem.Allocator, addr: Address) ![]const u8 {
    const slice: *[4]u8 = try allocator.create([4]u8);
    defer allocator.destroy(slice);
    toByteSlice(addr, slice);
    var size: u8 = 3; // 3 .'s
    for (slice) |byte| {
        if (byte < 10) size += 1 else if (byte < 100) size += 2 else size += 3;
    }

    // 15 is the longest an ipv4 string can be (255.255.255.255)
    // plus 1 for less logic for the trailing .
    var str: [16]u8 = undefined;
    var i: u8 = 0;
    for (slice) |byte| {
        if (byte >= 100) {
            str[i] = @divTrunc(byte, 100) + '0';
            i += 1;
            str[i..][0..2].* = std.fmt.digits2(byte % 100);
            if (byte % 100 >= 10) i += 2 else i += 1;
        } else if (byte >= 10) {
            str[i..][0..2].* = std.fmt.digits2(byte);
            i += 2;
        } else {
            str[i] = byte + '0';
            i += 1;
        }

        str[i] = '.';
        i += 1;
    }

    const finalStr = try allocator.dupe(u8, str[0..size]);
    return finalStr;
}

pub fn processPacket(allocator: std.mem.Allocator, rawPacket: ethernet.PacketPayload) !void {
    const packet = try parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);
    defer allocator.free(packet.options);
    defer allocator.free(packet.payload);

    const srcIpStr = try format(allocator, packet.source);
    defer allocator.free(srcIpStr);
    const dstIpStr = try format(allocator, packet.dest);
    defer allocator.free(dstIpStr);

    log.debug("Caught an IPv4 packet from {s} to {s} with length {d}, protocol ", .{ srcIpStr, dstIpStr, packet.length });
    if (packet.protocol.name()) |name| {
        log.debug("{s}", .{name});
    } else {
        log.debug("0x{x}", .{packet.protocol});
    }
    log.debugS("\n");
}

pub fn parsePacket(allocator: std.mem.Allocator, rawPacket: ethernet.PacketPayload) !*Packet {
    if (rawPacket.len < 20) return Error.InvalidLength;

    const packet = try allocator.create(Packet);
    errdefer allocator.destroy(packet);

    packet.version = @intCast((rawPacket[0] & 0xF0) >> 4);
    if (packet.version != 4) return Error.WrongVersion;
    packet.ihl = @intCast(rawPacket[0] & 0x0F);
    if (packet.ihl < 5) return Error.InvalidLength;
    packet.dscp = @intCast((rawPacket[1] & 0xFC) >> 2);
    packet.ecn = @intCast(rawPacket[1] & 0x03);
    packet.length = std.mem.readInt(u16, rawPacket[2..4], BigEndian);
    packet.id = std.mem.readInt(u16, rawPacket[4..6], BigEndian);

    const flagsFragOff = std.mem.readInt(u16, rawPacket[6..8], BigEndian);
    packet.flags = @intCast((flagsFragOff & 0xE000) >> 13);
    packet.fragOffset = @intCast(flagsFragOff & 0x1FFF);

    packet.ttl = rawPacket[8];
    packet.protocol = @enumFromInt(rawPacket[9]);
    packet.checksum = std.mem.readInt(u16, rawPacket[10..12], BigEndian);

    packet.source = std.mem.readInt(u32, rawPacket[12..16], BigEndian);
    packet.dest = std.mem.readInt(u32, rawPacket[16..20], BigEndian);

    const optionsEnd = 20 + ((@as(u32, packet.ihl) - 5) * 4);
    packet.options = try allocator.alloc(u8, rawPacket[20..optionsEnd].len);
    errdefer allocator.free(packet.options);
    packet.payload = try allocator.alloc(u8, rawPacket[optionsEnd..].len);

    @memcpy(packet.options, rawPacket[20..optionsEnd]);
    @memcpy(packet.payload, rawPacket[optionsEnd..]);

    return packet;
}
