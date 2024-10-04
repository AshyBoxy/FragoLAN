const std = @import("std");
const ethernet = @import("ethernet.zig");
const log = @import("log.zig");

const BigEndian = std.builtin.Endian.big;

pub const Address = u32;
pub const Empty: Address = 0;

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

    pub fn serialize(self: *Packet, allocator: std.mem.allocator) ![]u8 {
        const payload = try allocator.alloc(u8, 20 + self.options.len + self.payload.len);

        const header = try self.serializeHeader(allocator);
        @memcpy(payload[0..12], header[0..12]);
        allocator.destroy(header);

        std.mem.writeInt(u32, payload[12..16], self.source, BigEndian);
        std.mem.writeInt(u32, payload[16..20], self.dest, BigEndian);

        @memcpy(payload[20..20+self.options.len], self.options);
        @memcpy(payload[20+self.options.len..], self.payload);

        std.mem.writeInt(u16, payload[10..12], calculateChecksum(payload[0..20]), BigEndian);

        return payload;
    }
};

pub fn fromByteSlice(bytes: []u8) Address {
    return std.mem.readInt(u32, bytes[0..4], std.builtin.Endian.big);
}

pub fn fromInts(one: u8, two: u8, three: u8, four: u8) Address {
    return (@as(Address, @intCast(one)) << 24) | (@as(Address, @intCast(two)) << 16) | (@as(Address, @intCast(three)) << 8) | four;
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

/// no options for now
pub fn createPacket(allocator: std.mem.Allocator, dscp: u6, protocol: u8, source: Address, dest: Address, payload: []u8) !Packet {
    const p = try allocator.create(Packet);
    errdefer allocator.destroy(p);
    p.version = 4;
    p.ihl = 5;
    p.dscp = dscp;
    p.protocol = protocol;
    p.length = 20 + payload.len;
    p.id = 0;
    // always don't fragment
    p.flags = 0b010;
    p.fragOffset = 0;
    p.ttl = 255;
    p.checksum = 0;
    p.source = source;
    p.dest = dest;
    // this is silly
    p.options = try allocator.alloc(u8, 0);
    errdefer allocator.free(p.options);
    p.payload = try allocator.dupe(u8, payload);
    return p;
}

pub fn calculateChecksum(header: *[20]u8) u16 {
    var check: u32 = 0;

    var i: u8 = 0;
    while (i < 20) {
        if (i == 10) {
            // skip the checksum itself
            i += 2;
            continue;
        }
        const num = (@as(u16, header[i]) << 8) | header[i + 1];
        check += num;
        i += 2;
    }

    var sum: u16 = @intCast(check & 0xFFFF);
    sum += @intCast(check >> 16);

    return ~sum;
}

pub fn tcpCalculateChecksum(sourceDestIp: *[8]u8, tcpPayload: []u8) u16 {
    var check: u32 = 0;

    var i: usize = 0;
    while (i < 8) {
        check += (@as(u16, sourceDestIp[i]) << 8) | sourceDestIp[i + 1];
        i += 2;
    }

    i = 0;
    var im = tcpPayload.len;
    if (tcpPayload.len % 2 == 1) im -= 1;
    while (i < im) {
        if (i == 16) {
            // skip the checksum
            i += 2;
            continue;
        }

        const num = (@as(u16, tcpPayload[i]) << 8) | tcpPayload[i + 1];
        check +%= num;
        i += 2;
    }

    // add final byte if odd length
    if (tcpPayload.len != im) check += @as(u16, tcpPayload[im]) << 8;

    // tcp protocol
    check +%= 6;
    // tcp length
    check +%= @intCast(tcpPayload.len);

    var sum: u16 = @intCast(check & 0xFFFF);
    sum +%= @intCast(check >> 16);

    return ~sum;
}
