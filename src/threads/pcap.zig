const std = @import("std");
const c = @import("c").c;
const log = @import("../log.zig");
const ethernet = @import("../ethernet.zig");
const ipv4 = @import("../ipv4.zig");
const lan = @import("../lan/packet.zig");
const client = @import("./client.zig");
const UUID = @import("../UUID.zig");
const main = @import("root");
const peer = @import("../lan/peer.zig");
const arp = @import("../arp.zig");
const mac = @import("../mac.zig");
const config = @import("../config.zig");
const pia = @import("../lan/pia.zig");

// solving double free issues...
var allocator: std.mem.Allocator = undefined;

const debug_runpcap = true;
var _handle: ?*c.pcap_t = null;

pub fn loop(pcapHandlePtr: usize) void {
    const pcapHandle: *c.pcap_t = @ptrFromInt(pcapHandlePtr);

    allocator = @import("root").allocator;

    log.name = "PCap";
    _handle = pcapHandle;

    log.log("pcap thread started with id: {d}\n", .{std.Thread.getCurrentId()});

    if (!debug_runpcap) {
        log.logS("Cancelling pcap thread\n");
        return;
    }

    const loopResult = c.pcap_loop(pcapHandle, -1, lanPcapLoop, null);
    if (loopResult == 0) {
        log.debugS("Tried to start pcap_loop after closing pcap?\n");
    } else {
        log.debug("Error when attempting to run pcap_loop: ({d}) {s}\n", .{ loopResult, c.pcap_geterr(pcapHandle) });
    }
}

pub fn lanPcapLoop(data: [*c]c.u_char, header: [*c]const c.pcap_pkthdr, bytes: [*c]const c.u_char) callconv(.c) void {
    _ = data;

    if (header.*.len > header.*.caplen) {
        log.debug("Caught only part of a packet {d}/{d}\n", .{ header.*.caplen, header.*.len });
        return;
    } else {
        // _ = ethernet.captureEthernet(allocator, header, bytes) catch null;
        const rp: [*]const u8 = @ptrCast(bytes);

        if (header.*.caplen > 1514) {
            const dest_mac = mac.fromByteSlice(@constCast(rp[0..6])) catch return;
            const source_mac = mac.fromByteSlice(@constCast(rp[6..12])) catch return;
            log.debug("Caught a packet (tv_sec {d}) (caplen {d}) (len {d}) (src: {x}) (dst: {x})\n", .{ header.*.ts.tv_sec, header.*.caplen, header.*.len, source_mac, dest_mac });
        } else {
            // log.debug("Caught a packet (tv_sec {d}) (caplen {d}) (len {d})\n", .{ header.*.ts.tv_sec, header.*.caplen, header.*.len});
        }

        const p = allocator.create(handlePacketArgs) catch return;
        p.packet = allocator.alloc(u8, header.*.caplen) catch return;

        // log.debugS("Caught a packet\n");

        @memcpy(p.packet, rp);
        @import("./pool.zig").push(handlePacket, @ptrCast(p));
    }
}

fn handle() *c.pcap_t {
    if (_handle == null) std.debug.panic("Tried to get pcap handle before intialization?\n", .{});
    return _handle.?;
}

const handlePacketArgs = struct { packet: []u8 };

pub const Error = error{
    // sorry
    _NotAnActualError, NotActivated, PcapError };

fn handlePacket(packet: *handlePacketArgs) void {
    // log.log("Caught a packet with length: {d}\n", .{packet.packet.len});

    defer allocator.destroy(packet);
    defer allocator.free(packet.packet);

    const pack = ethernet.parsePacket(allocator, packet.packet) catch return;
    _ = switch (pack.etherType) {
        .ipv4 => handleIpv4(pack.payload, pack),
        .arp => handleArp(pack.payload),
        // else => Error._NotAnActualError,
        else => {
            // log.debug("Got a packet with ethertype {x}\n", .{@intFromEnum(pack.etherType)});
        },
    } catch |err| {
        if (err != Error._NotAnActualError)
            log.err("Error handling {s} packet: {}\n", .{ pack.etherType.name() orelse "unknown", err });
    };
}

fn handleIpv4(rawPacket: []u8, ethernetPacket: *ethernet.EthernetPacket) !void {
    const packet = try ipv4.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);
    defer allocator.free(packet.options);
    defer allocator.free(packet.payload);

    if (packet.protocol == .icmp and config.g.local_ping and packet.payload[0] == 8) {
        return localPing(packet, ethernetPacket);
    }

    // log.debug("Got a packet with protocol {d}\n", .{packet.protocol});

    if (!(packet.protocol == .tcp or packet.protocol == .udp or packet.protocol == .icmp)) return;
    if (pia.maybePiaPacket(packet) and try pia.handlePiaPacket(allocator, packet)) return;

    const destUuid = if (packet.dest == config.g.broadcast) UUID.BROADCAST else peer.IpUuid.get(packet.dest) orelse return;

    const header = try packet.serializeHeader(allocator);
    defer allocator.destroy(header);

    const lanIpPack = try lan.ipv4.createPacket(allocator, main.TEST_UUID, destUuid, header.*, packet.options, packet.payload);
    defer allocator.destroy(lanIpPack);
    defer lanIpPack.free(allocator);
    const lanIpPackS = try lanIpPack.serialize(allocator);
    defer allocator.free(lanIpPackS);

    const lanPack = try lan.createPacket(allocator, .IPv4, lanIpPackS);
    defer allocator.destroy(lanPack);
    defer lanPack.free(allocator);

    const lanPackS = try lanPack.serialize(allocator);
    defer allocator.free(lanPackS);

    // if (packet.protocol == .udp) {
    //     log.debug("Queued a {d} byte UDP packet from port {d} to port {d}\n", .{ std.mem.readInt(u16, packet.payload[4..6], .big), std.mem.readInt(u16, packet.payload[0..2], .big), std.mem.readInt(u16, packet.payload[2..4], .big) });
    // }
    client.sendThread(lanPackS);
}

fn localPing(packet: *ipv4.Packet, pack: *ethernet.EthernetPacket) !void {
    log.debugS("Responding to ICMP echo request packet locally\n");

    const resPayload: []u8 = try allocator.alloc(u8, packet.payload.len);
    defer allocator.free(resPayload);

    resPayload[0] = 0;
    resPayload[1] = 0;
    // 2 and 3 are checksum
    resPayload[2] = 0;
    resPayload[3] = 0;

    @memcpy(resPayload[4..], packet.payload[4..]);

    var checksum: u16 = 0;
    {
        var check: u32 = 0;
        var i: usize = 0;
        while (i + 1 < resPayload.len) : (i += 2) {
            const num = (@as(u16, resPayload[i]) << 8) | resPayload[i + 1];
            check +%= num;
        }

        if (resPayload.len & 1 == 1) check += @as(u16, resPayload[resPayload.len - 1]) << 8;

        while ((check >> 16) != 0) {
            check = (check & 0xFFFF) + (check >> 16);
        }

        checksum = ~@as(u16, @intCast(check));
    }

    std.mem.writeInt(u16, resPayload[2..4], checksum, .big);

    const ipv4Packet = try ipv4.createPacket(allocator, 0, .icmp, packet.dest, packet.source, resPayload);
    defer allocator.destroy(ipv4Packet);
    const ipv4Payload = try ipv4Packet.serialize(allocator);
    defer allocator.free(ipv4Payload);
    std.mem.writeInt(u16, ipv4Payload[10..12], ipv4.calculateChecksum(ipv4Payload[0..20]), .big);

    const ethernetPacket = try ethernet.createPacket(allocator, pack.src, pack.dest, .ipv4, ipv4Payload);
    defer allocator.destroy(ethernetPacket);
    const ethernetPayload = try ethernet.serialize(allocator, ethernetPacket);
    defer allocator.free(ethernetPayload);

    log.debugS("Injecting ICMP reply\n");

    const injectResult = c.pcap_inject(handle(), ethernetPayload.ptr, ethernetPayload.len);
    if (injectResult == c.PCAP_ERROR) {
        log.debug("Error injecting packet: {s}\n", .{c.pcap_geterr(handle())});
    }

    return;
}

fn handleArp(rawPacket: []u8) !void {
    const packet = try arp.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);
    defer packet.free(allocator);

    if (packet.protocolType != .ipv4) return;

    const targetAddress = ipv4.fromByteSlice(packet.tPrAddr[0..4]);
    const sourceAddress = ipv4.fromByteSlice(packet.sPrAddr[0..4]);

    if (sourceAddress == config.g.host) {
        main.TEST_DEST_MAC = try mac.fromByteSlice(packet.sHwAddr[0..6]);
        log.debug("Got an arp from the target at {x}\n", .{main.TEST_DEST_MAC});
    }

    if (!peer.IpUuid.contains(targetAddress)) {
        // log.debugS("Got an arp, not responding\n");
        return;
    }

    const arpPacket = try arp.createIpv4Packet(allocator, config.g.mac, try mac.fromByteSlice(packet.sHwAddr), @ptrCast(packet.tPrAddr), @ptrCast(packet.sPrAddr), .reply);
    defer allocator.destroy(arpPacket);
    defer arpPacket.free(allocator);
    const arpPacketS = try arp.serialize(allocator, arpPacket);
    defer allocator.free(arpPacketS);

    const ethernetPacket = try ethernet.createPacket(allocator, try mac.fromByteSlice(packet.sHwAddr), config.g.mac, .arp, arpPacketS);
    defer allocator.destroy(ethernetPacket);
    defer allocator.free(ethernetPacket.payload);
    const ethernetPacketS = try ethernetPacket.serialize(allocator);
    defer allocator.free(ethernetPacketS);

    const result = c.pcap_inject(handle(), ethernetPacketS.ptr, ethernetPacketS.len);
    if (result == c.PCAP_ERROR_NOT_ACTIVATED) {
        log.debugS("Tried to respond to an arp on a non activated pcap?\n");
    } else if (result == c.PCAP_ERROR) {
        log.debug("Got an error injecting an arp: {s}\n", .{c.pcap_geterr(handle())});
    } else {
        // log.debug("Injected {d} bytes\n", .{result});
    }
}

pub fn inject(packet: []const u8) !c_int {
    const result = c.pcap_inject(handle(), packet.ptr, packet.len);

    if (result == c.PCAP_ERROR_NOT_ACTIVATED) return Error.NotActivated else if (result == c.PCAP_ERROR) return Error.PcapError;

    return result;
}

pub fn geterr() [*c]u8 {
    return c.pcap_geterr(handle());
}
