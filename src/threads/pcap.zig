const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});
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

// solving double free issues...
var allocator: std.mem.Allocator = undefined;

const debug_runpcap = true;
var _handle: ?*c.pcap_t = null;

pub fn loop(pcapHandle: *c.pcap_t) void {
    allocator = @import("root").allocator;

    log.name = "PCap";
    _handle = pcapHandle;

    log.log("pcap thread started with id: {d}\n", .{std.Thread.getCurrentId()});

    if (!debug_runpcap) {
        log.logS("Cancelling pcap thread\n");
        return;
    }

    const loopResult = c.pcap_loop(pcapHandle, 0, lanPcapLoop, null);
    if (loopResult == 0) {
        log.debugS("Tried to start pcap_loop after closing pcap?\n");
    } else {
        log.debug("Error when attempting to run pcap_loop: ({d}) {s}\n", .{ loopResult, c.pcap_geterr(pcapHandle) });
    }
}

pub fn lanPcapLoop(data: [*c]c.u_char, header: [*c]const c.pcap_pkthdr, bytes: [*c]const c.u_char) callconv(.C) void {
    _ = data;

    if (header.*.len > header.*.caplen) {
        log.debug("Caught only part of a packet {d}/{d}\n", .{ header.*.caplen, header.*.len });
        return;
    } else {
        // _ = ethernet.captureEthernet(allocator, header, bytes) catch null;
        const rp: [*]const u8 = @ptrCast(bytes);
        const p = allocator.create(handlePacketArgs) catch return;
        p.packet = allocator.alloc(u8, header.*.caplen) catch return;

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
        .ipv4 => handleIpv4(pack.payload),
        .arp => handleArp(pack.payload),
        else => Error._NotAnActualError,
    } catch |err| {
        if (err != Error._NotAnActualError)
            log.err("Error handling {s} packet: {!}\n", .{ pack.etherType.name() orelse "unknown", err });
    };
}

fn handleIpv4(rawPacket: []u8) !void {
    const packet = try ipv4.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);
    defer allocator.free(packet.options);
    defer allocator.free(packet.payload);

    if (!(packet.protocol == .tcp or packet.protocol == .udp or packet.protocol == .icmp)) return;

    const destUuid = peer.IpUuid.get(packet.dest) orelse return;

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

    client.sendThread(lanPackS);
}

fn handleArp(rawPacket: []u8) !void {
    const packet = try arp.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);
    defer packet.free(allocator);

    if (packet.protocolType != .ipv4) return;

    const targetAddress = ipv4.fromByteSlice(packet.tPrAddr[0..4]);
    const sourceAddress = ipv4.fromByteSlice(packet.sPrAddr[0..4]);

    if (sourceAddress == main.TEST_HOST) {
        // log.debugS("Got an arp from the target\n");
        main.TEST_DEST_MAC = try mac.fromByteSlice(packet.sHwAddr[0..6]);
    }

    if (!peer.IpUuid.contains(targetAddress)) {
        // log.debugS("Got an arp, not responding\n");
        return;
    }

    const arpPacket = try arp.createIpv4Packet(allocator, main.TEST_MAC, try mac.fromByteSlice(packet.sHwAddr), @ptrCast(packet.tPrAddr), @ptrCast(packet.sPrAddr), .reply);
    defer allocator.destroy(arpPacket);
    defer arpPacket.free(allocator);
    const arpPacketS = try arp.serialize(allocator, arpPacket);
    defer allocator.free(arpPacketS);

    const ethernetPacket = try ethernet.createPacket(allocator, try mac.fromByteSlice(packet.sHwAddr), main.TEST_MAC, .arp, arpPacketS);
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
