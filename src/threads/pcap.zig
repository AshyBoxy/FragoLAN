const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});
const log = @import("../log.zig");
const ethernet = @import("../ethernet.zig");
const ipv4 = @import("../ipv4.zig");
const lan = @import("../lan/packet.zig");
const client = @import("./client.zig");

// solving double free issues...
var allocator: std.mem.Allocator = undefined;

const debug_runpcap = true;

pub fn loop(handle: ?*c.pcap_t) void {
    allocator = @import("root").allocator;

    log.name = "PCap";

    log.log("pcap thread started with id: {d}\n", .{std.Thread.getCurrentId()});

    if (!debug_runpcap) {
        log.logS("Cancelling pcap thread\n");
        return;
    }

    const loopResult = c.pcap_loop(handle, 0, lanPcapLoop, null);
    if (loopResult == 0) {
        log.debugS("Tried to start pcap_loop after closing pcap?\n");
    } else {
        log.debug("Error when attempting to run pcap_loop: ({d}) {s}\n", .{ loopResult, c.pcap_geterr(handle) });
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

const handlePacketArgs = struct { packet: []u8 };

fn handlePacket(packet: *handlePacketArgs) void {
    log.log("Caught a packet with length: {d}\n", .{packet.packet.len});

    defer allocator.destroy(packet);
    defer allocator.free(packet.packet);

    const pack = ethernet.parsePacket(allocator, packet.packet) catch return;
    _ = switch(pack.etherType) {
        .ipv4 => handleIpv4(pack.payload) catch null,
        else => null
    };
}

fn handleIpv4(rawPacket: []u8) !void {
    const packet = try ipv4.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);
    defer allocator.free(packet.options);
    defer allocator.free(packet.payload);

    if(!(packet.protocol == .tcp or packet.protocol == .udp)) return;

    const header = try packet.serializeHeader(allocator);
    defer allocator.destroy(header);

    const lanIpPack = try lan.ipv4.createPacket(allocator, lan.ipv4.MAX_UUID, lan.ipv4.MAX_UUID, header.*, packet.options, packet.payload);
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
