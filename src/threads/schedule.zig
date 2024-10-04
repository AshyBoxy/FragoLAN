const std = @import("std");
const log = @import("../log.zig");
const keepalive = @import("../lan/keepalive.zig");
const lan = @import("../lan/packet.zig");
const client = @import("client.zig");
const peer = @import("../lan/peer.zig");
const ipv4 = @import("../ipv4.zig");
const arp = @import("../arp.zig");
const ethernet = @import("../ethernet.zig");
const main = @import("../main.zig");
const mac = @import("../mac.zig");
const pcap = @import("../threads/pcap.zig");

const allocator = std.heap.c_allocator;

var iteration: u64 = 0;

pub fn loop() void {
    log.name = "Sched";

    _ = findHost(main.TEST_HOST) catch null;

    while (true) {
        std.time.sleep(500 * 1000 * 1000);

        iteration +%= 1;

        _ = doKeepAlive() catch null;

        if (iteration % 10 == 0) {
            log.log("We know about {d} peers\n", .{peer.UuidIp.count()});
            var it = peer.UuidIp.iterator();

            while (it.next()) |entry| {
                const fmtIp = ipv4.format(allocator, entry.value_ptr.*) catch continue;
                defer allocator.free(fmtIp);

                log.debug("{}: {s} ({d})\n", .{ entry.key_ptr.*, fmtIp, entry.value_ptr.* });
            }

            if (main.TEST_DEST_MAC == mac.Broadcast) _ = findHost(main.TEST_HOST) catch null;
        }

        if (iteration % 50 == 0) {
            _ = findHost(main.TEST_HOST) catch null;
        }
    }
}

fn doKeepAlive() !void {
    const peers: [1]peer.Peer = .{peer.Peer{ .uuid = @import("root").TEST_UUID, .ip = 0 }};

    const keepAlivePacket = try keepalive.createPacket(allocator, &peers);
    defer allocator.destroy(keepAlivePacket);
    defer keepAlivePacket.free(allocator);

    const keepAlivePacketS = try keepAlivePacket.serialize(allocator);
    defer allocator.free(keepAlivePacketS);

    const lanPacket = try lan.createPacket(allocator, lan.Type.KeepAlive, keepAlivePacketS);
    defer allocator.destroy(lanPacket);
    defer lanPacket.free(allocator);

    const lanPacketS = try lanPacket.serialize(allocator);
    client.sendThread(lanPacketS);
}

/// sends out an arp packet asking `address` to respond
pub fn findHost(address: ipv4.Address) !void {
    var destIp: [4]u8 = undefined;
    ipv4.toByteSlice(address, &destIp);
    var srcIp: [4]u8 = undefined;
    ipv4.toByteSlice(0, &srcIp);

    const arpPacket = try arp.createIpv4Packet(allocator, main.TEST_MAC, mac.Broadcast, &srcIp, &destIp, .request);
    defer allocator.destroy(arpPacket);
    defer arpPacket.free(allocator);
    const arpPacketS = try arp.serialize(allocator, arpPacket);
    defer allocator.free(arpPacketS);

    const packet = try ethernet.createPacket(allocator, mac.Broadcast, main.TEST_MAC, .arp, arpPacketS);
    defer allocator.destroy(packet);
    defer allocator.free(packet.payload);
    const packetS = try packet.serialize(allocator);
    defer allocator.free(packetS);

    _ = try pcap.inject(packetS);
}
