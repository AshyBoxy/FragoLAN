const std = @import("std");
const log = @import("../log.zig");
const keepalive = @import("../lan/keepalive.zig");
const lan = @import("../lan/packet.zig");
const client = @import("client.zig");
const peer = @import("../lan/peer.zig");
const ipv4 = @import("../ipv4.zig");

const allocator = std.heap.c_allocator;

var iteration: u64 = 0;

pub fn loop() void {
    log.name = "Sched";

    while (true) {
        std.time.sleep(500 * 1000 * 1000);

        iteration +%= 1;

        _ = doKeepAlive() catch null;

        if (iteration % 10 == 0) {
            log.log("We know about {d} peers\n", .{peer.count});
            var itUuid = peer.UuidIp.keyIterator();
            var itIp = peer.UuidIp.valueIterator();

            var ip: ipv4.Address = undefined;
            while (itUuid.next()) |uuid| : (ip = itIp.next().?.*) {
                const fmtIp = ipv4.format(allocator, ip) catch continue;
                defer allocator.free(fmtIp);

                log.debug("{}: {s} ({d})\n", .{ uuid, fmtIp, ip });
            }
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
