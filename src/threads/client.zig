const std = @import("std");
const log = @import("../log.zig");
const lanPacket = @import("../lan/packet.zig");

const allocator = std.heap.c_allocator;

const address = "127.0.0.1";
const port = 6969;

var sock: std.posix.socket_t = undefined;

pub fn loop() void {
    log.name = "Client";
    log.logS("Starting up\n");
    _loop() catch |err| {
        log.err("{}\n", .{err});
    };
}

fn _loop() !void {
    const addr = try std.net.Address.parseIp4(address, port);
    sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());

    var buf: [4096]u8 = undefined;

    try addr.in.format("", .{}, std.io.getStdOut().writer());
    log.debugN("\n{d}, {d}\n", .{ addr.getPort(), sock }, false);

    {
        const firstKeepAliveI = try lanPacket.keepalive.createPacket(allocator, 0);
        defer allocator.destroy(firstKeepAliveI);
        const firstKeepAliveIS = try firstKeepAliveI.serialize(allocator);
        defer allocator.free(firstKeepAliveIS);
        const firstKeepAliveP = try lanPacket.createPacket(allocator, lanPacket.Type.KeepAlive, firstKeepAliveIS);
        defer allocator.destroy(firstKeepAliveP);
        const firstKeepAlivePS = try firstKeepAliveP.serialize(allocator);
        defer allocator.free(firstKeepAlivePS);

        const sent = try send(firstKeepAlivePS);
        log.debug("Sent {d} bytes for first KeepAlive\n", .{sent});
    }

    while (true) {
        const recv = try std.posix.recv(sock, buf[0..], 0);
        log.debug("Received {d} bytes\n", .{recv});

        const bytes = buf[0..recv];
        const packet = lanPacket.parsePacket(allocator, bytes) catch continue;
        defer allocator.destroy(packet);
        defer allocator.free(packet.payload);

        if (packet.type == .KeepAlive) handleKeepAlive(bytes[2..]) catch |err| {
            log.err("Error handling KeepAlive: {}\n", .{err});
        } else {
            const packet2 = try allocator.create(lanPacket.Packet);
            errdefer allocator.destroy(packet2);
            packet2.payload = try allocator.dupe(u8, packet.payload);
            @import("./pool.zig").push(handlePacket, packet2);
        }
    }
}

fn handleKeepAlive(rawPacket: []u8) !void {
    const packet = try lanPacket.keepalive.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);

    log.log("Got a KeepAlive from the server with {d} clients\n", .{packet.clients});
}

fn handlePacket(packet: *lanPacket.Packet) void {
    defer allocator.destroy(packet);
    defer allocator.free(packet.payload);

    log.debug("Got a {s} from the server\n", .{packet.type.name() orelse "unknown"});
}

pub fn send(payload: []const u8) !usize {
    return try std.posix.send(sock, payload, 0);
}

const sendThreadArgs = struct { payload: []const u8 };
pub fn sendThread(payload: []const u8) void {
    const p = allocator.dupe(u8, payload) catch return;
    errdefer allocator.free(p); // this might not run?
    const args = allocator.create(sendThreadArgs) catch return;
    args.payload = p;

    @import("./pool.zig").push(_sendThread, args);
}
fn _sendThread(args: *sendThreadArgs) void {
    defer allocator.destroy(args);
    defer allocator.free(args.payload);

    const sent = send(args.payload) catch return;
    log.debug("Sent {d} bytes\n", .{sent});
}
