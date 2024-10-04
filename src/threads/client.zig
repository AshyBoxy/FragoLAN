const std = @import("std");
const log = @import("../log.zig");
const lan = @import("../lan/packet.zig");
const peer = @import("../lan/peer.zig");
const ipv4 = @import("../ipv4.zig");
const main = @import("../main.zig");
const ethernet = @import("../ethernet.zig");
const pcap = @import("pcap.zig");

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
        const firstKeepAliveI = try lan.keepalive.createPacket(allocator, &[0]peer.Peer{});
        defer allocator.destroy(firstKeepAliveI);
        const firstKeepAliveIS = try firstKeepAliveI.serialize(allocator);
        defer allocator.free(firstKeepAliveIS);
        const firstKeepAliveP = try lan.createPacket(allocator, lan.Type.KeepAlive, firstKeepAliveIS);
        defer allocator.destroy(firstKeepAliveP);
        const firstKeepAlivePS = try firstKeepAliveP.serialize(allocator);
        defer allocator.free(firstKeepAlivePS);

        _ = try send(firstKeepAlivePS);
        // log.debug("Sent {d} bytes for first KeepAlive\n", .{sent});
    }

    while (true) {
        const recv = try std.posix.recv(sock, buf[0..], 0);

        const bytes = buf[0..recv];
        const packet = lan.parsePacket(allocator, bytes) catch continue;
        defer allocator.destroy(packet);
        defer allocator.free(packet.payload);

        if (packet.type == .KeepAlive) handleKeepAlive(bytes[2..]) catch |err| {
            log.err("Error handling KeepAlive: {}\n", .{err});
        } else {
            const packet2 = try allocator.create(lan.Packet);
            errdefer allocator.destroy(packet2);
            packet2.type = packet.type;
            packet2.payload = try allocator.dupe(u8, packet.payload);

            // log.debug("Received {d} bytes\n", .{recv});
            @import("./pool.zig").push(handlePacket, packet2);
        }
    }
}

fn handleKeepAlive(rawPacket: []u8) !void {
    const packet = try lan.keepalive.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);

    // log.log("Got a KeepAlive from the server with {d} clients\n", .{packet.clients});
    peer.processPeers(packet.peers);
}

const Error = error{
// sorry again
_NotAnActualError};
fn handlePacket(packet: *lan.Packet) void {
    defer allocator.destroy(packet);
    defer allocator.free(packet.payload);

    const name = packet.type.name();
    if (name != null) {
        // log.debug("Got a {s} from the server\n", .{name.?});
    } else log.debug("Got unknown packet 0x{x} from the server\n", .{@intFromEnum(packet.type)});

    _ = switch (packet.type) {
        .IPv4 => handleIpv4(packet),
        .KeepAlive => unreachable,
        else => Error._NotAnActualError,
    } catch |err| {
        if (err != Error._NotAnActualError)
            log.err("Error handling {s} packet: {!}\n", .{ packet.type.name() orelse "unknown", err });
    };
}

fn handleIpv4(rawPacket: *lan.Packet) !void {
    const packet = try lan.ipv4.parsePacket(allocator, rawPacket.payload);
    defer allocator.destroy(packet);
    defer packet.free(allocator);

    if (!packet.dest.eql(main.TEST_UUID)) return;

    // the inner ipv4 packet is kept intact for the most part, so it just needs stitching back together
    const ipv4Packet = try allocator.alloc(u8, packet.header.len + 4 + 4 + packet.options.len + packet.payload.len);
    defer allocator.free(ipv4Packet);

    @memcpy(ipv4Packet[0..12], packet.header[0..12]);
    ipv4.toByteSlice(peer.UuidIp.get(packet.source) orelse return, ipv4Packet[12..16]);
    ipv4.toByteSlice(main.TEST_HOST, ipv4Packet[16..20]);

    std.mem.writeInt(u16, ipv4Packet[10..12], ipv4.calculateChecksum(ipv4Packet[0..20]), std.builtin.Endian.big);

    const payloadStart = 20 + packet.options.len;
    @memcpy(ipv4Packet[20..payloadStart], packet.options);
    @memcpy(ipv4Packet[payloadStart..], packet.payload);

    // tcp and udp's checksums include the source and destination ip addresses
    switch (ipv4Packet[9]) {
        // tcp
        6 => {
            const checksum = ipv4.tcpCalculateChecksum(ipv4Packet[12..20], ipv4Packet[payloadStart..]);
            std.mem.writeInt(u16, @ptrCast(ipv4Packet[payloadStart + 16 .. payloadStart + 18]), checksum, std.builtin.Endian.big);
        },
        else => {},
    }

    const p = try ethernet.createPacket(allocator, main.TEST_DEST_MAC, main.TEST_MAC, .ipv4, ipv4Packet);
    defer allocator.destroy(p);
    defer allocator.free(p.payload);
    const ps = try p.serialize(allocator);
    defer allocator.free(ps);

    // hm.
    // TODO: respect when don't fragment is not set
    if (ps.len > 1518) {
        
    }

    _ = pcap.inject(ps) catch |err| switch (err) {
        pcap.Error.PcapError => {
            log.debug("Error injecting ipv4 packet: {s}\n", .{pcap.geterr()});
            log.debug("ethernet len: {d}, ipv4 len: {d}, payload len: {d}\n", .{ps.len, ipv4Packet.len, packet.payload.len});
        },
        else => return err,
    };
    // log.debug("Injected an ipv4 packet {d} bytes long\n", .{size});
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
    // log.debug("Sent {d} bytes\n", .{sent});
    _ = sent;
}
