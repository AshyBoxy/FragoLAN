const builtin = @import("builtin");
const std = @import("std");
const log = @import("../log.zig");
const lan = @import("../lan/packet.zig");
const peer = @import("../lan/peer.zig");
const ipv4 = @import("../ipv4.zig");
const main = @import("../main.zig");
const ethernet = @import("../ethernet.zig");
const pcap = @import("pcap.zig");
const config = @import("../config.zig");
const mac = @import("../mac.zig");
const UUID = @import("../UUID.zig");
const util = @import("../util.zig");
const pia = @import("../lan/pia.zig");
const pool = @import("./pool.zig");

const Error = error{
    // TODO: better name for this error
    NoAddress, _NotAnActualError };

pub const allocator = std.heap.c_allocator;

var sock: std.posix.socket_t = undefined;

pub fn loop() void {
    log.name = "Client";
    log.log("Starting up with id: {d}\n", .{std.Thread.getCurrentId()});
    _loop() catch |err| {
        log.err("{}\n", .{err});
    };
}

fn _loop() !void {
    // const addr = try std.net.Address.parseIp(TEST_ADDRESS, TEST_PORT);
    sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    // TODO: handle errors gracefully
    log.log("Connecting to {s}:{d}\n", .{ config.g.server_address, config.g.server_port });
    const addressList = getAddress(allocator, &config.g.server_address, config.g.server_port) catch |e| util.panic("Unable to connect to server", e);
    for (addressList.addrs) |a| {
        log.debug("Trying {f} / [{f}]\n", .{ a.in, a.in6 });
        std.posix.connect(sock, &a.any, a.getOsSockLen()) catch |e| {
            log.debug("Failed to connect: {any}\n", .{e});
            continue;
        };
        break;
    } else {
        util.panic("Unable to connect to server", error.UnableToConnect);
    }

    var buf: [65535]u8 = undefined;

    log.debug("sock: {" ++ (if (builtin.os.tag == .windows) "any" else "d") ++ "}\n", .{sock});

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
        const recv = std.posix.recv(sock, buf[0..], 0) catch |e| {
            log.err("Error receiving on socket: {any}\n", .{e});
            continue;
        };

        const bytes = buf[0..recv];
        const packet = lan.parsePacket(allocator, bytes) catch continue;

        if (packet.type == .KeepAlive) {
            defer allocator.destroy(packet);
            defer packet.free(allocator);

            handleKeepAlive(bytes[2..]) catch |err| {
                log.err("Error handling KeepAlive: {}\n", .{err});
            };
        } else {
            // log.debug("Got a {s} packet from the server\n", .{packet.type.name() orelse "unknown"});
            // log.debug("Received {d} bytes\n", .{recv});
            @import("./pool.zig").push(handlePacket, packet);
        }
    }

    log.err("Client loop unexpectedly ended\n", .{});
}

fn getAddress(a: std.mem.Allocator, address: []const u8, port: u16) !*std.net.AddressList {
    // todo: handle gracefully
    const list = try std.net.getAddressList(a, address, port);
    if (list.addrs.len < 1) {
        list.deinit();
        return Error.NoAddress;
    }

    return list;
}

fn handleKeepAlive(rawPacket: []u8) !void {
    const packet = try lan.keepalive.parsePacket(allocator, rawPacket);
    defer allocator.destroy(packet);

    // log.log("Got a KeepAlive from the server with {d} clients\n", .{packet.clients});
    peer.processPeers(packet.peers);
}

fn handlePacket(packet: *lan.Packet) void {
    defer packet.freeA(allocator);

    const name = packet.type.name();
    if (name != null) {
        log.debug("Got a {s} from the server\n", .{name.?});
    } else log.debug("Got unknown packet {d} from the server\n", .{@intFromEnum(packet.type)});

    _ = switch (packet.type) {
        .KeepAlive => unreachable,
        .IPv4 => ipv4utils.handleIpv4Lan(packet),
        .PiaBrowseRequest => pia.lanClient.handleBrowseRequest(packet),
        .PiaBrowseReply => pia.lanClient.handleBrowseReply(packet),
        else => log.debug("Unable to handle packet from server: {d}\n", .{@intFromEnum(packet.type)}),
    } catch |err| {
        if (err != Error._NotAnActualError)
            log.err("Error handling {s} packet: {}\n", .{ packet.type.name() orelse "unknown", err });
    };
}

pub const ipv4utils = struct {
    fn handleIpv4Lan(rawPacket: *lan.Packet) !void {
        const packet = try lan.ipv4.parsePacket(allocator, rawPacket.payload);
        defer allocator.destroy(packet);
        defer packet.free(allocator);

        if (!(packet.dest.eql(main.TEST_UUID) or packet.dest.eql(UUID.BROADCAST))) return;

        // the inner ipv4 packet is kept intact for the most part, so it just needs stitching back together
        const ipv4Packet = try allocator.alloc(u8, packet.header.len + 4 + 4 + packet.options.len + packet.payload.len);
        defer allocator.free(ipv4Packet);

        @memcpy(ipv4Packet[0..12], packet.header[0..12]);

        const payloadStart = 20 + packet.options.len;
        @memcpy(ipv4Packet[20..payloadStart], packet.options);
        @memcpy(ipv4Packet[payloadStart..], packet.payload);

        handleIpv4(ipv4Packet, packet.source, packet.dest) catch |err| {
            log.err("Error handling an IPv4 packet from the server: {}\n", .{err});
        };
    }

    /// takes a full ipv4 packet except source and dest ips, and checksums
    pub fn handleIpv4(ipv4Packet: []u8, source: UUID, dest: UUID) !void {
        const sourceIp = peer.UuidIp.get(source) orelse {
            log.debug("Couldn't find source ip for {f} for an IPv4 packet\n", .{source});
            return;
        };
        const destIp = if (dest.eql(UUID.BROADCAST)) config.g.broadcast else config.g.host;

        ipv4.toByteSlice(sourceIp, ipv4Packet[12..16]);
        ipv4.toByteSlice(destIp, ipv4Packet[16..20]);

        std.mem.writeInt(u16, ipv4Packet[10..12], ipv4.calculateChecksum(ipv4Packet[0..20]), std.builtin.Endian.big);

        const optionsLen = (ipv4Packet[0] & 0x0F) * 4 - 20;
        if (optionsLen < 0) {
            log.err("Invalid options length in IPv4 packet: {d}\n", .{optionsLen});
            return;
        }
        const payloadStart = 20 + optionsLen;

        // tcp and udp's checksums include the source and destination ip addresses
        switch (ipv4Packet[9]) {
            // tcp
            6 => {
                const checksum = ipv4.tcpCalculateChecksum(ipv4Packet[12..20], ipv4Packet[payloadStart..]);
                std.mem.writeInt(u16, @ptrCast(ipv4Packet[payloadStart + 16 .. payloadStart + 18]), checksum, std.builtin.Endian.big);
            },
            // udp
            17 => {
                const checksum: u16 = ipv4.udpCalculateChecksum(ipv4Packet[12..20], ipv4Packet[payloadStart..]);
                std.mem.writeInt(u16, @ptrCast(ipv4Packet[payloadStart + 6 .. payloadStart + 8]), checksum, .big);
            },
            else => {},
        }

        const p = try ethernet.createPacket(allocator, if (dest.eql(UUID.BROADCAST)) mac.Broadcast else main.TEST_DEST_MAC, config.g.mac, .ipv4, ipv4Packet);
        defer allocator.destroy(p);
        defer allocator.free(p.payload);
        const ps = try p.serialize(allocator);
        defer allocator.free(ps);

        // hm.
        // TODO: respect when don't fragment is not set
        if (ps.len > 1518) {
            // TODO: warn
            // log.log("Skipping injecting a too long packet ({d} bytes) (lan packet payload was {d} bytes)\nRaw packet: {x}\n", .{ ps.len, rawPacket.payload.len, ps });
            // log.log("Skipping injecting a too long packet ({d} bytes) (lan packet payload was {d} bytes)\n", .{ ps.len, rawPacket.payload.len });
            log.log("Skipping injecting a too long packet ({d} bytes)\n", .{ps.len});
            return;
        }

        const size = pcap.inject(ps) catch |err| blk: {
            switch (err) {
                pcap.Error.PcapError => {
                    log.debug("Error injecting ipv4 packet: {s}\n", .{pcap.geterr()});
                    // log.debug("ethernet len: {d}, ipv4 len: {d}, payload len: {d}\n", .{ ps.len, ipv4Packet.len, packet.payload.len });
                    log.debug("ethernet len: {d}, ipv4 len: {d}\n", .{ ps.len, ipv4Packet.len });
                },
                else => return err,
            }
            break :blk 0;
        };
        if (size > 0) log.debug("Injected an ipv4 packet {d} bytes long\n", .{size});
    }

    /// takes source and dest uuids, source and dest port, and a payload
    pub fn handleUdp(source: UUID, dest: UUID, srcPort: u16, dstPort: u16, payload: []u8) !void {
        const udp = try allocator.alloc(u8, 8 + payload.len);
        defer allocator.free(udp);

        std.mem.writeInt(u16, udp[0..2], srcPort, .big);
        std.mem.writeInt(u16, udp[2..4], dstPort, .big);
        std.mem.writeInt(u16, udp[4..6], @intCast(8 + payload.len), .big);

        // checksum is handled in handleIpv4

        @memcpy(udp[8..], payload);

        const p4 = try ipv4.createPacket(allocator, 0, .udp, 0, 0, udp);
        defer allocator.destroy(p4);
        defer allocator.free(p4.payload);
        defer allocator.free(p4.options);

        const p4Payload = try p4.serialize(allocator);
        defer allocator.free(p4Payload);

        return handleIpv4(p4Payload, source, dest);
    }
};

pub fn send(payload: []const u8) std.posix.SendError!usize {
    return try std.posix.send(sock, payload, 0);
}

const sendThreadArgs = struct { payload: []const u8 };
pub fn sendThread(payload: []const u8) void {
    const p = allocator.dupe(u8, payload) catch return;
    const args = allocator.create(sendThreadArgs) catch |e| {
        log.err("Failed to create send thread args: {any}\n", .{e});
        allocator.free(p);
        return;
    };
    args.payload = p;

    @import("./pool.zig").push(_sendThread, args);
}
fn _sendThread(args: *sendThreadArgs) void {
    defer allocator.destroy(args);
    defer allocator.free(args.payload);

    const sent = send(args.payload) catch |e| {
        switch (e) {
            std.posix.SendError.MessageTooBig => {
                log.err("Tried to send a too big ({d} bytes) packet to the server\n", .{args.payload.len});
            },
            else => {
                log.err("Error sending packet to the server: {any}\n", .{e});
            },
        }
        return;
    };
    // log.debug("Sent {d} bytes\n", .{sent});
    _ = sent;
}
