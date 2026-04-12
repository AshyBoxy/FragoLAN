const std = @import("std");
const UUID = @import("../UUID.zig");
const ipv4 = @import("../ipv4.zig");
const rand = @import("../random.zig");
const log = @import("../log.zig");
const util = @import("../util.zig");
const main = @import("root");
const config = @import("../config.zig");

const allocator = std.heap.c_allocator;

const IpUuidType = std.AutoHashMap(ipv4.Address, UUID);
const UuidIpType = std.AutoHashMap(UUID, ipv4.Address);

// const UuidList = std.SinglyLinkedList(UUID);
const UuidListEntry = struct { uuid: UUID, node: std.SinglyLinkedList.Node };

pub var IpUuid = IpUuidType.init(allocator);
pub var UuidIp = UuidIpType.init(allocator);
pub var count: u32 = 0;

pub const Peer = struct { uuid: UUID, ip: ipv4.Address };

pub const Error = error{NoneAvailable};

/// this ignores any peer's set ip
pub fn processPeers(peers: []Peer) void {
    // TODO: thread safety...

    var uuidsToBeRemoved = std.SinglyLinkedList{};

    // sorry
    var it = UuidIp.iterator();
    while (it.next()) |entry| {
        const uuid = entry.key_ptr.*;

        var b = false;
        for (peers) |p| {
            if (uuid.eql(p.uuid)) {
                b = true;
                break;
            }
        }
        if (b) continue;

        const u = allocator.create(UuidListEntry) catch |err| {
            std.debug.panic("Error creating uuid node: {}\n", .{err});
        };
        u.uuid = uuid;
        uuidsToBeRemoved.prepend(&u.node);

        // log.debug("Removing {} ({d})\n", .{ uuid, entry.key_ptr.* });
    }
    while (uuidsToBeRemoved.popFirst()) |node| {
        const u: *UuidListEntry = @fieldParentPtr("node", node);
        const ip = UuidIp.get(u.uuid);
        defer allocator.destroy(u);

        // log.debug("Removing {} ({d})\n", .{ node.data, ip orelse 0 });
        logPeerUpdate(true, u.uuid, ip) catch |e| {
            log.debug("Error logging peer leaving: {any}", .{e});
        };

        const uuidRemoved = UuidIp.remove(u.uuid);
        if (!uuidRemoved) log.debug("{f} was not in uuids?\n", .{u.uuid});

        if (ip == null) {
            log.debug("Ip for {f} is non existent?\n", .{u.uuid});
            continue;
        }

        const ipRemoved = IpUuid.remove(ip.?);
        if (!ipRemoved) log.debug("{d} was not in ips?\n", .{ip.?});
    }

    for (peers) |p| {
        if (UuidIp.get(p.uuid) != null) continue;

        const ip = getRandomIpAddress() catch |err| {
            switch (err) {
                Error.NoneAvailable => {
                    log.err("Ran out of ip addresses adding {f}\n", .{p.uuid});
                },
                else => {
                    log.err("Error getting ip address: {any}\n", .{err});
                },
            }
            break;
        };

        UuidIp.put(p.uuid, ip) catch |err| util.panic("Error updating peers", err);
        IpUuid.put(ip, p.uuid) catch |err| util.panic("Error updating peers", err);

        logPeerUpdate(false, p.uuid, ip) catch |e| {
            log.debug("Error logging peer joining: {any}", .{e});
        };
    }

    count = IpUuid.count();
}

pub fn getRandomIpAddress() !ipv4.Address {
    var ips = try allocator.alloc(ipv4.Address, config.g.lastIp - config.g.firstIp);
    defer allocator.free(ips);
    ips.len = 0;

    log.debug("ips len: {d}\n", .{ips.len});

    for (config.g.firstIp..config.g.lastIp) |_ip| {
        const ip: ipv4.Address = @intCast(_ip);

        if (IpUuid.contains(ip)) continue;

        log.debug("ip {d} ({d})\n", .{ ip, ips.len });

        ips.len += 1;
        ips[ips.len - 1] = ip;
    }

    if (ips.len < 1) return Error.NoneAvailable;

    return ips[rand.rand.uintLessThan(usize, ips.len)];
}

fn logPeerUpdate(comptime leaving: bool, uuid: UUID, ip: ?ipv4.Address) !void {
    var buf: [50]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();

    var ipBuf: []const u8 = undefined;
    if (ip) |i| {
        ipBuf = try ipv4.format(a, i);
    } else {
        // ipBuf = try util.makeString(a, "(no ip)");
        ipBuf = "(no ip)";
    }

    log.log("Peer " ++ (if (leaving) "left" else "join") ++ ": {f} {s}\n", .{ uuid, ipBuf });
}
