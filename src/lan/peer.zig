const std = @import("std");
const UUID = @import("../UUID.zig");
const ipv4 = @import("../ipv4.zig");
const rand = @import("../random.zig");
const log = @import("../log.zig");
const util = @import("../util.zig");
const main = @import("root");

const allocator = std.heap.c_allocator;

const IpUuidType = std.AutoHashMap(ipv4.Address, UUID);
const UuidIpType = std.AutoHashMap(UUID, ipv4.Address);

const UuidList = std.SinglyLinkedList(UUID);

pub var IpUuid = IpUuidType.init(allocator);
pub var UuidIp = UuidIpType.init(allocator);
pub var count: u32 = 0;

pub const Peer = struct { uuid: UUID, ip: ipv4.Address };

pub const Error = error{NoneAvailable};

/// this ignores any peer's set ip
pub fn processPeers(peers: []Peer) void {
    // TODO: thread safety...

    var uuidsToBeRemoved = UuidList{};

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

        const u = allocator.create(UuidList.Node) catch |err| {
            std.debug.panic("Error creating uuid node: {!}\n", .{err});
        };
        u.data = uuid;
        uuidsToBeRemoved.prepend(u);

        // log.debug("Removing {} ({d})\n", .{ uuid, entry.key_ptr.* });
    }
    while (uuidsToBeRemoved.popFirst()) |node| {
        const ip = UuidIp.get(node.data);
        defer allocator.destroy(node);

        // log.debug("Removing {} ({d})\n", .{ node.data, ip orelse 0 });

        const uuidRemoved = UuidIp.remove(node.data);
        if (!uuidRemoved) log.debug("{} was not in uuids?\n", .{node.data});

        if (ip == null) {
            log.debug("Ip for {} is non existent?\n", .{node.data});
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
                    log.err("Ran out of ip addresses adding {}\n", .{p.uuid});
                },
                else => {
                    log.err("Error getting ip address: {}\n", .{err});
                },
            }
            break;
        };

        UuidIp.put(p.uuid, ip) catch |err| util.panic("Error updating peers", err);
        IpUuid.put(ip, p.uuid) catch |err| util.panic("Error updating peers", err);
    }

    count = IpUuid.count();
}

pub fn getRandomIpAddress() !ipv4.Address {
    var ips = try allocator.alloc(ipv4.Address, main.TEST_LAST_IP - main.TEST_FIRST_IP);
    defer allocator.free(ips);
    ips.len = 0;

    log.debug("ips len: {d}\n", .{ips.len});

    for (main.TEST_FIRST_IP..main.TEST_LAST_IP) |_ip| {
        const ip: ipv4.Address = @intCast(_ip);

        if (IpUuid.contains(ip)) continue;

        log.debug("ip {d} ({d})\n", .{ ip, ips.len });

        ips.len += 1;
        ips[ips.len - 1] = ip;
    }

    if (ips.len < 1) return Error.NoneAvailable;

    return ips[rand.rand.uintLessThan(usize, ips.len)];
}
