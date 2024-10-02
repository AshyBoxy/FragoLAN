const std = @import("std");
const UUID = @import("../UUID.zig");
const ipv4 = @import("../ipv4.zig");
const rand = @import("../random.zig");
const log = @import("../log.zig");
const util = @import("../util.zig");

const allocator = std.heap.c_allocator;

const IpUuidType = std.AutoHashMap(ipv4.Address, UUID);
const UuidIpType = std.AutoHashMap(UUID, ipv4.Address);

const UuidList = std.SinglyLinkedList(UUID);

pub var IpUuid = IpUuidType.init(allocator);
pub var UuidIp = UuidIpType.init(allocator);
pub var count: u32 = 0;

pub const Peer = struct { uuid: UUID, ip: ipv4.Address };

/// this ignores any peer's set ip
pub fn processPeers(peers: []Peer) void {
    // TODO: thread safety...

    var uuidsToBeRemoved = UuidList{};

    // sorry
    var it = IpUuid.iterator();
    while (it.next()) |entry| {
        const uuid = entry.value_ptr.*;

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

        log.debug("Removing {} ({d})\n", .{ uuid, entry.key_ptr.* });
    }
    while (uuidsToBeRemoved.popFirst()) |node| {
        const ip = UuidIp.get(node.data);
        defer allocator.destroy(node);

        if (ip == null) {
            log.debug("Ip for {} is non existent?\n", .{node.data});
            continue;
        }

        log.debug("Removing {} ({d})\n", .{ node.data, ip.? });

        _ = IpUuid.remove(ip.?);
        _ = UuidIp.remove(node.data);
    }

    for (peers) |p| {
        if (UuidIp.get(p.uuid) != null) continue;

        const ip = getRandomIpAddress();

        UuidIp.put(p.uuid, ip) catch |err| util.panic("Error updating peers", err);
        IpUuid.put(p.ip, p.uuid) catch |err| util.panic("Error updating peers", err);
    }

    count = IpUuid.count();
}

pub fn getRandomIpAddress() ipv4.Address {
    return rand.int(ipv4.Address);
}
