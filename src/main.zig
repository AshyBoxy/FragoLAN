const std = @import("std");
pub const c = @import("c").c;
const log = @import("log.zig");
const ethernet = @import("ethernet.zig");
const arp = @import("arp.zig");
const mac = @import("mac.zig");
const ipv4 = @import("ipv4.zig");
const UUID = @import("UUID.zig");
const config = @import("config.zig");
const util = @import("util.zig");

pub var allocator = std.heap.c_allocator;
// const TEST_DEVICE = "veth1";
// const TEST_DEVICE = "br0";
// pub const TEST_HOST = ipv4.fromByteSlice(.{ 10, 13, 65, 74 });

// pub const TEST_HOST = ipv4.fromInts(10, 13, 37, 2);
// pub const TEST_FIRST_IP = ipv4.fromInts(10, 13, 70, 1);
// pub const TEST_LAST_IP = ipv4.fromInts(10, 13, 70, 5);
// pub const TEST_MAC: mac.MacAddress = 0x5a4d5a8359c7;

// pub const TEST_HOST = ipv4.fromInts(192, 168, 2, 6);
// pub const TEST_FIRST_IP = ipv4.fromInts(192, 168, 2, 220);
// pub const TEST_LAST_IP = ipv4.fromInts(192, 168, 2, 225);
// pub const TEST_MAC: mac.MacAddress = 0xeee0561b83cd;

pub var TEST_DEST_MAC = mac.Broadcast;
pub var TEST_UUID = UUID{};
pub const debugUseGpa: bool = false;

var pool: std.Thread.Pool = undefined;

pub fn main() !u8 {
    // TODO: none of the defers in here end up running
    // this is mostly relevant for the gpa
    // but some memory is held longer than necessary

    log.name = "Main";

    const logThread = try std.Thread.spawn(.{}, log.loop, .{});
    _ = logThread.setName("lan_log") catch null;
    logThread.detach();

    try @import("random.zig").init();

    TEST_UUID.setRandom();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    if (debugUseGpa) {
        defer {
            const gpaStatus = gpa.deinit();
            if (gpaStatus == .leak) {
                log.err("Memory has been leaked", .{});
            }
        }
        allocator = gpa.allocator();
    }


    const args = try std.process.argsAlloc(allocator);
    // log.debug("Got {d} args\n", .{args.len});
    // for (args, 0..args.len) |arg, i| {
    //     log.debug("arg {d}: {s}\n", .{i, arg});
    // }
    if (args.len > 1) {
        if (util.streq(args[1], "interfaces")) {
            return findAllDevs(allocator);
        }
        if (util.streq(args[1], "test")) {
            var ret: u8 = 0;
            if (args.len < 3) {
                log.logS("which test though, hm?\n");
                ret = 5;
            } else if (util.streq(args[2], "pia")) {
                ret = try @import("./lan/pia.zig")._test(allocator);
            } else {
                log.log("unknown test {s}\n", .{args[2]});
                ret = 5;
            }

            log.wait();
            return ret;
        }
    }
    std.process.argsFree(allocator, args);


    try config.loadConfig(allocator);
    if (!config.checkConfigValid()) {
        log.wait();
        return 4;
    }

    const handle = @import("./init/pcap.zig").init(allocator) catch return 2;
    defer @import("./init/pcap.zig").free(allocator, handle);

    // test injection
    const testSrcMac: u48 = 0x220000694200;
    const testDestMac = mac.Broadcast;
    const testSrcIp = [_]u8{ 172, 30, 0, 1 };
    // const testDestIp = .{ 172, 30, 0, 2 };
    const testDestIp = [_]u8{ 10, 0, 69, 51 };

    const arpPacket = try arp.createIpv4Packet(allocator, testSrcMac, testDestMac, &testSrcIp, &testDestIp, arp.Operation.request);
    defer arpPacket.free(allocator);
    defer allocator.destroy(arpPacket);
    const arpPayload = try arp.serialize(allocator, arpPacket);
    defer allocator.free(arpPayload);

    const ethernetPacket = try ethernet.createPacket(allocator, testDestMac, testSrcMac, ethernet.EtherType.arp, arpPayload);
    defer allocator.destroy(ethernetPacket);
    const ethernetPayload = try ethernet.serialize(allocator, ethernetPacket);

    const injectResult = c.pcap_inject(handle, ethernetPayload.ptr, ethernetPayload.len);
    if (injectResult == c.PCAP_ERROR) {
        log.debug("Error injecting packet: {s}\n", .{c.pcap_geterr(handle)});
    }

    @import("./lan/pia.zig").init(allocator);
    try @import("./threads/pool.zig").start();

    const pcapThread = try std.Thread.spawn(.{}, @import("./threads/pcap.zig").loop, .{@intFromPtr(handle.?)});
    _ = pcapThread.setName("lan_pcap") catch null;

    const clientThread = try std.Thread.spawn(.{}, @import("./threads/client.zig").loop, .{});
    _ = clientThread.setName("lan_client") catch null;

    const scheduleThread = try std.Thread.spawn(.{}, @import("./threads/schedule.zig").loop, .{});
    _ = scheduleThread.setName("lan_sched") catch null;
    scheduleThread.detach();

    // tryTest();

    pcapThread.join();
    clientThread.join();

    log.wait();

    return 0;
}

fn findAllDevs(a: std.mem.Allocator) !u8 {
    const errbuf: [:0]u8 = a.allocSentinel(u8, @sizeOf(u8) * c.PCAP_ERRBUF_SIZE, 0) catch |e| util.panic("glup {any}", e);
    var ifs: ?*c.pcap_if_t = null;
    const ifsp = &ifs;

    const err = c.pcap_findalldevs(ifsp, errbuf.ptr);
    if (err != 0) {
        log.err("Failed looking for interfaces: {s}\n", .{errbuf});
        return 1;
    }

    if (ifs == null) {
        log.logS("No interfaces found\n");
        return 0;
    }

    log.logS("Found interfaces:\n");
    var el = ifs;
    while (el) |i| {
        log.logN("- {s}", .{i.name}, false);
        if (i.description) |d| {
            log.logN(" ({s})", .{d}, false);
        }
        log.logN("\n", .{}, false);
        el = i.next;
    }

    log.wait();
    return 0;
}

fn tryTest() void {
    std.time.sleep(2 * 1000 * 1000);
    for (1..101) |i| {
        const num = allocator.create(usize) catch return;
        num.* = i;
        @import("./threads/pool.zig").push(testRun, num);
    }
}
fn testRun(num: *usize) void {
    log.debug("Ran testRun() {d}\n", .{num.*});
    allocator.destroy(num);
}
