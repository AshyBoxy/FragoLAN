const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});
const log = @import("log.zig");
const ethernet = @import("ethernet.zig");
const arp = @import("arp.zig");
const mac = @import("mac.zig");
const ipv4 = @import("ipv4.zig");
const UUID = @import("UUID.zig");

pub var allocator = std.heap.c_allocator;
const TEST_DEVICE = "wlp5s0";
const TEST_FILTER = "ip host 10.13.65.74";
pub const TEST_HOST = ipv4.fromByteSlice(.{ 10, 13, 65, 74 }) catch unreachable;
pub var TEST_UUID = UUID{};

var pool: std.Thread.Pool = undefined;

pub fn main() !u8 {
    // TODO: none of the defers in here end up running
    // this is mostly relevant for the gpa
    // but some memory is held longer than necessary

    log.name = "Main";

    try @import("random.zig").init();

    TEST_UUID.setRandom();

    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer {
    //     const gpaStatus = gpa.deinit();
    //     if (gpaStatus == .leak) {
    //         log.err("Memory has been leaked", .{});
    //     }
    // }
    // allocator = gpa.allocator();

    const errbuf: [*:0]u8 = (try allocator.allocSentinel(u8, @sizeOf(u8) * c.PCAP_ERRBUF_SIZE, 0));
    defer allocator.free(std.mem.span(errbuf));
    var err: c_int = 0;

    // get handle, check if ethernet(-like)
    const handle = c.pcap_open_live(TEST_DEVICE, c.BUFSIZ, 1, 1000, errbuf);
    // i KNOW i read something on what to do in this situation, but i can't find it
    if (handle == null) {
        // this should be an error anyway
        // later this should be wrapped by a zig function which correctly returns the error
        log.err("Couldn't open {s}: {s}\n", .{ TEST_DEVICE, errbuf });
        return 2;
    }
    defer c.pcap_close(handle);

    if (c.pcap_datalink(handle) != c.DLT_EN10MB) {
        log.err("{s} doesn't use ethernet headers\n", .{TEST_DEVICE});
        return 2;
    }

    // compile and apply filter
    const bpf_program = try allocator.create(c.struct_bpf_program);
    defer allocator.destroy(bpf_program);
    err = c.pcap_compile(handle, bpf_program, TEST_FILTER, 1, 0);
    if (err == -1) {
        log.err("Couldn't compile filter {s}: {s}\n", .{ TEST_FILTER, c.pcap_geterr(handle) });
        return 2;
    }

    err = c.pcap_setfilter(handle, bpf_program);
    if (err == -1) {
        log.err("Couldn't set filter {s}: {s}\n", .{ TEST_FILTER, c.pcap_geterr(handle) });
        return 2;
    }

    // test injection
    const testSrcMac: u48 = 0x220000694200;
    const testDestMac = mac.Broadcast;
    const testSrcIp = .{ 172, 30, 0, 1 };
    // const testDestIp = .{ 172, 30, 0, 2 };
    const testDestIp = .{ 10, 0, 69, 51 };

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

    const logThread = try std.Thread.spawn(.{}, log.loop, .{});
    _ = logThread.setName("lan_log") catch null;
    logThread.detach();

    try @import("./threads/pool.zig").start();

    const pcapThread = try std.Thread.spawn(.{}, @import("./threads/pcap.zig").loop, .{handle});
    _ = pcapThread.setName("lan_pcap") catch null;

    const clientThread = try std.Thread.spawn(.{}, @import("./threads/client.zig").loop, .{});
    _ = clientThread.setName("lan_client") catch null;

    const scheduleThread = try std.Thread.spawn(.{}, @import("./threads/schedule.zig").loop, .{});
    _ = scheduleThread.setName("lan_sched") catch null;
    scheduleThread.detach();

    // tryTest();

    pcapThread.join();
    clientThread.join();

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

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
