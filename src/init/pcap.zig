const std = @import("std");
const c = @import("root").c;
const log = @import("../log.zig");
const config = @import("../config.zig");
const ipv4 = @import("../ipv4.zig");

const TEST_FILTER = "arp or ip host ";

const Error = error{
    OpenFailed,
    NotEthernet,
    FilterCompileFailed,
    FilterSetFailed
};

pub var errbuf: [:0]u8 = undefined;
pub var cerrbuf: [*c]u8 = undefined;

pub fn init(allocator: std.mem.Allocator) !?*c.pcap_t {
    log.logS("Setting up pcap\n");

    errbuf = try allocator.allocSentinel(u8, @sizeOf(u8) * c.PCAP_ERRBUF_SIZE, 0);
    cerrbuf = @ptrCast(errbuf);

    // get handle, check if ethernet(-like)
    const device = config.g.getDeviceCStr();
    // second 1 here (4th arg) is to_ms, aka the packet buffer timeout. please do not be stupid again and set it high
    const handle = c.pcap_open_live(device, c.BUFSIZ, 1, 1, cerrbuf);
    // i KNOW i read something on what to do in this situation, but i can't find it
    if (handle == null) {
        // this should be an error anyway
        // later this should be wrapped by a zig function which correctly returns the error
        log.err("Couldn't open {s}: {s}\n", .{ device, cerrbuf });
        return Error.OpenFailed;
    }

    if (c.pcap_datalink(handle) != c.DLT_EN10MB) {
        log.err("{s} doesn't use ethernet headers\n", .{device});
        return Error.NotEthernet;
    }

    try setupFilter(allocator, handle);
    return handle;
}

fn setupFilter(allocator: std.mem.Allocator, handle: ?*c.pcap_t) !void {
    // TODO: this can be heap
    // compile and apply filter
    const bpf_program = try allocator.create(c.struct_bpf_program);
    defer allocator.destroy(bpf_program);
    const fmtHost = try ipv4.format(allocator, config.g.host);
    const filter: [:0]u8 = @ptrCast(try allocator.alloc(u8, TEST_FILTER.len + fmtHost.len + 1));
    @memcpy(filter[0..TEST_FILTER.len], TEST_FILTER);
    @memcpy(filter[TEST_FILTER.len .. filter.len - 1], fmtHost);
    filter[filter.len - 1] = 0;
    allocator.free(fmtHost);

    var err: c_int = 0;

    err = c.pcap_compile(handle, bpf_program, @ptrCast(filter), 1, 0);
    if (err == -1) {
        log.err("Couldn't compile filter {s}: {s}\n", .{ filter, c.pcap_geterr(handle) });
        return Error.FilterCompileFailed;
    }

    err = c.pcap_setfilter(handle, bpf_program);
    if (err == -1) {
        log.err("Couldn't set filter {s}: {s}\n", .{ filter, c.pcap_geterr(handle) });
        return Error.FilterSetFailed;
    }
    log.debug("Set pcap filter: {s}\n", .{filter});
    allocator.free(filter);
}

pub fn free(allocator: std.mem.Allocator, handle: ?*c.pcap_t) void {
    c.pcap_close(handle);
    allocator.free(errbuf);
}
