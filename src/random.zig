const std = @import("std");
const log = @import("log.zig");

var prng: std.Random.DefaultPrng = undefined;
pub var rand: std.Random = undefined;

pub fn init() !void {
    log.logS("Initializing main pseudo random generator\n");

    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    prng = std.Random.DefaultPrng.init(seed);
    rand = prng.random();
}

pub fn bytes(buf: []u8) void {
    rand.bytes(buf);
}

pub fn int(comptime T: type) T {
    return rand.int(T);
}
