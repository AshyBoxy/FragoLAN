const std = @import("std");
// pub const main = @import("./main.zig");
pub const UUID = @import("./UUID.zig");

test {
    std.testing.refAllDecls(@This());
}
