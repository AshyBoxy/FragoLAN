const std = @import("std");

pub threadlocal var name: []const u8 = "Unnamed";

// essentially just so we don't have to handle errors everywhere
// this should be extended to support writing to a file later
// + loglevels and such
// each one of these also gets a convenience overload with no args (logSimple)
pub fn logN(comptime format: []const u8, args: anytype, printName: bool) void {
    const stdout = std.io.getStdOut().writer();
    if (printName) stdout.print("[{s}] ", .{name}) catch return;
    stdout.print(format, args) catch return;
}
pub fn log(comptime format: []const u8, args: anytype) void {
    logN(format, args, true);
}
pub fn logS(comptime message: []const u8) void {
    log(message, .{});
}

// only exists for consistency
pub fn debugN(comptime format: []const u8, args: anytype, printName: bool) void {
    if (printName) std.debug.print("[{s}] ", .{name});
    std.debug.print(format, args);
}
pub fn debug(comptime format: []const u8, args: anytype) void {
    debugN(format, args, true);
}
pub fn debugS(comptime message: []const u8) void {
    debug(message, .{});
}

pub fn errN(comptime format: []const u8, args: anytype, printName: bool) void {
    debugN("[ERROR] " ++ format, args, printName);
}
pub fn err(comptime format: []const u8, args: anytype) void {
    errN(format, args, true);
}
