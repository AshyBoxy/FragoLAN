const std = @import("std");
const config = @import("./config.zig");

pub threadlocal var name: []const u8 = "Unnamed";

const allocator = std.heap.c_allocator;

var logs: std.DoublyLinkedList = .{};
var lock = std.Thread.Mutex{};
var logsAvailable = std.Thread.Semaphore{};

const Log = struct { string: []const u8, err: bool, node: std.DoublyLinkedList.Node };

pub fn loop() void {
    name = "Log";

    var stdout = std.fs.File.stdout();
    var stderr = std.fs.File.stderr();

    // useful to see what got logged before this thread was started
    logS("\"And then he logged all over the place\"\n");
    log("Started up with id: {d}\n", .{std.Thread.getCurrentId()});

    while (true) {
        if (pop()) |l| {
            _ = (if (l.err) stderr.writeAll(l.string) else stdout.writeAll(l.string)) catch null;
            allocator.free(l.string);
            allocator.destroy(l);
        }
    }
}

fn push(str: []const u8, e: bool) void {
    lock.lock();

    // if this errors then we're out of memory and the program is about to crash elsewhere anyway
    const l = allocator.create(Log) catch return;
    // errdefer allocator.destroy(l);
    l.string = str;
    l.err = e;

    logs.append(&l.node);

    lock.unlock();
    logsAvailable.post();
}

fn pop() ?*Log {
    logsAvailable.wait();
    lock.lock();
    defer lock.unlock();

    const node = logs.popFirst();
    if (node == null) return null;

    const l: *Log = @fieldParentPtr("node", node.?);
    return l;
}

// essentially just so we don't have to handle errors everywhere
// this should be extended to support writing to a file later
// + loglevels and such
// each one of these also gets a convenience overload with no args (logSimple)
fn _log(comptime format: []const u8, args: anytype, printName: bool, e: bool) void {
    var string: ?[]const u8 = null;

    if (printName) {
        string = std.fmt.allocPrint(allocator, "[{s}] " ++ format, .{name} ++ args) catch return;
    } else {
        string = std.fmt.allocPrint(allocator, format, args) catch return;
    }

    push(string.?, e);
}

pub inline fn logN(comptime format: []const u8, args: anytype, printName: bool) void {
    // const stdout = std.io.getStdOut().writer();
    // if (printName) stdout.print("[{s}] ", .{name}) catch return;
    // stdout.print(format, args) catch return;

    _log(format, args, printName, false);
}
pub inline fn log(comptime format: []const u8, args: anytype) void {
    logN(format, args, true);
}
pub inline fn logS(comptime message: []const u8) void {
    log(message, .{});
}

pub inline fn debugN(comptime format: []const u8, args: anytype, comptime printName: bool) void {
    // if (printName) std.debug.print("[{s}] ", .{name});
    // std.debug.print(format, args);

    if (config.initialized and !config.g.log_debug) return;

    _log("[DEBUG] " ++ format, args, printName, true);
}
pub inline fn debug(comptime format: []const u8, args: anytype) void {
    debugN(format, args, true);
}
pub inline fn debugS(comptime message: []const u8) void {
    debug(message, .{});
}

pub inline fn errN(comptime format: []const u8, args: anytype, comptime printName: bool) void {
    _log("[ERROR] " ++ format, args, printName, true);
}
pub inline fn err(comptime format: []const u8, args: anytype) void {
    errN(format, args, true);
}

pub fn wait() void {
    while (logsAvailable.permits > 0)
        std.Thread.sleep(10 * 1000);
}
