const std = @import("std");
const log = @import("../log.zig");

const allocator = std.heap.c_allocator;
const size = 1;

const JobList = std.DoublyLinkedList(*Job);

var lock = std.Thread.Mutex{};
var jobs: JobList = JobList{};
var jobsAvailable = std.Thread.Semaphore{};

pub const Job = struct { function: *const fn (?*anyopaque) void, args: ?*anyopaque };

pub fn start() !void {
    log.logS("Starting thread pool\n");

    for (1..size + 1) |i| {
        const thread = try std.Thread.spawn(.{}, pool, .{i});
        const name = std.fmt.allocPrint(allocator, "lan_{d}", .{i}) catch "lan";
        defer allocator.free(name);
        _ = thread.setName(name) catch null;
        thread.detach();
    }
}

pub fn pool(num: usize) void {
    log.name = std.fmt.allocPrint(allocator, "Pool-{d}", .{num}) catch "Pool";
    defer allocator.free(log.name);

    log.logS("Started up\n");

    while (true) {
        const maybeJob = pop();
        if (maybeJob) |job| {
            if (job.args) |args| {
                job.function(args);
            } else job.function(null);
            allocator.destroy(job);
        }
    }
}

// pub fn push(function: *const fn (?*void) void, args: ?*void) void {
pub fn push(function: *const anyopaque, args: ?*const anyopaque) void {
    lock.lock();

    const job = allocator.create(Job) catch return;
    job.function = @ptrCast(function);
    job.args = @constCast(args);

    const node = allocator.create(JobList.Node) catch return;
    node.data = job;

    jobs.append(node);

    // log.debug("Pushed: {*}\n", .{job.function});

    lock.unlock();
    jobsAvailable.post();
}
pub fn pushS(function: *const fn () void) void {
    push(@ptrCast(function), null);
}

pub fn pop() ?*Job {
    jobsAvailable.wait();
    lock.lock();
    defer lock.unlock();

    const node = jobs.popFirst();
    if (node == null) return null;

    defer allocator.destroy(node.?);

    const job = node.?.data;

    return job;
}
