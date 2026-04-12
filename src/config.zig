const std = @import("std");
const ipv4 = @import("./ipv4.zig");
const log = @import("./log.zig");
const mac = @import("./mac.zig");
const util = @import("./util.zig");

const getenv = util.getenv;
const streq = util.streq;

const ConfigError = error{HomeUnset};

const Config = struct {
    host: ipv4.Address,
    firstIp: ipv4.Address,
    lastIp: ipv4.Address,
    mac: mac.MacAddress,
    device: [32:0]u8,
    thread_count: usize,
    local_ping: bool,
    log_debug: bool,

    pub fn getDeviceCStr(self: *Config) [*c]u8 {
        return util.asCStr(&self.device);
    }
};

const defaultConfig = Config{
    // a
    .host = ipv4.fromInts(10, 13, 37, 2),
    .firstIp = ipv4.fromInts(10, 13, 70, 1),
    .lastIp = ipv4.fromInts(10, 13, 70, 5),
    .mac = 0x5a4d5a8359c7,
    .device = "unset".* ++ [_:0]u8{0} ** 27,
    .thread_count = 4,
    .local_ping = false,
    .log_debug = false,
};

var tmpState: struct {
    // TODO: this needs to be proper state tracking for whether a config option was actually set in the file
    // for now this is just for booleans (since false will look like unset)
    local_ping_seen: bool = false,
    log_debug_seen: bool = false,
} = .{};

/// do not attempt to access this before loadConfig()
pub var g: Config = undefined;

pub fn loadConfig(allocator: std.mem.Allocator) !void {
    log.logS("Searching for config\n");
    const filepath = try findConfigFile(allocator);
    log.log("Using config file: {s}\n", .{filepath});
    const file = try getActualConfigFile(filepath);
    allocator.free(filepath);

    var writeBack = true;
    var filelen: usize = 0;

    // use the global config as a sentinel to avoid even more duplication
    @memset(std.mem.asBytes(&g), 0);
    var c: Config = undefined;
    @memset(std.mem.asBytes(&c), 0);

    const stat = try file.stat();
    if (stat.size > 0) blk: {
        log.debug("Existing config file is {d} bytes\n", .{stat.size});
        if (stat.size > 1 * 1000 * 1000) {
            log.err("Existing config file is weirdly large, ignoring it\n", .{});
            writeBack = false;
            break :blk;
        }
        var reader = file.reader(&.{});
        const rif = &reader.interface;

        const contents = try std.Io.Reader.allocRemaining(rif, allocator, .unlimited);
        defer allocator.free(contents);
        filelen = contents.len;

        // log.debug("Read {d} bytes, Got file contents:\n---\n{s}\n---\n", .{ contents.len, contents });

        _ = try parseConfigFile(contents, &c);

        log.logS("Got config: ");
        try printConfig(&c);
        log.logN("\n", .{}, false);
    } else {
        log.debugS("Existing config file is empty\n");
    }

    const newConfigLines = try fillConfigDefaults(allocator, &c);

    log.logS("Got full config: ");
    try printConfig(&g);
    log.logN("\n", .{}, false);

    if (newConfigLines) |ncl| if (writeBack) {
        defer allocator.free(ncl);
        // log.log("Got new config lines:\n---\n{s}\n---\n", .{ncl});
        var writer = file.writer(&.{});
        const wif = &writer.interface;
        // TODO: error handling
        try writer.seekTo(filelen);
        try wif.writeAll("\n");
        try wif.writeAll(ncl);
        try wif.flush(); // this is a noop here because this writer is unbuffered, but good to keep around to remember
        log.logS("Wrote defaults to config file\n");
    };

    file.close();
}

// [cwd]/fragolan.conf
// $XDG_CONFIG_HOME/fragolan/fragolan.conf (auto created if no config is found)
// $HOME/.config/fragolan/fragolan.conf
// error if neither xdg config nor home set
const configFilename = "fragolan.conf";
const configFilenameSub = "/" ++ configFilename;
const configFilepathXdg = "/fragolan";
const configFilepathHome = "/.config" ++ configFilepathXdg;

fn findConfigFile(allocator: std.mem.Allocator) ![]u8 {
    const stat = std.fs.cwd().statFile(configFilename) catch |e| blk: {
        if (e != error.FileNotFound)
            log.err("Error stat-ing config file in cwd: {}\n", .{e});
        break :blk null;
    };
    if (stat) |s| {
        const f = try std.fs.cwd().realpathAlloc(allocator, configFilename);
        if (s.kind == .file) {
            return f;
        } else {
            log.err("Config file in working directory {s} is not an actual file, ignoring\n", .{f});
            allocator.free(f);
        }
    }

    var file: []u8 = undefined;
    const xdg = try getenv(allocator, "XDG_CONFIG_HOME");
    if (xdg) |x| {
        defer allocator.free(x);
        file = try allocator.alloc(u8, x.len + configFilepathXdg.len + configFilenameSub.len);
        @memcpy(file[0..x.len], x);
        @memcpy(file[x.len .. x.len + configFilepathXdg.len], configFilepathXdg);
    } else {
        const home = try getenv(allocator, "HOME") orelse try getenv(allocator, "USERPROFILE");
        if (home) |h| {
            defer allocator.free(h);
            file = try allocator.alloc(u8, h.len + configFilepathHome.len + configFilenameSub.len);
            @memcpy(file[0..h.len], h);
            @memcpy(file[h.len .. h.len + configFilepathHome.len], configFilepathHome);
        } else {
            log.err("Could not find the home directory, your system is probably weird\n", .{});
            return ConfigError.HomeUnset;
        }
    }

    @memcpy(file[file.len - configFilenameSub.len ..], configFilenameSub);

    return file;
}

fn getActualConfigFile(filepath: []u8) !std.fs.File {
    const dirname = std.fs.path.dirname(filepath) orelse unreachable;
    // const basename = std.fs.path.basename(filepath) orelse error{};

    std.fs.makeDirAbsolute(dirname) catch |e| {
        if (e != error.PathAlreadyExists) {
            log.err("Error making config directory {s}: {any}\n", .{ dirname, e });
            return e;
        }
    };

    const file = std.fs.createFileAbsolute(filepath, .{ .read = true, .truncate = false }) catch |e| {
        log.err("Error getting config file {s}: {any}\n", .{ filepath, e });
        return e;
    };

    return file;
}

fn parseConfigFile(contents: []u8, c: *Config) !*Config {
    log.logS("Parsing config file\n");

    var it = std.mem.splitScalar(u8, contents, '\n');
    while (it.next()) |line| {
        // log.log("Got line: {s}\n", .{line});
        try processLine(line, c);
    }

    return c;
}

fn processLine(line: []const u8, c: *Config) !void {
    if (line.len < 1 or line[0] == '#') return;

    const i = std.mem.indexOfScalar(u8, line, '=') orelse return;
    const key = line[0..i];
    const value = line[i + 1 ..];

    // log.debug("Found config `{s}` = `{s}`\n", .{ key, value });

    try processSetting(key, value, c);
}

fn processSetting(key: []const u8, value: []const u8, c: *Config) !void {
    if (streq(key, "device")) {
        if (value.len > c.device.len) {
            // leave a zero at the end
            const out = c.device[0 .. c.device.len - 1];
            @memcpy(out, value[0..out.len]);
        } else {
            const out = c.device[0..value.len];
            @memcpy(out, value);
        }
    } else if (streq(key, "host")) {
        const a = try std.net.Ip4Address.parse(value, 1);
        c.host = @byteSwap(a.sa.addr);
    } else if (streq(key, "first_ip")) {
        const a = try std.net.Ip4Address.parse(value, 1);
        c.firstIp = @byteSwap(a.sa.addr);
    } else if (streq(key, "last_ip")) {
        const a = try std.net.Ip4Address.parse(value, 1);
        c.lastIp = @byteSwap(a.sa.addr);
    } else if (streq(key, "mac")) {
        c.mac = try mac.fromString(value);
    } else if (streq(key, "thread_count")) {
        c.thread_count = try std.fmt.parseInt(usize, value, 10);
    } else if (streq(key, "local_ping")) {
        if (streq(value, "true")) {
            c.local_ping = true;
            tmpState.local_ping_seen = true;
        } else if (streq(value, "false")) {
            c.local_ping = false;
            tmpState.local_ping_seen = true;
        }
    } else if (streq(key, "log_debug")) {
        if (streq(value, "true")) {
            c.log_debug = true;
            tmpState.log_debug_seen = true;
        } else if (streq(value, "false")) {
            c.log_debug = false;
            tmpState.log_debug_seen = true;
        }
    }
}

fn fillConfigDefaults(a: std.mem.Allocator, c: *Config) !?[]u8 {
    // const lines = try a.alloc(u8, 4096);
    var linesBuf: [4096]u8 = undefined;
    var lines = &linesBuf;
    var written: usize = 0;

    if (c.host == g.host) {
        g.host = defaultConfig.host;
        const ipStr = try ipv4.format(a, g.host);
        defer a.free(ipStr);
        written += (try std.fmt.bufPrint(lines[written..], "host={s}\n", .{ipStr})).len;
    } else g.host = c.host;

    if (c.firstIp == g.firstIp) {
        g.firstIp = defaultConfig.firstIp;
        const ipStr = try ipv4.format(a, g.firstIp);
        defer a.free(ipStr);
        written += (try std.fmt.bufPrint(lines[written..], "first_ip={s}\n", .{ipStr})).len;
    } else g.firstIp = c.firstIp;

    if (c.lastIp == g.lastIp) {
        g.lastIp = defaultConfig.lastIp;
        const ipStr = try ipv4.format(a, g.lastIp);
        defer a.free(ipStr);
        written += (try std.fmt.bufPrint(lines[written..], "last_ip={s}\n", .{ipStr})).len;
    } else g.lastIp = c.lastIp;

    if (c.mac == g.mac) {
        g.mac = defaultConfig.mac;
        written += (try std.fmt.bufPrint(lines[written..], "mac={x}\n", .{g.mac})).len;
    } else g.mac = c.mac;

    if (streq(&c.device, &g.device)) {
        @memcpy(&g.device, &defaultConfig.device);
        // casting config.device to a c pointer makes the format code treat it as a zero terminated string
        written += (try std.fmt.bufPrint(lines[written..], "device={s}\n", .{g.getDeviceCStr()})).len;
    } else @memcpy(&g.device, &c.device);

    if (c.thread_count == g.thread_count) {
        g.thread_count = defaultConfig.thread_count;
        written += (try std.fmt.bufPrint(lines[written..], "thread_count={d}\n", .{g.thread_count})).len;
    } else g.thread_count = c.thread_count;

    if (tmpState.local_ping_seen) {
        g.local_ping = c.local_ping;
    } else {
        g.local_ping = defaultConfig.local_ping;
        written += (try std.fmt.bufPrint(lines[written..], "local_ping={}\n", .{g.local_ping})).len;
    }

    if (tmpState.log_debug_seen) {
        g.log_debug = c.log_debug;
    } else {
        g.log_debug = defaultConfig.log_debug;
        written += (try std.fmt.bufPrint(lines[written..], "log_debug={}\n", .{g.log_debug})).len;
    }

    if (written > 0) {
        const finalLines = try a.alloc(u8, written);
        @memcpy(finalLines, lines[0..written]);
        return finalLines;
    }
    return null;
}

fn printConfig(c: *Config) !void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();
    const host = try ipv4.format(a, c.host);
    const firstIp = try ipv4.format(a, c.firstIp);
    const lastIp = try ipv4.format(a, c.lastIp);

    log.logN("Config {{ host={s}, firstIp={s}, lastIp={s}, mac={x}, device={s}, thread_count={d}, local_ping={}, log_debug={} }}", .{ host, firstIp, lastIp, c.mac, c.getDeviceCStr(), c.thread_count, c.local_ping, c.log_debug }, false);
}
