const std = @import("std");
const main = @import("../main.zig");
const ipv4 = @import("../ipv4.zig");
const util = @import("../util.zig");
const log = @import("../log.zig");
const UUID = @import("../UUID.zig");
const peer = @import("./peer.zig");
const client = @import("../threads/client.zig");
const lan = @import("./packet.zig");
const ethernet = @import("../ethernet.zig");
const config = @import("../config.zig");
const pcap = @import("../threads/pcap.zig");

// TODO: move somewhere shared
pub const Error = error{ InvalidPacketData, InvalidLength, DecryptionFailed };

// this is all focusing on pia 5.9 (for now)
// some todos include notes for lower versions

const PIA_MAGIC: [4]u8 = .{ 0x32, 0xab, 0x98, 0x64 };
const SESSION_KEY_PARAM_SIZE = 0x20;
const LAN_STATION_INFO_SIZE = 0x32;
const HOST_STATION_SIZE = 0x23;
// i'm too tired to figure out why the offset is wrong
const HOST_STATION_OFFSET_ADJUST = 19;
// from the end
const HOST_STATION_OFFSET = SESSION_KEY_PARAM_SIZE + (LAN_STATION_INFO_SIZE * 16) + HOST_STATION_SIZE - HOST_STATION_OFFSET_ADJUST;
const CRYPTO_CHALLENGE_REQUEST_SIZE = 0x12A;
const CRYPTO_CHALLENGE_RESPONSE_SIZE = 58;

// splatoon 2
// TODO: multiple game keys
const GAME_KEY = util.comp.hexToBytes("ee182a63e216cdb1f51ad4bed8cf6508");

// we should only need one at a time
// ^ for testing; only works with one session
// TODO: multiple session keys
var sessionKeyParam: [SESSION_KEY_PARAM_SIZE]u8 = .{0} ** SESSION_KEY_PARAM_SIZE;

pub fn init(allocator: std.mem.Allocator) void {
    challengeKeyManager.init(allocator);
}

const challengeKeyManager = struct {
    // TODO: maybe don't consider a failure in here a panic
    // TODO: throw away old keys
    const ChallengeKeyList = std.array_list.Aligned([16]u8, std.mem.Alignment.@"1");
    var challengeKeys: ChallengeKeyList = undefined;
    var allocator: std.mem.Allocator = undefined;
    var lock = std.Thread.Mutex{};

    fn init(a: std.mem.Allocator) void {
        log.logS("Initializing challenge key manager\n");
        allocator = a;
        challengeKeys = ChallengeKeyList.initCapacity(allocator, 10) catch |e| {
            util.panic("Failed to initialize challenge key list", e);
        };
    }

    fn add(key: [16]u8) void {
        lock.lock();
        defer lock.unlock();
        challengeKeys.append(allocator, key) catch |e| {
            util.panic("Failed to add challenge key", e);
        };
    }

    // thread safety !!!
    fn get() [][16]u8 {
        lock.lock();
        defer lock.unlock();
        return allocator.dupe([16]u8, challengeKeys.items) catch |e| {
            util.panic("Failed to get challenge keys", e);
        };
    }
    fn free(keys: [][16]u8) void {
        allocator.free(keys);
    }
};

pub const PiaBrowseRequest = struct {
    pub fn create(allocator: std.mem.Allocator, source: UUID, payload: []const u8, challengeKey: ?[16]u8, challengeData: ?[256]u8, srcPort: u16) !*PiaBrowseRequest {
        const packet = try allocator.create(PiaBrowseRequest);
        errdefer allocator.destroy(packet);
        packet.source = source;
        packet.payload = try allocator.dupe(u8, payload);

        packet.challengeKey = challengeKey;
        packet.challengeData = challengeData;

        packet.srcPort = srcPort;

        return packet;
    }

    pub fn createSerialized(allocator: std.mem.Allocator, source: UUID, payload: []const u8, challengeKey: ?[16]u8, challengeData: ?[256]u8, srcPort: u16) ![]u8 {
        const packet = try create(allocator, source, payload, challengeKey, challengeData, srcPort);
        defer packet.free(allocator);
        return packet.serialize(allocator);
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []u8) !PiaBrowseRequest {
        if (bytes.len < 16 + 1) return Error.InvalidLength;
        var offset: usize = 0;
        const source: UUID = .{ .bytes = bytes[offset .. offset + 16][0..16].* };
        offset += 16;

        const srcPort = try util.RawData.readBe(u16, bytes, &offset);

        const cryptoEnabled = bytes[offset];
        offset += 1;
        var challengeKey: ?[16]u8 = null;
        var challengeData: ?[256]u8 = null;
        if (cryptoEnabled != 0) {
            if (bytes.len < offset + 16 + 256) return Error.InvalidLength;
            challengeKey = bytes[offset .. offset + 16][0..16].*;
            offset += 16;
            challengeData = bytes[offset .. offset + 256][0..256].*;
            offset += 256;
        }
        const payload = try allocator.dupe(u8, bytes[offset..]);
        return .{ .source = source, .payload = payload, .challengeKey = challengeKey, .challengeData = challengeData, .srcPort = srcPort };
    }

    source: UUID,
    payload: []u8,
    challengeKey: ?[16]u8,
    challengeData: ?[256]u8,
    srcPort: u16,

    // shape is:
    // uuid dest
    // u16 dst port
    // u8 crypto enabled
    // if crypto enabled:
    //     16 byte key
    //     256 byte unencrypted challenge data
    // original payload
    pub fn serialize(self: *PiaBrowseRequest, allocator: std.mem.Allocator) ![]u8 {
        const uuidSize = self.source.bytes.len;

        var offset: usize = 0;
        var size = uuidSize + 2 + 1 + self.payload.len;
        if (self.challengeKey != null) size += 16 + 256;

        const payload = try allocator.alloc(u8, size);

        @memcpy(payload[offset .. offset + uuidSize], &self.source.bytes);
        offset += uuidSize;

        try util.RawData.writeBe(u16, payload, &offset, self.srcPort);

        if (self.challengeKey) |key| {
            payload[offset] = 1;
            offset += 1;
            @memcpy(payload[offset .. offset + 16], &key);
            offset += 16;
            @memcpy(payload[offset .. offset + 256], &self.challengeData.?);
            offset += 256;
        } else {
            payload[offset] = 0;
            offset += 1;
        }

        @memcpy(payload[offset..], self.payload);

        return payload;
    }

    pub fn free(self: *PiaBrowseRequest, allocator: std.mem.Allocator) void {
        self.freeS(allocator);
        allocator.destroy(self);
    }
    pub fn freeS(self: *const PiaBrowseRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};
pub const PiaBrowseReply = struct {
    /// use fromRawBrowseReply
    fn create(allocator: std.mem.Allocator, source: UUID, payload: []const u8, key: ?[16]u8, decrypted: ?[16]u8, dstPort: u16) !*PiaBrowseReply {
        const packet = try allocator.create(PiaBrowseReply);
        errdefer allocator.destroy(packet);
        packet.source = source;
        packet.payload = try allocator.dupe(u8, payload);
        @memcpy(&packet.sessionKeyParam, &sessionKeyParam);

        // make sure the host ip is zeroed
        const host_station_start = packet.payload.len - HOST_STATION_OFFSET;
        @memset(packet.payload[host_station_start .. host_station_start + 4], 0);

        packet.key = key;
        packet.decrypted = decrypted;

        packet.dstPort = dstPort;

        return packet;
    }

    pub fn createSerialized(allocator: std.mem.Allocator, source: UUID, payload: []const u8, key: ?[16]u8, decrypted: ?[16]u8, dstPort: u16) ![]u8 {
        const packet = try create(allocator, source, payload, key, decrypted, dstPort);
        defer packet.free(allocator);
        return packet.serialize(allocator);
    }

    pub fn fromRawBrowseReply(allocator: std.mem.Allocator, raw: *const RawBrowseReply, source: UUID, key: ?[16]u8, decrypted: ?[16]u8, dstPort: u16) !*PiaBrowseReply {
        const payload = try raw.serialize(allocator);

        return create(allocator, source, payload, key, decrypted, dstPort);
    }

    pub fn serializedFromRawBrowseReply(allocator: std.mem.Allocator, raw: *const RawBrowseReply, source: UUID, key: ?[16]u8, decrypted: ?[16]u8, dstPort: u16) ![]u8 {
        const packet = try fromRawBrowseReply(allocator, raw, source, key, decrypted, dstPort);
        defer packet.free(allocator);
        return packet.serialize(allocator);
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !PiaBrowseReply {
        if (bytes.len < 16) return Error.InvalidLength;

        var offset: usize = 0;

        const source: UUID = .{ .bytes = bytes[offset .. offset + 16][0..16].* };
        offset += 16;

        const dstPort = try util.RawData.readBe(u16, bytes, &offset);

        const cryptoEnabled = bytes[16];
        offset += 1;
        var key: ?[16]u8 = null;
        var decrypted: ?[16]u8 = null;
        if (cryptoEnabled != 0) {
            if (bytes.len < offset + 32) return Error.InvalidLength;
            key = bytes[offset .. offset + 16][0..16].*;
            offset += 16;
            decrypted = bytes[offset .. offset + 16][0..16].*;
            offset += 16;
        }

        if (bytes.len < offset + SESSION_KEY_PARAM_SIZE) return Error.InvalidLength;
        var sKeyParam: [SESSION_KEY_PARAM_SIZE]u8 = undefined;
        @memcpy(&sKeyParam, bytes[offset .. offset + SESSION_KEY_PARAM_SIZE]);
        offset += SESSION_KEY_PARAM_SIZE;

        const payload = try allocator.dupe(u8, bytes[offset..]);

        return .{ .source = source, .sessionKeyParam = sKeyParam, .payload = payload, .key = key, .decrypted = decrypted, .dstPort = dstPort };
    }

    source: UUID,
    sessionKeyParam: [SESSION_KEY_PARAM_SIZE]u8,
    payload: []u8,
    key: ?[16]u8,
    decrypted: ?[16]u8,
    dstPort: u16,

    pub fn free(self: *PiaBrowseReply, allocator: std.mem.Allocator) void {
        self.freeS(allocator);
        allocator.destroy(self);
    }
    pub fn freeS(self: *PiaBrowseReply, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }

    // shape is:
    // uuid dest
    // u16 dst port
    // u8 crypto enabled
    // if crypto enabled:
    //     16 byte key
    //     16 byte decrypted challenge response
    // session key param
    // session info
    pub fn serialize(self: *PiaBrowseReply, allocator: std.mem.Allocator) ![]u8 {
        const uuidSize = self.source.bytes.len;

        var size: usize = uuidSize + 2 + 1 + SESSION_KEY_PARAM_SIZE + self.payload.len;
        if (self.key != null) size += 32;

        const payload = try allocator.alloc(u8, size);
        var offset: usize = 0;
        @memcpy(payload[offset..uuidSize], &self.source.bytes);
        offset += uuidSize;

        try util.RawData.writeBe(u16, payload, &offset, self.dstPort);

        if (self.key) |key| {
            payload[offset] = 1;
            offset += 1;
            @memcpy(payload[offset .. offset + 16], &key);
            offset += 16;
            @memcpy(payload[offset .. offset + 16], &self.decrypted.?);
            offset += 16;
        } else {
            payload[offset] = 0;
            offset += 1;
        }

        @memcpy(payload[offset .. offset + SESSION_KEY_PARAM_SIZE], &sessionKeyParam);
        offset += SESSION_KEY_PARAM_SIZE;
        @memcpy(payload[offset..], self.payload);

        return payload;
    }

    pub fn format(self: *const PiaBrowseReply, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("PiaBrowseReply { source=");
        try self.source.format(writer);
        try writer.writeAll(", sessionKeyParam=");
        try writer.printHex(self.sessionKeyParam[0..16], .lower);
        try writer.writeAll("..., payload=");
        try writer.printHex(self.payload[0..16], .lower);
        try writer.writeAll("...");

        try writer.writeAll(", key=");
        if (self.key) |key| {
            try writer.printHex(&key, .lower);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(", decrypted=");
        if (self.decrypted) |decrypted| {
            try writer.printHex(&decrypted, .lower);
        } else {
            try writer.writeAll("null");
        }

        try writer.writeAll(" }");
    }
};
pub const PiaPacket = struct {};

const RawBrowseRequest = struct {
    fn parse(allocator: std.mem.Allocator, bytes: []const u8) !RawBrowseRequest {
        if (bytes[0] != 0) return Error.InvalidPacketData;
        const searchCriteriaSize = std.mem.readInt(u32, bytes[1..5], .big);
        if (bytes.len < 5 + searchCriteriaSize) return Error.InvalidPacketData;

        const searchCriteria = try allocator.dupe(u8, bytes[5 .. 5 + searchCriteriaSize]);
        errdefer allocator.free(searchCriteria);

        var cryptoChallenge: ?UnencapsulatedCryptoChallenge = null;
        if (bytes.len > 5 + searchCriteriaSize) {
            const cryptoChallengeBytes = bytes[5 + searchCriteriaSize ..];
            cryptoChallenge = try UnencapsulatedCryptoChallenge.parse(allocator, cryptoChallengeBytes);
            errdefer cryptoChallenge.?.free(allocator);
        }

        return .{ .searchCriteria = searchCriteria, .cryptoChallenge = cryptoChallenge };
    }

    // u8: packet type (0)
    // u32: size of search criteria

    searchCriteria: []u8,
    cryptoChallenge: ?UnencapsulatedCryptoChallenge,

    pub fn format(self: *const RawBrowseRequest, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("RawBrowseRequest { searchCriteria=");
        try writer.printHex(self.searchCriteria[0..16], .lower);
        try writer.writeAll("..., cryptoChallenge=");
        if (self.cryptoChallenge) |challenge| {
            try challenge.format(writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(" }");
    }

    pub fn freeS(self: *const RawBrowseRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.searchCriteria);
    }
    pub fn free(self: *RawBrowseRequest, allocator: std.mem.Allocator) void {
        self.freeS(allocator);
        allocator.destroy(self);
    }

    pub fn serialize(self: *const RawBrowseRequest, allocator: std.mem.Allocator) ![]u8 {
        var size: usize = 1 + 4 + self.searchCriteria.len;
        if (self.cryptoChallenge != null) size += CRYPTO_CHALLENGE_REQUEST_SIZE;

        const bytes = try allocator.alloc(u8, size);

        bytes[0] = 0;
        std.mem.writeInt(u32, bytes[1..5], @intCast(self.searchCriteria.len), .big);
        @memcpy(bytes[5 .. 5 + self.searchCriteria.len], self.searchCriteria);
        if (self.cryptoChallenge) |challenge| {
            const challengeBytes = challenge.serializeRequest();
            @memcpy(bytes[5 + self.searchCriteria.len ..], &challengeBytes);
        }
        return bytes;
    }
};

const RawBrowseReply = struct {
    // u8: packet type (1)
    // u32: size of sessionInfo

    sessionInfo: SessionInfo,
    cryptoChallenge: ?UnencapsulatedCryptoChallenge,
    tmpCryptoChallenge: ?[]u8,

    pub fn format(self: *const RawBrowseReply, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("RawBrowseReply { sessionInfo=");
        try self.sessionInfo.format(writer);
        try writer.writeAll(", tmpCryptoChallenge=");
        if (self.tmpCryptoChallenge) |challenge| {
            try writer.printHex(challenge, .lower);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(", cryptoChallenge=");
        if (self.cryptoChallenge) |challenge| {
            try challenge.format(writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(" }");
    }

    fn parse(allocator: std.mem.Allocator, bytes: []const u8) !RawBrowseReply {
        if (bytes[0] != 1) return Error.InvalidPacketData;
        const sessionInfoSize = std.mem.readInt(u32, bytes[1..5], .big);
        if (bytes.len < 5 + sessionInfoSize) return Error.InvalidPacketData;
        log.debug("sessionInfoSize: {d}, bytes.len: {d}\n", .{ sessionInfoSize, bytes.len });

        const sessionInfoBytes = bytes[5 .. 5 + sessionInfoSize];
        var sessionInfo: SessionInfo = undefined;
        // TODO: move this into SessionInfo
        {
            var offset: usize = 0;
            sessionInfo.gameMode = try util.RawData.readBe(u32, sessionInfoBytes, &offset);

            sessionInfo.sessionId = try util.RawData.readBe(u32, sessionInfoBytes, &offset);

            for (&sessionInfo.attributes) |*attr| {
                // log.log("Reading attribute at offset 0x{x}\n", .{offset});
                attr.* = try util.RawData.readBe(u32, sessionInfoBytes, &offset);
            }

            sessionInfo.curParticipants = try util.RawData.readBe(u16, sessionInfoBytes, &offset);
            sessionInfo.minParticipants = try util.RawData.readBe(u16, sessionInfoBytes, &offset);
            sessionInfo.maxParticipants = try util.RawData.readBe(u16, sessionInfoBytes, &offset);

            // TODO: if pia is <5.3 these two are not present
            sessionInfo.systemCommunicationVersion = sessionInfoBytes[offset];
            sessionInfo.applicationCommunicationVersion = sessionInfoBytes[offset + 1];
            offset += 2;

            sessionInfo.sessionType = try util.RawData.readBe(u32, sessionInfoBytes, &offset);

            // and now parse from the end because applicationDataSize is after applicationData

            // TODO: if pia is <5.7 this is not present
            var endOffset: usize = 0;
            sessionInfo.sessionKeyParam = sessionInfoBytes[sessionInfoBytes.len - SESSION_KEY_PARAM_SIZE ..][0..SESSION_KEY_PARAM_SIZE].*;
            endOffset += SESSION_KEY_PARAM_SIZE;

            for (0..16) |i| {
                // log.log("Reading LanStationInfo {d} at offset 0x{x}\n", .{ i, sessionInfoBytes.len - endOffset });
                const o = sessionInfoBytes.len - endOffset - LAN_STATION_INFO_SIZE;
                sessionInfo.playersStationInfo[15 - i] = try LanStationInfo.parse(&sessionInfoBytes[o .. o + LAN_STATION_INFO_SIZE]);
                endOffset += LAN_STATION_INFO_SIZE;
            }

            const hostStationOffset = sessionInfoBytes.len - endOffset - HOST_STATION_SIZE;
            const hostStationParse = try StationLocation.parse(&sessionInfoBytes[hostStationOffset .. hostStationOffset + HOST_STATION_SIZE]);
            sessionInfo.stationLocation = hostStationParse.stationLocation;
            endOffset += HOST_STATION_SIZE;

            sessionInfo.open = sessionInfoBytes[sessionInfoBytes.len - endOffset] != 0;
            endOffset += 1;

            sessionInfo.applicationDataSize = std.mem.readInt(u32, sessionInfoBytes[sessionInfoBytes.len - endOffset - 4 ..][0..4], .big);
            endOffset += 4;

            const bytesLeft = sessionInfoBytes.len - offset - endOffset;
            // if (bytesLeft > sessionInfo.applicationDataSize) {
            //     log.debug("applicationDataSize {d} is smaller than the leftover data {d}?\n", .{ sessionInfo.applicationDataSize, bytesLeft });
            // } else if (bytesLeft < sessionInfo.applicationDataSize) {
            //     log.debug("applicationDataSize {d} is larger than the leftover data {d}?\n", .{ sessionInfo.applicationDataSize, bytesLeft });
            // }
            // const appDataSize = if (sessionInfo.applicationDataSize < bytesLeft) sessionInfo.applicationDataSize else bytesLeft;

            // sessionInfo.applicationData = try allocator.dupe(u8, sessionInfoBytes[offset .. offset + appDataSize]);
            // just use the leftover bytes for now
            // even if it's incorrect it should serialize back properly
            sessionInfo.applicationData = try allocator.dupe(u8, sessionInfoBytes[offset .. offset + bytesLeft]);
            errdefer allocator.free(sessionInfo.applicationData);

            // const APPLICATION_DATA_SIZE = 0x180;
            // sessionInfo.applicationData = try allocator.dupe(u8, sessionInfoBytes[offset .. offset + APPLICATION_DATA_SIZE]);
            // offset += APPLICATION_DATA_SIZE;
            // errdefer allocator.free(sessionInfo.applicationData);
            // const applicationDataSize = try util.RawData.readBe(u32, sessionInfoBytes, &offset);
            // sessionInfo.applicationDataSize = applicationDataSize;
            // // std.debug.panic("App data size: 0x{x}, Offset: 0x{x}\n", .{ applicationDataSize, offset });

            // sessionInfo.open = sessionInfoBytes[offset] != 0;
            // offset += 1;

            // return sessionInfo;
        }

        var tmpCryptoChallenge: ?[]u8 = null;
        var cryptoChallenge: ?UnencapsulatedCryptoChallenge = null;
        if (bytes.len > 5 + sessionInfoSize) {
            tmpCryptoChallenge = try allocator.dupe(u8, bytes[5 + sessionInfoSize ..]);
            errdefer allocator.free(tmpCryptoChallenge.?);

            cryptoChallenge = try UnencapsulatedCryptoChallenge.parse(allocator, tmpCryptoChallenge.?);
            errdefer cryptoChallenge.?.free(allocator);
        }

        return .{ .sessionInfo = sessionInfo, .tmpCryptoChallenge = tmpCryptoChallenge, .cryptoChallenge = cryptoChallenge };
    }

    pub fn freeS(self: *const RawBrowseReply, allocator: std.mem.Allocator) void {
        allocator.free(self.sessionInfo.applicationData);
    }
    pub fn free(self: *RawBrowseReply, allocator: std.mem.Allocator) void {
        self.freeS(allocator);
        allocator.destroy(self);
    }

    pub fn serialize(self: *const RawBrowseReply, allocator: std.mem.Allocator) ![]u8 {
        const sessionInfoBytes = try self.sessionInfo.serialize(allocator);
        defer allocator.free(sessionInfoBytes);

        var size: usize = 1 + 4 + sessionInfoBytes.len;
        if (self.cryptoChallenge != null) size += CRYPTO_CHALLENGE_RESPONSE_SIZE;

        const bytes = try allocator.alloc(u8, size);
        bytes[0] = 1;
        std.mem.writeInt(u32, bytes[1..5], @intCast(sessionInfoBytes.len), .big);
        @memcpy(bytes[5 .. 5 + sessionInfoBytes.len], sessionInfoBytes);

        if (self.cryptoChallenge) |challenge| {
            const challengeBytes = challenge.serializeResponse();
            @memcpy(bytes[5 + sessionInfoBytes.len ..], &challengeBytes);
        }

        return bytes;
    }
};

const SessionInfo = struct {
    gameMode: u32,
    sessionId: u32,
    attributes: [6]u32,
    curParticipants: u16,
    minParticipants: u16,
    maxParticipants: u16,
    systemCommunicationVersion: u8,
    applicationCommunicationVersion: u8,
    sessionType: u32,

    applicationData: []u8,
    // supposedly always 0x180
    applicationDataSize: u32,
    // i assume 1 byte
    open: bool,

    stationLocation: StationLocation,
    playersStationInfo: [16]LanStationInfo,

    sessionKeyParam: [SESSION_KEY_PARAM_SIZE]u8,

    pub fn format(self: *const SessionInfo, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("SessionInfo { ");
        try writer.print("gameMode={d}, sessionId={d}, ", .{ self.gameMode, self.sessionId });

        try writer.print("attributes=[{d}, {d}, {d}, {d}, {d}, {d}], ", .{ self.attributes[0], self.attributes[1], self.attributes[2], self.attributes[3], self.attributes[4], self.attributes[5] });

        try writer.print("curParticipants={d}, minParticipants={d}, maxParticipants={d}, ", .{ self.curParticipants, self.minParticipants, self.maxParticipants });

        try writer.print("systemCommunicationVersion={d}, applicationCommunicationVersion={d}, sessionType={d}, ", .{ self.systemCommunicationVersion, self.applicationCommunicationVersion, self.sessionType });

        try writer.print("applicationDataSize={d}, ", .{self.applicationDataSize});
        // skip application data

        try writer.print("open={}, ", .{self.open});

        try writer.writeAll("stationLocation=");
        try self.stationLocation.format(writer);
        try writer.writeAll(", playersStationInfo=[");
        for (self.playersStationInfo, 0..) |value, i| {
            if (i != 0) try writer.writeAll(", ");
            try value.format(writer);
        }
        try writer.writeAll("], sessionKeyParam=");
        try writer.printHex(&self.sessionKeyParam, .lower);
        try writer.writeAll(" }");
    }

    pub fn serialize(self: *const SessionInfo, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try allocator.alloc(u8, 4 + 4 + (6 * 4) + 2 + 2 + 2 + 1 + 1 + 4 + self.applicationData.len + 4 + 1 + HOST_STATION_SIZE + (16 * LAN_STATION_INFO_SIZE) + SESSION_KEY_PARAM_SIZE);

        var offset: usize = 0;
        try util.RawData.writeBe(u32, bytes, &offset, self.gameMode);
        try util.RawData.writeBe(u32, bytes, &offset, self.sessionId);

        for (self.attributes) |attr| {
            // log.log("Writing attribute {d} at offset 0x{x}\n", .{ attr, offset });
            try util.RawData.writeBe(u32, bytes, &offset, attr);
        }

        try util.RawData.writeBe(u16, bytes, &offset, self.curParticipants);
        try util.RawData.writeBe(u16, bytes, &offset, self.minParticipants);
        try util.RawData.writeBe(u16, bytes, &offset, self.maxParticipants);

        bytes[offset] = self.systemCommunicationVersion;
        bytes[offset + 1] = self.applicationCommunicationVersion;
        offset += 2;

        try util.RawData.writeBe(u32, bytes, &offset, self.sessionType);

        @memcpy(bytes[offset .. offset + self.applicationData.len], self.applicationData);
        offset += self.applicationData.len;
        try util.RawData.writeBe(u32, bytes, &offset, self.applicationDataSize);

        bytes[offset] = if (self.open) 1 else 0;
        offset += 1;

        // TODO: move this into StationLocation
        {
            try util.RawData.writeBe(u32, bytes, &offset, self.stationLocation.address.address);
            try util.RawData.writeBe(u16, bytes, &offset, self.stationLocation.address.port);

            try util.RawData.writeBe(u64, bytes, &offset, self.stationLocation.constantId);
            try util.RawData.writeBe(u32, bytes, &offset, self.stationLocation.variableId);
            try util.RawData.writeBe(u32, bytes, &offset, self.stationLocation.serviceVariableId);

            bytes[offset] = self.stationLocation.urlType;
            bytes[offset + 1] = self.stationLocation.nexStreamId;
            bytes[offset + 2] = self.stationLocation.nexStreamType;
            bytes[offset + 3] = self.stationLocation.natMapping;
            bytes[offset + 4] = self.stationLocation.natFiltering;
            bytes[offset + 5] = self.stationLocation.natLocation;
            bytes[offset + 6] = self.stationLocation.probeInit;
            offset += 7;

            try util.RawData.writeBe(u32, bytes, &offset, self.stationLocation.relayAddress.address);
            try util.RawData.writeBe(u16, bytes, &offset, self.stationLocation.relayAddress.port);
        }

        // TODO: move this into LanStationInfo
        for (self.playersStationInfo) |info| {
            // log.log("Writing LanStationInfo at offset 0x{x}\n", .{offset});
            bytes[offset] = @intFromEnum(info.role);
            bytes[offset + 1] = @intFromEnum(info.usernameEncodingType);
            offset += 2;

            @memcpy(bytes[offset .. offset + 40], &info.username);
            offset += 40;

            try util.RawData.writeBe(u64, bytes, &offset, info.stationId);
        }

        @memcpy(bytes[offset..], &self.sessionKeyParam);
        offset += SESSION_KEY_PARAM_SIZE;

        if (offset != bytes.len) {
            log.debug("SessionInfo serialization offset {d} does not match expected length {d}\n", .{ offset, bytes.len });
        }

        return bytes;
    }
};

const StationLocation = struct {
    const Address = struct { address: u32, port: u16 };

    address: Address,
    constantId: u64,
    variableId: u32,
    serviceVariableId: u32,
    urlType: u8,
    nexStreamId: u8,
    nexStreamType: u8,
    natMapping: u8,
    natFiltering: u8,
    natLocation: u8,
    probeInit: u8,
    relayAddress: Address,

    const ParseReturn = struct { stationLocation: StationLocation, bytesRead: usize };

    pub fn format(self: *const StationLocation, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("StationLocation { ");

        try writer.writeAll("address=");
        try ipv4.formatW(writer, self.address.address);
        try writer.print(":{d}, ", .{self.address.port});

        try writer.print("constantId={d}, variableId={d}, serviceVariableId={d}, ", .{ self.constantId, self.variableId, self.serviceVariableId });
        try writer.print("urlType={d}, nexStreamId={d}, nexStreamType={d}, natMapping={d}, natFiltering={d}, natLocation={d}, probeInit={d}, ", .{ self.urlType, self.nexStreamId, self.nexStreamType, self.natMapping, self.natFiltering, self.natLocation, self.probeInit });

        try writer.writeAll("relayAddress=");
        try ipv4.formatW(writer, self.relayAddress.address);
        try writer.print(":{d} ", .{self.relayAddress.port});

        try writer.writeAll("}");
    }

    fn parse(_bytes: *const []const u8) !ParseReturn {
        const bytes = _bytes.*;
        var stationLocation: @This() = undefined;

        var offset: usize = 0;

        stationLocation.address.address = try util.RawData.readBe(u32, bytes, &offset);
        stationLocation.address.port = try util.RawData.readBe(u16, bytes, &offset);

        stationLocation.constantId = try util.RawData.readBe(u64, bytes, &offset);
        stationLocation.variableId = try util.RawData.readBe(u32, bytes, &offset);
        stationLocation.serviceVariableId = try util.RawData.readBe(u32, bytes, &offset);

        stationLocation.urlType = bytes[offset];
        stationLocation.nexStreamId = bytes[offset + 1];
        stationLocation.nexStreamType = bytes[offset + 2];
        stationLocation.natMapping = bytes[offset + 3];
        stationLocation.natFiltering = bytes[offset + 4];
        stationLocation.natLocation = bytes[offset + 5];
        stationLocation.probeInit = bytes[offset + 6];
        offset += 7;

        stationLocation.relayAddress.address = try util.RawData.readBe(u32, bytes, &offset);
        stationLocation.relayAddress.port = try util.RawData.readBe(u16, bytes, &offset);

        return .{ .stationLocation = stationLocation, .bytesRead = offset };
    }
};

const LanStationInfo = struct {
    const Role = enum(u8) { empty = 0, host = 1, player = 2 };
    const EncodingType = enum(u8) { empty = 0, utf8 = 1, utf16 = 2 };

    role: Role,
    usernameEncodingType: EncodingType,
    username: [40]u8,
    stationId: u64,

    pub fn format(self: *const LanStationInfo, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("LanStationInfo { ");

        if (self.role == .empty) {
            try writer.writeAll("empty }");
            return;
        }

        try writer.print("role={s}, ", .{if (self.role == .host) "host" else "player"});
        // try writer.print("role={d}, ", .{self.role});
        try writer.print("usernameEncodingType={s}, ", .{if (self.usernameEncodingType == .utf8) "utf8" else "utf16"});
        // try writer.print("usernameEncodingType={d}, ", .{self.usernameEncodingType});
        try writer.print("username=\"{s}\", ", .{self.username});
        try writer.print("stationId={d} ", .{self.stationId});
        try writer.writeAll("}");
    }

    fn parse(_bytes: *const []const u8) !LanStationInfo {
        const bytes = _bytes.*;
        var stationInfo: @This() = undefined;

        var offset: usize = 0;

        stationInfo.role = @enumFromInt(bytes[offset]);
        stationInfo.usernameEncodingType = @enumFromInt(bytes[offset + 1]);
        // stationInfo.role = bytes[offset];
        // stationInfo.usernameEncodingType = bytes[offset + 1];
        offset += 2;

        @memcpy(&stationInfo.username, bytes[offset .. offset + 40]);
        offset += 40;

        stationInfo.stationId = try util.RawData.readBe(u64, bytes, &offset);

        return stationInfo;
    }
};

const UnencapsulatedCryptoChallenge = struct {
    version: u8,
    cryptoEnabled: bool,
    nonceCounter: u64,
    challengeKey: [16]u8,
    authenticationTag: [16]u8,
    // 256 bytes in the request, 16 bytes in the response
    challenge: []u8,

    pub fn format(self: *const UnencapsulatedCryptoChallenge, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("UnencapsulatedCryptoChallenge { ");
        try writer.print("version={d}, cryptoEnabled={}, nonceCounter={d}, challengeKey={x}, authenticationTag={x}, challenge=", .{ self.version, self.cryptoEnabled, self.nonceCounter, self.challengeKey, self.authenticationTag });
        try writer.printHex(self.challenge, .lower);
        try writer.writeAll(" }");
    }

    fn parse(allocator: std.mem.Allocator, bytes: []const u8) !UnencapsulatedCryptoChallenge {
        const minLength = 1 + 1 + 8 + 16 + 16 + 16;
        if (bytes.len < minLength) return Error.InvalidPacketData;

        var challenge: @This() = undefined;
        var offset: usize = 0;

        challenge.version = bytes[offset];
        offset += 1;

        challenge.cryptoEnabled = bytes[offset] != 0;
        offset += 1;

        challenge.nonceCounter = try util.RawData.readBe(u64, bytes, &offset);

        @memcpy(&challenge.challengeKey, bytes[offset .. offset + 16]);
        offset += 16;
        @memcpy(&challenge.authenticationTag, bytes[offset .. offset + 16]);
        offset += 16;

        challenge.challenge = try allocator.dupe(u8, bytes[offset..]);
        errdefer allocator.free(challenge.challenge);

        return challenge;
    }

    pub fn freeS(self: *const UnencapsulatedCryptoChallenge, allocator: std.mem.Allocator) void {
        allocator.free(self.challenge);
    }
    pub fn free(self: *UnencapsulatedCryptoChallenge, allocator: std.mem.Allocator) void {
        self.freeS(allocator);
        allocator.destroy(self);
    }

    pub fn serializeRequest(self: *const UnencapsulatedCryptoChallenge) [CRYPTO_CHALLENGE_REQUEST_SIZE]u8 {
        var bytes: [CRYPTO_CHALLENGE_REQUEST_SIZE]u8 = undefined;

        bytes[0] = self.version;
        bytes[1] = if (self.cryptoEnabled) 1 else 0;
        std.mem.writeInt(u64, bytes[2..10], self.nonceCounter, .big);

        var offset: usize = 10;
        @memcpy(bytes[offset .. offset + 16], &self.challengeKey);
        offset += 16;
        @memcpy(bytes[offset .. offset + 16], &self.authenticationTag);
        offset += 16;

        @memcpy(bytes[offset..], self.challenge);

        return bytes;
    }

    pub fn serializeResponse(self: *const UnencapsulatedCryptoChallenge) [CRYPTO_CHALLENGE_RESPONSE_SIZE]u8 {
        var bytes: [CRYPTO_CHALLENGE_RESPONSE_SIZE]u8 = undefined;

        bytes[0] = self.version;
        bytes[1] = if (self.cryptoEnabled) 1 else 0;
        std.mem.writeInt(u64, bytes[2..10], self.nonceCounter, .big);

        var offset: usize = 10;
        @memcpy(bytes[offset .. offset + 16], &self.challengeKey);
        offset += 16;
        @memcpy(bytes[offset .. offset + 16], &self.authenticationTag);
        offset += 16;

        @memcpy(bytes[offset..], self.challenge);

        return bytes;
    }
};

pub fn handlePiaPacket(a: std.mem.Allocator, packet: *ipv4.Packet) !bool {
    const srcPort = std.mem.readInt(u16, packet.payload[0..2], .big);
    const dstPort = std.mem.readInt(u16, packet.payload[2..4], .big);
    if (srcPort == 30000 or dstPort == 30000) return try handleLanBrowse(a, packet, srcPort, dstPort);

    log.debugS("Got a Pia packet\n");

    // TODO: more versions than just 5.9
    const piaPacket = packet.payload[8..];
    const encrypted = piaPacket[4] == 2;

    if (encrypted) try decryptPacket(a, piaPacket, packet.source);

    return false;
}

fn decryptPacket(a: std.mem.Allocator, packet: []u8, sourceIp: u32) !void {
    _ = .{ a, packet, sourceIp };
}

fn handleLanBrowse(a: std.mem.Allocator, packet: *ipv4.Packet, srcPort: u16, dstPort: u16) !bool {
    const payload = packet.payload[8..];
    const pType = payload[0];
    // apparently always 0x23a?
    // const size = std.mem.readInt(u32, payload[1..5], .big);
    // const data = payload[5..size+5];

    if (pType == 0) {
        log.debugS("Caught a Pia lan browse request packet\n");

        const browseRequest = try RawBrowseRequest.parse(a, payload);
        defer browseRequest.freeS(a);

        var challengeKey: ?[16]u8 = null;
        var decrypted: ?[256]u8 = null;
        if (browseRequest.cryptoChallenge) |challenge| {
            log.debugS("Decrypting browse request\n");

            challengeKey = challenge.challengeKey;
            decrypted = crypto.fullDecryptRequestChallenge(&challenge, &ipv4.asByteSlice(config.g.broadcast), &GAME_KEY) catch |e| {
                log.debug("Failed to decrypt browse request challenge: {any}\n", .{e});
                return true;
            };
        }

        const piaBrowseRequest = try PiaBrowseRequest.createSerialized(a, main.TEST_UUID, payload, challengeKey, decrypted, srcPort);
        defer a.free(piaBrowseRequest);
        const lanPacket = try lan.createPacket(a, lan.Type.PiaBrowseRequest, piaBrowseRequest);
        defer lanPacket.freeA(a);
        const lanPayload = try lanPacket.serialize(a);
        defer a.free(lanPayload);
        log.debugS("Sending off a pia browse request packet\n");
        client.sendThread(lanPayload);

        return true;
    } else if (pType == 1) {
        const rawBrowseReply = try RawBrowseReply.parse(a, payload);
        defer rawBrowseReply.freeS(a);

        const sKeyPar = rawBrowseReply.sessionInfo.sessionKeyParam;
        @memcpy(&sessionKeyParam, &sKeyPar);

        const addr = try ipv4.format(a, rawBrowseReply.sessionInfo.stationLocation.address.address);
        log.debug("Caught a Pia lan browse reply packet from (Pia) {s}:{d}\nData: {f}\n", .{ addr, rawBrowseReply.sessionInfo.stationLocation.address.port, rawBrowseReply });
        log.debug("Got session key param: {x}\n", .{sessionKeyParam});

        var replyChallengeKey: ?[16]u8 = null;
        var decrypted: ?[16]u8 = null;
        if (rawBrowseReply.cryptoChallenge) |challenge| {
            log.debugS("Figuring out the challenge key\n");
            // figure out which challenge key this uses
            const challengeKeys = challengeKeyManager.get();
            defer challengeKeyManager.free(challengeKeys);
            const replyNonce = crypto.generateNonce(&ipv4.asByteSlice(config.g.broadcast), challenge.nonceCounter);
            log.debug("Using nonce: {x}\n", .{replyNonce});
            for (challengeKeys) |key| {
                log.debug("Trying challenge key {x}\n", .{key});
                const replyKey = crypto.getReplyEncryptionKey(&challenge.challengeKey, &key, &GAME_KEY);
                log.debug("Derived reply key: {x}\n", .{replyKey});
                decrypted = crypto.decryptResponseChallenge(&challenge, &replyNonce, &replyKey) catch continue;
                replyChallengeKey = key;
                break;
            }

            if (replyChallengeKey) |key| {
                log.debug("Found a matching challenge key {x}\n", .{key});
            } else {
                log.debugS("Couldn't find a matching challenge key for this browse reply, giving up\n");
                return true;
            }
        }

        const brPacket = try PiaBrowseReply.serializedFromRawBrowseReply(a, &rawBrowseReply, main.TEST_UUID, replyChallengeKey, decrypted, dstPort);
        defer a.free(brPacket);

        const lanPacket = try lan.createPacket(a, lan.Type.PiaBrowseReply, brPacket);
        const lanPayload = try lanPacket.serialize(a);
        defer a.free(lanPayload);
        log.debug("Sending off a pia browse reply packet {f}\n", .{rawBrowseReply});
        client.sendThread(lanPayload);
    } else {
        // this would most likely be something else using the same port
        log.debug("Got an unknown unencapsulated Pia type: {d}\n", .{pType});
    }

    return true;
}

pub fn maybePiaPacket(packet: *ipv4.Packet) bool {
    const srcPort = std.mem.readInt(u16, packet.payload[0..2], .big);
    const dstPort = std.mem.readInt(u16, packet.payload[2..4], .big);

    if (packet.protocol != .udp) return false;
    if (srcPort == 30000 or dstPort == 30000) return true;
    if (packet.payload.len > 16 and util.streq(packet.payload[8..12], &PIA_MAGIC)) return true;
    return false;
}

pub const lanClient = struct {
    pub fn handleBrowseRequest(rawPacket: *lan.Packet) !void {
        const allocator = client.allocator;
        const br = try PiaBrowseRequest.parse(allocator, rawPacket.payload);
        defer br.freeS(allocator);

        const source = br.source;
        const payload = br.payload;

        var rawBr = try RawBrowseRequest.parse(allocator, payload);
        defer rawBr.freeS(allocator);
        log.debug("Got a browse request from {f}: {f}\n", .{ source, rawBr });

        if (br.challengeKey) |challengeKey| {
            // we have no need to actually use a proper nonce
            const nonce = crypto.generateNonce(&ipv4.asByteSlice(config.g.broadcast), 0);
            const key = crypto.getRequestEncryptionKey(&challengeKey, &GAME_KEY);
            const encryptedChallenge = crypto.encryptRequestChallenge(&br.challengeData.?, &nonce, &key);

            rawBr.cryptoChallenge.?.nonceCounter = 0;
            rawBr.cryptoChallenge.?.authenticationTag = encryptedChallenge.tag;
            @memcpy(rawBr.cryptoChallenge.?.challenge, &encryptedChallenge.encrypted);
        }

        const srcIp = peer.UuidIp.get(source);
        if (srcIp) |s| {
            const ip = try ipv4.format(allocator, s);
            defer allocator.free(ip);
            log.log("Would be sending this browse request from {s}\n", .{ip});

            if (rawBr.cryptoChallenge) |challenge| {
                log.debug("Storing challenge key {x}\n", .{challenge.challengeKey});
                challengeKeyManager.add(challenge.challengeKey);
            }

            const brPayload = try rawBr.serialize(allocator);
            defer allocator.free(brPayload);

            // TODO: newer pia uses port 35000
            // okay so i meant to set this to broadcast instead of the target's uuid
            // but pia seems fine with it not being broadcast, so we ball
            try client.ipv4utils.handleUdp(source, main.TEST_UUID, br.srcPort, 30000, brPayload);
        } else {
            log.debug("Couldn't find source ip for {f} for a Browse Request\n", .{source});
        }
    }

    pub fn handleBrowseReply(rawPacket: *lan.Packet) !void {
        const allocator = client.allocator;

        var br = try PiaBrowseReply.parse(allocator, rawPacket.payload);
        defer br.freeS(allocator);

        log.debugS("Handling a br packet from the server\n");

        const source = br.source;
        @memcpy(&sessionKeyParam, &br.sessionKeyParam);
        log.debug("Got session key param from {f}: {x}\n", .{ source, br.sessionKeyParam });
        const payload = br.payload;

        var rawBr = try RawBrowseReply.parse(allocator, payload);
        defer rawBr.freeS(allocator);

        log.debug("Parsed pia browse reply: {f}\n", .{br});
        log.debug("Parsed raw browse reply: {f}\n", .{rawBr});

        const srcIp = peer.UuidIp.get(source);
        if (srcIp) |s| {
            rawBr.sessionInfo.stationLocation.address.address = s;

            if (br.key) |reqKey| {
                // br.key is the request challenge key
                const nonce = crypto.generateNonce(&ipv4.asByteSlice(config.g.broadcast), 0);
                const key = crypto.getReplyEncryptionKey(&rawBr.cryptoChallenge.?.challengeKey, &reqKey, &GAME_KEY);
                const encryptedChallenge = crypto.encryptResponseChallenge(&br.decrypted.?, &nonce, &key);
                rawBr.cryptoChallenge.?.nonceCounter = 0;
                rawBr.cryptoChallenge.?.authenticationTag = encryptedChallenge.tag;
                @memcpy(rawBr.cryptoChallenge.?.challenge, &encryptedChallenge.encrypted);

                log.debug("Encrypting browse reply with key {x}, nonce {x}\n", .{key, nonce});
                log.debug("Reencrypted challenge: {f}\n", .{rawBr.cryptoChallenge.?});
            }

            const rawBrPayload = try rawBr.serialize(allocator);
            defer allocator.free(rawBrPayload);

            return client.ipv4utils.handleUdp(source, main.TEST_UUID, 30000, br.dstPort, rawBrPayload);
        } else {
            log.debug("Couldn't find source ip for {f} for a Browse Reply\n", .{source});
        }
    }
};

pub fn _test(a: std.mem.Allocator) !u8 {
    log.logS("hello from the pia test\n");

    // make sure these two match
    const sampleBrowseRequestPacket = "000000023a00010001000a00040000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fff01010000000000000018a7c4c3fc9f44bed6609a25b3198d96be0b204fcfeb56704fa68f76fa1c13caf2eb1faef1e597d1bccccb05d56e910cd7ddfb1852f9aae7a86276a69df3150510da1981665bc3111d9b9a0108109f6026346e498c56f3a5e1a487c8f951b5971cd503383badef1e27e70985ca79ecba5b3b83d575ce712c085f31c1dc15cb3d95a71d63a57bb675b5752cea3c9e1afd8d1398aab58ef3ad6e5f5caa6fa6dab18f92a43568a62ef1089836aa09027cb0dbaea9599f96e7e4a252eb8d287807667be2fd2b62d6bf11d7b1f533e87357f7e3d0a5154c5ebb26269712057bdb38253289ea32fa5fafe0d9a42575f07c8dd1d6e8844ded491dbe3ebf6f7c30ddb7a7418f082854a0f4f669466964bcec7fd904d6411ce57ea44fab22937c802164f417";
    const sampleBrowseReplyPacket = "010000051200000000cc02d8cb00000000000000000000000000000000000000000000000000010001000a05440000640075006d006200200061006800680020007400680069006e00670020007700610068006f006f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a010000000000000000000000000000000000000000000000000000000300000000000000010164756d6220616868207468696e67207761686f6f0000000000000000000000000000000000000000dcd6fb338fd52321000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b0ed9f1493cb25bee54ce48e081c79f2f1bd96f01194bad4c41a7d7db4c87fef0101000000000000000209f4251d679a73be4308af295cbb1dbee24bc5998dbb969cc01c85634bcefb717293b5ce750027893237718617aceaae";
    // splatoon 2
    const gameKey = "ee182a63e216cdb1f51ad4bed8cf6508";
    const requestBroadcast: [4]u8 = .{ 192, 168, 2, 255 };
    const replyBroadcast: [4]u8 = .{ 192, 168, 2, 255 };

    const sampleBrowseRequestBytes = comptime util.comp.hexToBytes(sampleBrowseRequestPacket);
    const sampleBrowseReplyBytes = comptime util.comp.hexToBytes(sampleBrowseReplyPacket);
    const gameKeyBytes = comptime util.comp.hexToBytes(gameKey);

    const rawBrowseRequest = try RawBrowseRequest.parse(a, &sampleBrowseRequestBytes);
    defer rawBrowseRequest.freeS(a);
    const rawBrowseReply = try RawBrowseReply.parse(a, &sampleBrowseReplyBytes);
    defer rawBrowseReply.freeS(a);

    log.log("Parsed a RawBrowseRequest from sample data: {f}\n", .{rawBrowseRequest});
    log.log("Parsed a RawBrowseReply from sample data: {f}\n", .{rawBrowseReply});

    // so, since the nonce for the challenge uses the broadcast address we need to reencrypt the challenge response
    // here we have the request so we can basically just do it from scratch like the replying console would (obviously using the reply's challenge key)
    // TODO: we need to keep track of browse requests and somehow correlate them to browse replies
    // ^ note that each browse request could have multiple different consoles replying to it

    const reqCryptoChallenge = rawBrowseRequest.cryptoChallenge.?;
    const requestNonce = crypto.generateNonce(&requestBroadcast, reqCryptoChallenge.nonceCounter);
    const requestEncKey = crypto.getRequestEncryptionKey(&reqCryptoChallenge.challengeKey, &gameKeyBytes);
    const decryptedChallenge = crypto.decryptRequestChallenge(&reqCryptoChallenge, &requestNonce, &requestEncKey) catch return 1;
    const fullDecryptedChallenge = crypto.fullDecryptRequestChallenge(&reqCryptoChallenge, &requestBroadcast, &gameKeyBytes) catch return 1;

    log.log("Request nonce:\t\t\t{x}\n", .{requestNonce});
    log.log("Request enc key:\t\t\t{x}\n", .{requestEncKey});
    log.log("Decrypted challenge:\t\t{x}\n", .{decryptedChallenge});
    log.log("Full decrypted challenge:\t{x}\n", .{fullDecryptedChallenge});

    const replyCryptoChallenge = rawBrowseReply.cryptoChallenge.?;
    // const replySessionKeyParam = rawBrowseReply.sessionInfo.sessionKeyParam;
    const replyChallengeKey = replyCryptoChallenge.challengeKey;
    const replyNonce = crypto.generateNonce(&replyBroadcast, replyCryptoChallenge.nonceCounter);
    const replyEncKey = crypto.getReplyEncryptionKey(&replyChallengeKey, &reqCryptoChallenge.challengeKey, &gameKeyBytes);
    const replyPayload = crypto.hmacResponseChallenge(&decryptedChallenge, &gameKeyBytes);
    const encryptedReply = crypto.encryptResponseChallenge(&replyPayload, &replyNonce, &replyEncKey);

    log.logS("Reply info (from scratch)\n");
    log.logN("\tenc key:\t\t{x}\n", .{replyEncKey}, false);
    log.logN("\tnonce:\t\t\t{x}\n", .{replyNonce}, false);
    log.logN("\tpayload (pre-encrypt):\t{x}\n", .{replyPayload}, false);
    log.logN("\tencrypted payload:\t{x}\n", .{encryptedReply.encrypted}, false);
    log.logN("\tauth tag:\t\t{x}\n", .{encryptedReply.tag}, false);

    {
        const decryptedResponse = crypto.decryptResponseChallenge(&replyCryptoChallenge, &replyNonce, &replyEncKey) catch return 1;

        log.logS("Reply info (sample)\n");
        log.logN("\tdecrypted payload:\t{x}\n", .{decryptedResponse}, false);
        log.logN("\tencrypted payload:\t{x}\n", .{replyCryptoChallenge.challenge}, false);
        log.logN("\tauth tag:\t\t{x}\n", .{replyCryptoChallenge.authenticationTag}, false);
    }

    return 0;
}

const crypto = struct {
    const aes = std.crypto.core.aes.Aes128;
    const aesgcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const hmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

    // the nonces are the broadcast address followed by the nonce counter
    fn generateNonce(broadcast: *const [4]u8, counter: u64) [12]u8 {
        var nonce: [12]u8 = undefined;
        @memcpy(nonce[0..4], broadcast);
        std.mem.writeInt(u64, nonce[4..12], counter, .big);
        return nonce;
    }

    // the reply encryption key is the first 16 bytes of the hmacsha256 of the game key with the reply challenge key concatenated with the request challenge key
    fn getReplyEncryptionKey(replyChallengeKey: *const [16]u8, requestChallengeKey: *const [16]u8, gameKey: *const [16]u8) [16]u8 {
        var base: [32]u8 = undefined;
        @memcpy(base[0..16], replyChallengeKey);
        @memcpy(base[16..32], requestChallengeKey);
        var hmac: [32]u8 = undefined;
        hmacSha256.create(&hmac, &base, gameKey);
        return hmac[0..16].*;
    }

    // the request encryption key is the request challenge key encrypted with the game key with aes128
    fn getRequestEncryptionKey(requestChallengeKey: *const [16]u8, gameKey: *const [16]u8) [16]u8 {
        var key: [16]u8 = undefined;
        const aesEnc = aes.initEnc(gameKey.*);
        aesEnc.encrypt(&key, requestChallengeKey);
        return key;
    }

    fn decryptRequestChallenge(challenge: *const UnencapsulatedCryptoChallenge, nonce: *const [12]u8, key: *const [16]u8) ![256]u8 {
        if (challenge.challenge.len != 256) return Error.InvalidLength;

        var decrypted: [256]u8 = undefined;
        aesgcm.decrypt(&decrypted, challenge.challenge, challenge.authenticationTag, &.{}, nonce.*, key.*) catch |e| {
            log.err("Failed to decrypt the challenge: {any}\n", .{e});
            return Error.DecryptionFailed;
        };

        return decrypted;
    }

    fn fullDecryptRequestChallenge(challenge: *const UnencapsulatedCryptoChallenge, requestBroadcast: *const [4]u8, gameKey: *const [16]u8) ![256]u8 {
        const nonce = crypto.generateNonce(requestBroadcast, challenge.nonceCounter);
        const encKey = crypto.getRequestEncryptionKey(&challenge.challengeKey, gameKey);
        return crypto.decryptRequestChallenge(challenge, &nonce, &encKey);
    }

    fn decryptResponseChallenge(challenge: *const UnencapsulatedCryptoChallenge, nonce: *const [12]u8, key: *const [16]u8) ![16]u8 {
        if (challenge.challenge.len != 16) return Error.InvalidLength;

        var decrypted: [16]u8 = undefined;
        aesgcm.decrypt(&decrypted, challenge.challenge, challenge.authenticationTag, &.{}, nonce.*, key.*) catch |e| {
            log.err("Failed to decrypt the challenge: {any}\n", .{e});
            return Error.DecryptionFailed;
        };

        return decrypted;
    }

    /// gives the unencrypted reply challenge payload from the request challenge payload
    fn hmacResponseChallenge(challengeData: *const [256]u8, gameKey: *const [16]u8) [16]u8 {
        var hmac: [32]u8 = undefined;
        hmacSha256.create(&hmac, challengeData, gameKey);
        return hmac[0..16].*;
    }

    const EncryptResponseReturn = struct {
        encrypted: [16]u8,
        tag: [16]u8,
    };
    /// gives the encrypted reply challenge from the hmac
    fn encryptResponseChallenge(hmac: *const [16]u8, nonce: *const [12]u8, key: *const [16]u8) EncryptResponseReturn {
        var encrypted: [16]u8 = undefined;
        var tag: [16]u8 = undefined;
        aesgcm.encrypt(&encrypted, &tag, hmac, &.{}, nonce.*, key.*);
        return .{ .encrypted = encrypted, .tag = tag };
    }

    const EncryptRequestReturn = struct {
        encrypted: [256]u8,
        tag: [16]u8,
    };
    fn encryptRequestChallenge(challengeData: *const [256]u8, nonce: *const [12]u8, key: *const [16]u8) EncryptRequestReturn {
        var encrypted: [256]u8 = undefined;
        var tag: [16]u8 = undefined;
        aesgcm.encrypt(&encrypted, &tag, challengeData, &.{}, nonce.*, key.*);
        return .{ .encrypted = encrypted, .tag = tag };
    }
};
