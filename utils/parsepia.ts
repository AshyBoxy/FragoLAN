import crypto from "node:crypto";

// thank you https://github.com/kinnay/NintendoClients/wiki
// a lot of the comments in here are paraphrased from there

const samplePiaPacket = "32ab9864010000002e9d000000000000000000000000000000000000000000000000000009000c000000000000000000000000000000004400000000070000000000000000000000";
const samplePiaPacket2 = "32ab98640200000092b5000092f727615b50db035ad311318a7756698456b882be8d494c8dcb3ba45cb06ace0066f9b31ebf2a6217f2c6d7a03d7325eab5d74a00403f025f24af9bf2b36117b5d3dc9f5ee026ad";
const sampleBrowseRequest = "000000023a00010001000a00040000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fff0101000000000000001f3c35ed2158b4cd8e1508298b945828466bbfd66a9ba795afbe00e0c43a90971c029597a1cd1a6db164e38516bd14ae21c742f27e40f9eb4c19d4816659505ab75c16e43f40a164085e071d2c61fb8fbdb2892a2ce6d58b3284198547f816ad25c1686bbe33fa414359d133d0e1a3d9ede658d782203d682bff7da8667e32c6a9d1a5864e9ad1851d529835c0b4333a06a22bb21bf8dd566f25b1be694d1c0c0989e00cab40e5fdde86a702186a4588fa0095d6a4fef24f7a4007a9233411250c64ffaa7d77b221bbb334ba1f414b3ca0a7438e0ef693b26507e513d6b76717007c508a9d6372b75efba7a145b01ec7da26abf8d199878232814b4dc780bb07b5f4f1cdc7a70c0be9951496f914a989e4b19fa02290658a3b26e1a359b3298e86";
const sampleBrowseReply = "0100000512000000000134c00000000000000000000000000000000000000000000000000000010001000a054700004e00690063006b0037003200000000002c35500c100000005835500c10000000e474bca5200000000000000000000000000000000000000000000000000000000000000000000000005b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a01c0a80134c000c0a801340000c000c0f72f500134c0000000000102030000000000000001014e69636b373200000000000000000000000000000000000000000000000000000000000000000000c0a801340000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110f90988f999e3219f6b008594639c3f6f7e5ab880fa3a8321f4c858c020fbf01010000000000000001191844d1758b1ec42e43960ea43d5babf67299e3fd90a5324c27de772d9a301d1db551142446b5b5e51afa63b6433315";

const sampleTest = "010000051200000000414ac00100000000000000000000000000000000000000000000000000010001000a05440000410073006800790042006f00780079000000b49f5800000058f5b49f58000000e434fca84e0000000000000000000000000000000000000000000000000000000000000000000000005b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a010a0d414ac0010a0d414a0000c0019082ba63414ac00100000001020300000000000000010141736879426f787900000000000000000000000000000000000000000000000000000000000000000a0d414a0000c00100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000088f9b093bcd224bba5a674225dacd37829e8fd632d96204efb619445d7825a60010100000000000000036c214ba1a89e05f0d026c90dadcc5d156a00fff920f00f032d852305feeaaf97a621a6334fdb2e0d10184c04324742a1";
const sampleTest2 = "32ab98640200000092b5000092f727615b50db035ad311318a7756698456b882be8d494c8dcb3ba45cb06ace0066f9b31ebf2a6217f2c6d7a03d7325eab5d74a00403f025f24af9bf2b36117b5d3dc9f5ee026ad";


const sampleTest3 = "010000051200000000636b09d000000000000000000000000000000000000000000000000000010001000a05440000640075006d006200200061006800680020007400680069006e00670020007700610068006f006f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a000a0d460300000000000000000000000000000000000000000000000300000000000000010164756d6220616868207468696e67207761686f6f000000000000000000000000000000000000000000000000565bb630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b94d7ac2cc349cff98b6867f6392bd0469b7dc695755e783904798fbed1999bf0101000000000000000e0bee991dc7efb0488d60a261e09640c674334404b1e2719cbb09b41d03b3eda99c11cbc788cf92e11b70a53b06c6b0ec";

const HEADER_MAGIC = Buffer.from([0x32, 0xab, 0x98, 0x64]);
const splatoon2key = "ee182a63e216cdb1f51ad4bed8cf6508";

// maximum packet size pia can receive is is 1472 up to pia 6.33, 1452 thereafter
interface PiaPacket {
    // comments are describing the raw values
    // starts with magic number  0x 32 ab 98 64

    // just used in this program:
    // 1    :   -5.6
    // 2    :   5.7-5.10
    // official:
    // 3    :   5.11-5.17
    // 4    :   5.18-5.21
    // 5    :   5.23-5.26
    // 9    :   5.27-5.45
    // 11   :   6.16-6.23
    // 12   :   6.25-6.26
    // 13   :   6.29-6.30
    // 15   :   6.32-6.34
    // 16   :   6.39-7.2
    // this is encrypted & 0x7f in 5.11+
    version: number;

    // 1 byte; 1 = no, 2 = yes
    // version & 0x80 in 5.11+
    encrypted: number;
    // 1 byte, random number between 2 and 255
    // if packets are sent to a specific address rather than station index, the connection id is 0
    connectionId: number;
    // 2 bytes; integer; 0 if connection id is 0
    // starts at 1 when the connection id is not 0
    // when it rolls over, 0 is skipped, so 65535 > 1
    packetId: number;
    // the timers are used for latency calculations by pia
    // 2 bytes
    sourceTimer: number;
    destinationTimer: number;

    // 5.7+ (in 5.6- this is at the end of the packet)
    // 8 bytes
    nonce: Buffer;
    // 16 bytes 5.7-5.10, 8 bytes 5.11+
    authentication: Buffer;

    // at least one, these are what might be encrypted
    // "all messages are padded such that their size is a multiple of 4 bytes"
    // ^ is this each message individually, or all of them together though?
    // (like as in if you have 2 messages, would they both individually be padded, or would it only pad at the end)
    messages: PiaMessage[];

    // only in lan and ldn, contains the variable id of all the receiving consoles as 16 bit integers
    footer?: VariableId[];
}

interface PiaMessage {
    // 1 byte
    flags: number;
    // 1 byte; 5.4- only
    sourceStationIndex: number;
    // 2 bytes
    payloadSize: number;
    // 4 bytes 5.4-; 8 bytes 5.6+
    destination: Buffer;
    // 4 bytes 5.4-; 8 bytes 5.6+; source constant id
    source: Buffer;
    // 2 bytes 5.4-; 1 byte 5.6+
    protocolType: uint8;
    // 2 bytes 5.4-; 1 byte 5.6+
    protocolPort: number;

    // 4 reserved (zero) bytes here on 5.4
    // 3 bytes zero padding here on 5.6

    payload: Buffer;
}

interface PiaLanMessage extends PiaMessage {
    protocolType: 0x44;
    lanMessageType: uint8;
}

// 32 bit in 5.44-; 16 bit in 6.16+
type VariableId = number;

function parsePiaPacket(packetHex: string, sessionKey?: Buffer, sourceIp?: [number, number, number, number]): PiaPacket | null {
    let buf = Buffer.from(packetHex, "hex");

    const magic = buf.subarray(0, 4);
    if (!magic.equals(HEADER_MAGIC)) {
        console.log("not a pia packet");
        return null;
    }
    console.log("that is indeed a pia packet");
    // buf = buf.subarray(4);
    // console.log(buf);

    // TODO: other versions
    let p: Partial<PiaPacket> = {};
    p.encrypted = buf[4];
    p.connectionId = buf[5];
    p.packetId = buf.readUInt16BE(6);
    p.sourceTimer = buf.readUInt16BE(8);
    p.destinationTimer = buf.readUInt16BE(0xa);

    // TODO:
    // this just seems to be what splatoon 2 uses
    p.version = 2;

    p.nonce = Buffer.from(buf.subarray(0xc, 0x14));
    p.authentication = Buffer.from(buf.subarray(0x14, 0x24));

    let rest = buf.subarray(0x24);
    // console.log({ packet: p, rest, l: rest.length % 4 });

    p.messages = [];

    // i don't think there will be a footer when it's encrypted?
    if (p.encrypted === 2 && sessionKey !== undefined && sourceIp !== undefined) {
        const nonce = Buffer.alloc(12);
        nonce[0] = sourceIp[0];
        nonce[1] = sourceIp[1];
        nonce[2] = sourceIp[2];
        nonce[3] = sourceIp[3];

        nonce[4] = p.connectionId;

        p.nonce.copy(nonce, 5, 1);

        const decipher = crypto.createDecipheriv("aes-128-gcm", sessionKey, nonce);
        decipher.setAuthTag(p.authentication);
        rest = Buffer.concat([decipher.update(rest), decipher.final()]);
    }

    while (rest.length >= 0x18) {
        const message: Partial<PiaMessage> = {};

        message.flags = rest[0];
        message.payloadSize = rest.readUInt16BE(1);
        message.destination = Buffer.from(rest.subarray(0x3, 0xb));
        message.source = Buffer.from(rest.subarray(0xb, 0x13));
        message.protocolType = rest[0x13];
        message.protocolPort = rest[0x14];
        // 3 padding

        const headerLength = 0x18;
        const totalSize = headerLength + message.payloadSize;
        const padding = (4 - (totalSize % 4)) % 4;
        message.payload = Buffer.from(rest.subarray(headerLength, headerLength + message.payloadSize));

        if (message.protocolType === 0x44) {
            const m = <PiaLanMessage>message;
            const p = message.payload;
            m.lanMessageType = p[0];
        }

        p.messages.push(<PiaMessage>message);
        rest = rest.subarray(headerLength + message.payloadSize + padding);
    }

    if (rest.length > 1 && rest.length % 2 === 0) {
        p.footer = [];
        if (p.version >= 11) {
            // 16 bit variable ids
            const count = rest.length / 2;
            for (let i = 0; i < count; i++) {
                p.footer.push(rest.readUInt16BE(i * 2));
            }
        } else {
            if (rest.length % 4 !== 0)
                throw new Error("glup");

            // 32 bit variable ids
            const count = rest.length / 4;
            for (let i = 0; i < count; i++) {
                p.footer.push(rest.readUInt32BE(i * 4));
            }
        }

    } else if (rest.length > 0) {
        console.log("there's something weird going on", rest);
    }

    // console.log({ p, messages: p.messages, rest });
    return <PiaPacket>p;
}

// this is for 5.44- only
// for browse request and browse reply
interface UnencapsulatedLanPacket {
    // 1 byte
    type: number;
    // 4 bytes; apparently always 0x23a?
    size: number;

    // data here

    // 0x12a bytes; 5.7+ only
    crypto?: Buffer;
}

interface BrowseRequestPacket extends UnencapsulatedLanPacket {
    searchCriteria: Buffer;
}

interface BrowseReplyPacket extends UnencapsulatedLanPacket {
    sessionInfo: LanSessionInfo;
}

type uint64 = BigInt;
type uint32 = number;
type uint16 = number;
type uint8 = number;
type bytes = Buffer;

interface LanSessionInfo {
    gameMode: uint32;
    sessionId: uint32;
    // 6 of these
    attributes: uint32[];
    participantCount: uint16;
    minParticipants: uint16;
    maxParticipants: uint16;

    // 5.3+
    // 0    :   5.3
    // 2    :   5.6
    // 3    :   5.7
    // 4    :   5.8
    // 5    :   5.9
    // 6    :   5.10
    // 7    :   5.11-5.18
    // 8    :   5.19-5.44
    // 10   :   6.16-6.30
    // 22   :   6.41
    systemCommunicationVersion?: uint8;
    applicationCommunicationVersion?: uint8;

    sessionType: uint32;
    applicationData: bytes;
    // apparently always 0x180 (384)?
    applicationDataSize: uint32;
    // i assume a boolean is 1 byte?
    open: boolean;

    // 5.9- this is a StationLocation
    // 5.10+ this is a StationAddress
    hostStation: StationInfo;

    // 5.10+
    hostConstantId?: uint64;
    hostVariableId?: uint32;
    hostServiceVariableId?: uint32;

    // 16 of these
    lanStationInfo: LanStationInfo[];

    // 5.7+
    // 0x20 bytes
    sessionKeyParam?: bytes;
}

interface LanStationInfo {
    // 1 = host, 2 = player
    role: uint8;
    // 1 = utf8, 2 = utf16
    usernameEncoding: uint8;
    // 40 bytes
    username: string;
    stationId: uint64;
}

interface StationInfo {
    // 5.2-5.9
    // these are described as one field
    // 4 bytes
    stationAddress: string;
    stationPort: uint16;

    // we only really care about the address
    rest: bytes;
}

function parseUnencapsulatedLanPacket(packetHex: string): UnencapsulatedLanPacket {
    let buf = Buffer.from(packetHex, "hex");

    const p: Partial<UnencapsulatedLanPacket> = {};
    p.type = buf[0];
    p.size = buf.readUInt32BE(1);

    if (buf.length - (p.size + 5) > 0) {
        p.crypto = Buffer.from(buf.subarray(5 + p.size));
    }

    if (p.type === 0) {
        const t = <BrowseRequestPacket>p;
        t.searchCriteria = Buffer.from(buf.subarray(5, p.size + 5));
    } else if (p.type === 1) {
        const t = <BrowseReplyPacket>p;
        // t.sessionInfo = Buffer.from(buf.subarray(5, p.size + 5));
        t.sessionInfo = parseLanSessionInfo(buf.subarray(5, p.size + 5),);
    }

    // console.log(p);
    if (p.type === 1) {
        // console.log((<BrowseReplyPacket>p).sessionInfo.lanStationInfo);
    }

    return <UnencapsulatedLanPacket>p;
}

function parseLanSessionInfo(buffer: Buffer): LanSessionInfo {
    const s: Partial<LanSessionInfo> = {};

    s.gameMode = buffer.readUInt32BE(0x0);
    s.sessionId = buffer.readUInt32BE(0x4);

    s.attributes = [];
    for (let i = 0; i < 6; i++) {
        s.attributes.push(buffer.readUInt32BE(0x4 + 0x4 * (i + 1)));
    }

    s.participantCount = buffer.readUInt16BE(0x20);
    s.minParticipants = buffer.readUInt16BE(0x22);
    s.maxParticipants = buffer.readUInt16BE(0x24);

    let offset = 0x26;

    // TODO: check for lower than 5.3
    // actually this needs to check versions in general, i was dumb and didn't realise version wasn't available here
    // should be able to just check the full length of the buffer
    s.systemCommunicationVersion = buffer.readUInt8(offset);
    s.applicationCommunicationVersion = buffer.readUInt8(offset + 1);
    offset += 2;

    s.sessionType = buffer.readUInt32BE(offset);
    offset += 4;

    // since applicationdatasize comes after applicationdata we need to read in reverse

    let endOffset = 0;
    if (s.systemCommunicationVersion >= 3) {
        s.sessionKeyParam = Buffer.from(buffer.subarray(-0x20));
        endOffset += 0x20;
    }

    s.lanStationInfo = [];
    for (let i = 0; i < 16; i++) {
        // endOffset += 0x32;
        endOffset += 0x32;
        const b = buffer.subarray(-endOffset);
        // console.log(`Reading LanStationInfo at 0x${(buffer.length - endOffset).toString(16)}`);

        const lsi: LanStationInfo = {
            role: b[0],
            usernameEncoding: b[1],
            username: b.subarray(2, 0x2a).toString(b[0] === 2 ? "utf16le" : "utf8").replaceAll("\0", ""),
            stationId: b.readBigUInt64BE(0x2a)
        };

        s.lanStationInfo.unshift(lsi);

    }

    if (s.systemCommunicationVersion <= 5) {
        // 5.2 - 5.9 only;
        const b = buffer.subarray(-(endOffset + 0x23), -endOffset);
        endOffset += 0x23;
        console.log(`Bleeeeehhh: 0x${endOffset.toString(16)}`);

        s.hostStation = {
            stationAddress: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`,
            stationPort: b.readUInt16BE(4),
            rest: Buffer.from(b.subarray(6))
        };
    } else {
        // TODO: uhhhh i decided i don't care for now
        // stationaddress is 8 bytes
        endOffset += (8 + 16 + 8 + 8);
    }

    s.open = buffer.readUInt8(buffer.length - endOffset - 1) !== 0;
    endOffset += 1;

    s.applicationDataSize = buffer.readUInt32BE(buffer.length - endOffset - 4);
    endOffset += 4;

    console.log(`offset: 0x${offset.toString(16)}, endOffset: 0x${endOffset.toString(16)}, diff: 0x${(buffer.length - offset - endOffset).toString(16)}`);

    s.applicationData = Buffer.from(buffer.subarray(buffer.length - endOffset - s.applicationDataSize, buffer.length - endOffset));
    // s.applicationDataLength = s.applicationData.length.toString(16);

    /*
    s.applicationData = Buffer.from(buffer.subarray(offset, offset + 0x180));
    offset += 0x180;
    s.applicationDataSize = buffer.readUInt32BE(offset);
    offset += 4;
    if (s.applicationDataSize !== 0x180) console.log("application data size is not 0x180");

    s.open = buffer.readUint8(offset) > 0;
    offset += 1;

    }*/

    return <LanSessionInfo>s;
}

function calculateSessionKeyLan(sessionKeyParam: Buffer, gameKey: string): Buffer {
    const k = Buffer.from(sessionKeyParam);
    k[k.length - 1] = k[k.length - 1] + 1;
    const hmac = crypto.createHmac("sha256", Buffer.from(gameKey, "hex"));
    hmac.update(k);
    return hmac.digest().subarray(0, 16);
}

// parsePiaPacket(samplePiaPacket);
// parsePiaPacket(samplePiaPacket2);
// parseUnencapsulatedLanPacket(sampleBrowseRequest);
// parseUnencapsulatedLanPacket(sampleBrowseReply);
// parseUnencapsulatedLanPacket(sampleTest);
// parsePiaPacket(sampleTest2);





// const packet = parseUnencapsulatedLanPacket(sampleTest);
// if (packet.type !== 1) throw new Error("what");
// const key = calculateSessionKeyLan((<BrowseReplyPacket>packet).sessionInfo.sessionKeyParam!, splatoon2key);
// console.log(key.toString("hex"));
// const p2 = parsePiaPacket(sampleTest2, key, [10, 13, 65, 74]);
// console.log(p2);

// console.log(parsePiaPacket(sampleTest3));
console.log(parseUnencapsulatedLanPacket(sampleTest3));
