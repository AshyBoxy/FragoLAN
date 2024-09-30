import { UUID } from "crypto";
import { Packet, PacketType } from "./Packet";
import { KeepAlive } from "./KeepAlive";
import { IPv4 } from "./IPv4";

export const serializeUUID = (uuid: UUID): Buffer => {
    const u = uuid.replace(/-/g, "");
    if (u.length !== 32) throw new Error("UUID of invalid length");

    const buf = Buffer.alloc(16);

    for (let i = 0; i < 32; i++) {
        buf[i] = parseInt(u.substring(i * 2, (i * 2) + 2), 16);
    }

    return buf;
};

export const deserializeUUID = (buf: Buffer, offset = 0): UUID => {
    if (buf.length <= offset) throw new Error("Tried to use an offset longer than the buffer");

    const subBuf = buf.subarray(offset);
    if (subBuf.length < 16) throw new Error("Tried to deserialize a buffer without space for a uuid");

    // now actually deserialize it
    let uuid = "";

    for (let i = 0; i < 16; i++) {
        const byte = buf[i];
        uuid += byte.toString(16).padStart(2, "0");
    }

    return `${uuid.substring(0, 8)}-${uuid.substring(8, 12)}-${uuid.substring(12, 16)}-${uuid.substring(16, 20)}-${uuid.substring(20, 33)}`;
};

export const deserializePacket: (buf: Buffer) => Packet = (buf) => {
    const t = buf.readUint16BE(0);
    const payloadBuf = buf.subarray(2);
    switch (t) {
        case PacketType.KeepAlive:
            return KeepAlive.deserialize(payloadBuf);
        case PacketType.IPv4:
            return IPv4.deserialize(payloadBuf);
        default:
            throw new Error(`Unknown packet type: ${t}`);
    }
};
