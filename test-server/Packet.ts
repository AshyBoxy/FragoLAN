import { KeepAlive } from "./KeepAlive";

const EmptyBuffer = Buffer.from([]);

export class Packet {
    protected constructor(type: PacketType) {
        this.type = type;
    }

    type: PacketType;

    serializeFully: () => Buffer = () => {
        const b = Buffer.alloc(2);
        b.writeUint16BE(this.type);
        return this.serialize(b);
    };

    serialize: (buf: Buffer) => Buffer = (buf) => buf;

    static deserialize: (buf: Buffer) => Packet = () => { throw new Error("Tried to call an unimplemented deserialize?"); };
}

export enum PacketType {
    KeepAlive = 1,
    IPv4 = 2
}

export const getPacketTypeName: (type: PacketType) => string = (type: PacketType) => Object.keys(PacketType).find((x) => PacketType[x] == type) || type.toString();
