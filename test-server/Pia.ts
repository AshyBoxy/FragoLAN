import { UUID } from "crypto";
import { Packet, PacketType } from "./Packet";
import { deserializeUUID, serializeUUID } from "./utils";

export class PiaBrowse extends Packet {
    static RequestPacketType = PacketType.PiaBrowseRequest;
    static ReplyPacketType = PacketType.PiaBrowseReply;

    #source: UUID;
    #payload: Buffer;

    constructor(source: UUID, payload: Buffer, request: boolean) {
        super(request ? PiaBrowse.RequestPacketType : PiaBrowse.ReplyPacketType);

        this.#source = source;
        this.#payload = Buffer.from(payload);
    }

    serialize = (buf: Buffer) => {
        return Buffer.concat([
            buf,
            serializeUUID(this.#source),
            this.#payload
        ]);
    };

    static deserializeBrowse: (buf: Buffer, request: boolean) => PiaBrowse = (buf, request) => {
        const source = deserializeUUID(buf);
        const payload = buf.subarray(16);
        return new PiaBrowse(source, payload, request);
    };

    public get source(): UUID {
        return this.#source;
    }

    public get payload(): Buffer {
        return Buffer.from(this.#payload);
    }
}
