import { UUID } from "crypto";
import { Packet, PacketType } from "./Packet";
import { deserializeUUID, serializeUUID } from "./utils";

export class IPv4 extends Packet {
    static PacketType = PacketType.IPv4;
    static minLength = 16 + 16 + 12; // uuid * 2 + ipv4 header

    #source: UUID;
    #dest: UUID;
    #header: Buffer;
    #options: Buffer;
    #payload: Buffer;

    constructor(source: UUID, dest: UUID, header: Buffer, options: Buffer, payload: Buffer) {
        super(IPv4.PacketType);
        if (header.length !== 12) throw new Error("IPv4 Header is an invalid length");

        this.#source = source;
        this.#dest = dest;
        this.#header = Buffer.from(header);
        this.#options = Buffer.from(options);
        this.#payload = Buffer.from(payload);
    }

    serialize = (buf: Buffer) => {
        const srcDest = Buffer.concat([serializeUUID(this.#source), serializeUUID(this.#dest)]);
        return Buffer.concat([
            buf,
            srcDest,
            this.#header,
            this.#options,
            this.#payload
        ]);
    };

    static deserialize: (buf: Buffer) => IPv4 = (buf) => {
        if (buf.length < IPv4.minLength) throw new Error("Packet is smaller than minimum length");

        const srcDest = buf.subarray(0, 32);

        const source = deserializeUUID(srcDest);
        const dest = deserializeUUID(srcDest, 16);

        const header = buf.subarray(32, 44);

        const ihl = header[0] & 0x0F;
        if (ihl < 5) throw new Error("ihl is less than 5?")
        const optionsSize = (ihl - 5) * 4;
        if (buf.length - IPv4.minLength < optionsSize) throw new Error("Not enough space in IPv4 header for options");

        const options = buf.subarray(44, optionsSize);
        const payload = buf.subarray(44 + optionsSize);

        return new IPv4(source, dest, Buffer.from(header), Buffer.from(options), Buffer.from(payload));
    };

    public get source(): UUID {
        return this.#source;
    }

    public get dest(): UUID {
        return this.#dest;
    }

    public get header(): Buffer {
        return Buffer.from(this.#header);
    }

    public get payload(): Buffer {
        return Buffer.from(this.#payload);
    }
}
