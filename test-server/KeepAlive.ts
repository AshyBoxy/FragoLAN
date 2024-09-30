import { UUID } from "node:crypto";
import { Packet, PacketType } from "./Packet";
import { deserializeUUID, serializeUUID } from "./utils";

export class KeepAlive extends Packet {
    static PacketType = PacketType.KeepAlive;

    #clients: UUID[];

    constructor(clients: UUID[]) {
        if (clients.length > 255) throw new Error("Too many clients for KeepAlive packet");

        super(KeepAlive.PacketType);
        this.#clients = clients;
    }

    serialize = (buf: Buffer) => {
        const headerBuf = Buffer.from([this.#clients.length]);
        const clientBufs: Buffer[] = [];
        for (const client of this.#clients) {
            clientBufs.push(serializeUUID(client));
        }
        return Buffer.concat([buf, headerBuf, ...clientBufs]);
    };

    public get clients(): UUID[] {
        return this.#clients;
    }

    static deserialize: (buf: Buffer) => KeepAlive = (buf) => {
        const clientCount = buf.readUint8(0);
        if (buf.length - 1 < clientCount * 16) throw new Error(`Tried to deserialize KeepAlive with ${clientCount} clients, but only space for ${Math.floor(buf.length - 1 / 16)}`);

        const clients: UUID[] = [];

        for (let i = 0; i < clientCount; i++) {
            const curBuf = buf.subarray((i * 16) + 1);
            clients.push(deserializeUUID(curBuf));
        }

        return new KeepAlive(clients);
    };
}
