import * as dgram from "node:dgram";
import { getPacketTypeName, Packet, PacketType } from "./Packet";
import { KeepAlive } from "./KeepAlive";
import { randomUUID, UUID } from "node:crypto";
import { deserializePacket } from "./utils";

const client = dgram.createSocket("udp4");
const clients: UUID[] = [randomUUID()];

let keepAliveInterval: NodeJS.Timeout | null = null;

const keepAliveRun = () => {
    const p = new KeepAlive(clients);
    client.send(p.serializeFully());
};

client.on("connect", () => {
    console.log(`Connected from ${client.address().address}:${client.address().port}`);
    if (keepAliveInterval) clearInterval(keepAliveInterval);
    keepAliveInterval = setInterval(keepAliveRun, 500);
});

client.on("error", (err) => {
    console.error(err);
});

client.on("message", (msg, rinfo) => {
    try {
        const packet = deserializePacket(msg);
        console.log(`Got a ${getPacketTypeName(packet.type)} packet`);
        if (packet.type === PacketType.KeepAlive) {
            console.log(`Server has ${(<KeepAlive>packet).clients.length} clients: ${(<KeepAlive>packet).clients.join(", ")}`);
        }
    } catch (error) {}
});

client.connect(6969, "127.0.0.1");
