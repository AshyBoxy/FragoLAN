import * as dgram from "node:dgram";
import { KeepAlive } from "./KeepAlive";
import { getPacketTypeName, PacketType } from "./Packet";
import { addClient, checkClients, getClients, getClientsUUIDs, getClientsUUIDsExcluding } from "./serverutils";
import { deserializePacket } from "./utils";
import { IPv4 } from "./IPv4";
const server = dgram.createSocket("udp4");

server.on("listening", () => {
    console.log(`Listening on ${server.address().address}:${server.address().port}`);
});

server.on("error", (err) => {
    console.error(err);
});

server.on("message", (msg, rinfo) => {
    try {
        const packet = deserializePacket(msg);
        switch (packet.type) {
            case PacketType.KeepAlive: {
                addClient(rinfo.address, rinfo.port, (<KeepAlive>packet).clients);
                checkClients();
                const uuids = getClientsUUIDsExcluding(rinfo.address, rinfo.port);
                // console.log(uuids);
                const p = new KeepAlive(uuids);
                try {
                    server.send(p.serializeFully(), rinfo.port, rinfo.address);

                } catch (error) {
                    console.error(error);
                }

                break;
            }
            case PacketType.IPv4: {
                const p = <IPv4>packet;
                // console.log(`Got an IPv4 packet from ${rinfo.address}:${rinfo.port}, source: ${p.source} dest: ${p.dest}`);

                // really, multiple clients shouldn't advertise the same uuid, but whatever
                const dests = getClients().filter(x => x.clients.findIndex(y => y === p.dest) > -1);
                dests.forEach((d) => {
                    const ps = p.serializeFully();
                    // console.log(ps);
                    server.send(ps, d.port, d.address);
                });
                break;
            }
            default:
                console.log(`Got a ${getPacketTypeName(packet.type)} packet from ${rinfo.address}:${rinfo.port}`);
                break;
        }
    } catch (error) { }
});

setInterval(() => {
    checkClients();
    console.log(`Active clients: ${getClients().length}, uuids: ${getClientsUUIDs().length}`);
}, 5000);


server.bind(6969, "0.0.0.0");
