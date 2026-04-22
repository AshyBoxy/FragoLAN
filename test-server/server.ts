import * as dgram from "node:dgram";
import { KeepAlive } from "./KeepAlive";
import { getPacketTypeName, PacketType } from "./Packet";
import { addClient, checkClients, getClients, getClientsUUIDs, getClientsUUIDsExcluding, ServerClient } from "./serverutils";
import { deserializePacket } from "./utils";
import { IPv4 } from "./IPv4";
import { PiaBrowse } from "./Pia";
const server = dgram.createSocket("udp4");

server.on("listening", () => {
    console.log(`Listening on ${server.address().address}:${server.address().port}`);
});

server.on("error", (err) => {
    console.error(err);
});

const UUID_BROADCAST = "46c98531-2d5f-433b-b2ea-553efd7b4f70";

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

                let dests: ServerClient[] = [];

                if (p.dest === UUID_BROADCAST) {
                    console.log(`Got a broadcast IPv4 packet from ${rinfo.address}:${rinfo.port}, source: ${p.source}`);
                    dests = getClients().filter(x => x.clients.length > 1 || x.clients[0] !== p.source);
                } else {
                    console.log(`Got an IPv4 packet from ${rinfo.address}:${rinfo.port}, source: ${p.source} dest: ${p.dest}`);

                    // really, multiple clients shouldn't advertise the same uuid, but whatever
                    dests = getClients().filter(x => x.clients.findIndex(y => y === p.dest) > -1);
                }

                dests.forEach((d) => {
                    const ps = p.serializeFully();
                    // console.log(ps);
                    server.send(ps, d.port, d.address);
                });

                break;
            }
            case PacketType.PiaBrowseRequest:
            case PacketType.PiaBrowseReply: {
                const p = <PiaBrowse>packet;
                const dests = getClients().filter(x => x.clients.length < 1 || x.clients[0] !== p.source);
                console.log(`Sending a ${getPacketTypeName(packet.type)} packet from ${rinfo.address}:${rinfo.port}, source: ${p.source} to:`, dests.map((x) => x.clients));
                dests.forEach((d) => {
                    const ps = p.serializeFully();
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
