import { randomUUID } from "crypto";
import { Packet, PacketType } from "./Packet";
import { KeepAlive } from "./KeepAlive";
import { deserializePacket, deserializeUUID, serializeUUID } from "./utils";
import { addClient, getClientsUUIDs, getClientsUUIDsExcluding } from "./serverutils";
import { calculateChecksum, validateChecksum } from "./checksum";

// const u = randomUUID();
// const u = "7ee512a7-c866-4d54-a52e-911dcdc715f9";
// const us = serializeUUID(u);
// const ud = deserializeUUID(us);

// console.log({ u, us, ud });

// const p = new KeepAlive([u]);
// const ps = p.serializeFully();
// console.log({ p: p.clients, ps });

// const p2 = <KeepAlive>deserializePacket(ps);
// if (p2.type !== PacketType.KeepAlive) throw new Error();
// const p2s = p2.serializeFully();
// console.log({ p2: p2.clients, p2s });

// addClient("test1", 69, ["3cda86f9-d55e-4148-a019-371dd6d4076f"]);
// addClient("test2", 70, ["f1ccc114-5a34-1afa-1584-d226516e83df"]);
// const u = getClientsUUIDsExcluding("test1", 69);
// console.log(u);

// console.log(deserializeUUID(serializeUUID("3cda86f9-d55e-4148-a019-371dd6d4076f")));

// const p = new KeepAlive(u);
// const ps = p.serializeFully();
// console.log(ps);

// const testHeader = [
//     102, 175, 241, 8, 104, 154,
//     79, 17, 130, 111, 172, 171,
//     209, 17, 86, 160, 161, 73,
//     109, 187
// ];
const testHeader = [
    0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,/* 0xb8, 0x61,*/0, 0, 0xc0, 0xa8, 0x00, 0x01
    , 0xc0, 0xa8, 0x00, 0xc7
];
const checksum = calculateChecksum(testHeader);
console.log(`Checksum: 0x${checksum.toString(16)}`);
testHeader[10] = checksum >> 8;
testHeader[11] = checksum & 0xFF;
// testHeader[10] = 0xb8
// testHeader[11] = 0x61
console.log(`Valid: ${validateChecksum(testHeader)}`);
