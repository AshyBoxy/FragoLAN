import { UUID } from "node:crypto";

let activeClients: ServerClient[] = [];

export const addClient = (address: string, port: number, clients: UUID[]) => {
    let clientIndex = activeClients.findIndex((x) => x.address === address && x.port === port);
    if (clientIndex >= 0) {
        activeClients[clientIndex].clients = clients;
        activeClients[clientIndex].last = Date.now();
        return;
    }
    activeClients.push({
        address,
        port,
        clients,
        last: Date.now()
    });
};

// remove any clients that we haven't seen a keepalive from for 10 seconds
export const checkClients = () => {
    for (let i = 0; i < activeClients.length; i++) {
        const client = activeClients[i];
        const timeDiff = Date.now() - client.last;
        if (timeDiff > (10 * 1000) || timeDiff < 0) {
            activeClients[i] = null;
        }
    }
    activeClients = activeClients.filter((x) => x !== null);
};

export const getClients = () => getClientsExcluding(null, null);
export const getClientsUUIDs = () => getClientsUUIDsExcluding(null, null);
export const getClientsExcluding = (address: string, port: number) => activeClients.filter((x) => !(x.address === address && x.port === port));
export const getClientsUUIDsExcluding = (address: string, port: number) => getClientsExcluding(address, port).map((x) => x.clients).reduce((acc, cur) => [...acc, ...cur], []);

export interface ServerClient {
    address: string;
    port: number;
    clients: UUID[];
    last: number;
}
