#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define ADDRESS "192.168.2.6"
#define PORT 6968
#define BUFLEN 4096

#define MESSAGE "test c\n"

int main(int argc, char *argv[])
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        perror("socket()");
        exit(1);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    if (inet_aton(ADDRESS, &addr.sin_addr) == 0)
    {
        fprintf(stderr, "Couldn't make our address?");
        exit(1);
    }

    char buf[BUFLEN];
    memset(buf, 0, BUFLEN);
    if (sendto(sock, MESSAGE, strlen(MESSAGE), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1)
    {
        perror("sendto()");
        exit(1);
    };

    close(sock);
    return 0;
}
