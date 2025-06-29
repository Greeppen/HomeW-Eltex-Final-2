#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define ADDR "127.0.0.1"
#define SRC_PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    setsockopt(server_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    printf("Server waiting for messages...\n");

    char packet[BUFFER_SIZE];

    while (1) {
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);

        ssize_t recvmsg = recv(server_fd, buffer, BUFFER_SIZE, 0);
        if (recvmsg < 0) {
            perror("recv");
            exit(EXIT_FAILURE);
        }

        struct iphdr *recv_ip = (struct iphdr *)buffer;
        if (recv_ip->protocol != IPPROTO_UDP) continue;

        struct udphdr *recv_udp = (struct udphdr *)(buffer + sizeof(struct iphdr));
        if (ntohs(recv_udp->dest) != SRC_PORT) continue;

        uint16_t id = ntohs(recv_ip->id);
        int dst_port = ntohs(recv_udp->source);

        char *recv_data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);
        int recv_len = recvmsg - sizeof(struct iphdr) - sizeof(struct udphdr);
        recv_data[recv_len] = '\0';

        if (strcmp(recv_data, "__exit__") == 0) {
            printf("Client on port %d disconnected.\n", dst_port);
            continue;
        }

        printf("Received: '%s' (id=%u) from port %d\n", recv_data, id, dst_port);

        char result[256];
        snprintf(result, sizeof(result), "%s %u", recv_data, id);

        memset(packet, 0, sizeof(packet));
        struct iphdr *ip = (struct iphdr *)packet;
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
        char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        int len_data = strlen(result);
        memcpy(data, result, len_data);

        int udp_len = len_data + sizeof(struct udphdr);
        int ip_len = udp_len + sizeof(struct iphdr);

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(ip_len);
        ip->id = htons(rand() % 65536);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;
        ip->saddr = inet_addr(ADDR);
        ip->daddr = inet_addr(ADDR);

        udp->source = htons(SRC_PORT);
        udp->dest = htons(dst_port);
        udp->len = htons(udp_len);
        udp->check = 0;

        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dst_port);
        dest.sin_addr.s_addr = inet_addr(ADDR);

        ssize_t sended = sendto(server_fd, packet, ip_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sended < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }
    }

    close(server_fd);
    return 0;
}
