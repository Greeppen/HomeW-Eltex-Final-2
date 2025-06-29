#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define ADDR "127.0.0.1"
#define DST_PORT 8080
#define BUFFER_SIZE 1024

int main() {
    srand(time(NULL));
    int client_fd;
    uint16_t packet_counter = 1;
    int src_port = (rand() % 16382) + 4000;

    client_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (client_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    char packet[BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    int one = 1;
    setsockopt(client_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DST_PORT);
    dest.sin_addr.s_addr = inet_addr(ADDR);

    while (1) {
        char msg[BUFFER_SIZE];

        while (1) {
            printf("Enter message: ");
            if (fgets(msg, sizeof(msg), stdin) == NULL) {
                printf("Input error\n");
                continue;
            }

            size_t len = strlen(msg);
            if (len > 0 && msg[len - 1] == '\n') {
                msg[len - 1] = '\0';
            }

            if (strlen(msg) == 0) {
                continue;
            }

            break;
        }

        struct iphdr *ip = (struct iphdr *)packet;
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
        char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

        strncpy(data, msg, BUFFER_SIZE - sizeof(struct iphdr) - sizeof(struct udphdr));
        int len_data = strlen(data);
        int udp_len = len_data + sizeof(struct udphdr);
        int ip_len = udp_len + sizeof(struct iphdr);

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(ip_len);
        ip->id = htons(packet_counter++);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;
        ip->saddr = inet_addr(ADDR);
        ip->daddr = inet_addr(ADDR);

        udp->source = htons(src_port);
        udp->dest = htons(DST_PORT);
        udp->len = htons(udp_len);
        udp->check = 0;

        ssize_t sended = sendto(client_fd, packet, ip_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sended < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        while (1) {
            char buffer[BUFFER_SIZE];
            memset(buffer, 0, BUFFER_SIZE);

            ssize_t recvmsg = recv(client_fd, buffer, BUFFER_SIZE, 0);
            if (recvmsg < 0) {
                perror("recv");
                exit(EXIT_FAILURE);
            }

            struct iphdr *recv_ip = (struct iphdr *)buffer;
            if (recv_ip->protocol != IPPROTO_UDP)
                continue;

            struct udphdr *recv_udp = (struct udphdr *)(buffer + sizeof(struct iphdr));
            if (ntohs(recv_udp->dest) != src_port)
                continue;

            char *recv_data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);
            int recv_len = recvmsg - sizeof(struct iphdr) - sizeof(struct udphdr);
            if (recv_len < 0) recv_len = 0;
            recv_data[recv_len] = '\0';

            printf("Server replied: %s\n\n", recv_data);
            break;
        }
    }

    close(client_fd);
    return 0;
}
