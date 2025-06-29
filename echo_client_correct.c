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

struct Message {
    struct iphdr ip;
    struct udphdr udp;
    char data[BUFFER_SIZE - sizeof(struct iphdr) - sizeof(struct udphdr)];
};

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

    int one = 1;
    setsockopt(client_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DST_PORT);
    dest.sin_addr.s_addr = inet_addr(ADDR);

    struct Message msg_packet;

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
            if (strlen(msg) == 0) continue;
            break;
        }

        memset(&msg_packet, 0, sizeof(msg_packet));

        strncpy(msg_packet.data, msg, sizeof(msg_packet.data) - 1);
        int len_data = strlen(msg_packet.data);

        int udp_len = len_data + sizeof(struct udphdr);
        int ip_len = udp_len + sizeof(struct iphdr);

        msg_packet.ip.ihl = 5;
        msg_packet.ip.version = 4;
        msg_packet.ip.tos = 0;
        msg_packet.ip.tot_len = htons(ip_len);
        msg_packet.ip.id = htons(packet_counter++);
        msg_packet.ip.frag_off = 0;
        msg_packet.ip.ttl = 64;
        msg_packet.ip.protocol = IPPROTO_UDP;
        msg_packet.ip.check = 0;
        msg_packet.ip.saddr = inet_addr(ADDR);
        msg_packet.ip.daddr = inet_addr(ADDR);

        msg_packet.udp.source = htons(src_port);
        msg_packet.udp.dest = htons(DST_PORT);
        msg_packet.udp.len = htons(udp_len);
        msg_packet.udp.check = 0;

        ssize_t sended = sendto(client_fd, &msg_packet, ip_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sended < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        while (1) {
            char buffer[BUFFER_SIZE];
            memset(buffer, 0, sizeof(buffer));

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
