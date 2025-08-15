/*
 * test_send_raw.c: A simple C program to send a custom payload in a UDP packet
 * out of a specific network interface.
 *
 * COMPILE:
 * gcc -o send_raw send_raw.c
 *
 * RUN (requires root privileges):
 * sudo ./send_raw <interface> "<payload_string>"
 *
 * EXAMPLE:
 * sudo ./send_raw eth0 "This is a test packet"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

// Dummy destination details. Change as needed.
#define DEST_IP "8.8.8.8"
#define DEST_PORT 80

// Function to calculate the IP header checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> \"<payload_string>\"\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0 \"Hello from raw socket\"\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *iface_name = argv[1];
    const char *payload_str = argv[2];

    // 1. Create a raw socket that will build UDP packets
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    // 2. Bind the socket to the specified interface.
    // This is the crucial step that forces the packet out of this interface.
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name)) < 0) {
        perror("setsockopt(SO_BINDTODEVICE) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 3. We are providing our own IP header, so we must tell the kernel.
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 4. Construct the packet (IP header + UDP header + payload)
    char datagram[4096];
    memset(datagram, 0, 4096);

    strcpy(datagram, payload_str);
    // 5. Set up the destination address structure
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DEST_PORT);
    sin.sin_addr.s_addr = inet_addr(DEST_IP);

    // 6. Send the packet!
    printf("Sending payload \"%s\" out of interface %s...\n", payload_str, iface_name);
    if (sendto(sockfd, datagram, strlen(payload_str), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() failed");
    } else {
        printf("Packet sent successfully!\n");
    }

    close(sockfd);
    return 0;
}
