#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  dscp_ecn;
    uint16_t length;
    uint16_t ident;
    uint16_t frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t chksum;
    uint32_t src;
    uint32_t dest;
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t chksum;
} udp_header_t;

typedef union {
    struct sockaddr_storage ss;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
} sockaddr_t;

int
sock_timeout(int sockfd, uint32_t milliseconds);

int
ifconfig(int fd, const char* dev, in_addr_t addr, in_addr_t netmask, uint16_t mtu);

int
dgram_socket(int port);

int
listen_socket(int port);

