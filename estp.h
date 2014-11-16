#pragma once

#include <stdint.h>

#include "cipher.h"
#include "inet.h"

#define ESTP_DEFAULT_PORT       1190

#define ESTP_VERSION            0x10 // 1.0

#define ESTP_MTU_MAX            1408

#define ESTP_MTU_MIN            576

#define ESTP_TRANSPORT_OVERHEAD (sizeof(ip_header_t) + sizeof(udp_header_t))

#define ESTP_TUNNEL_OVERHEAD    (sizeof(estp_header_t) + CIPHER_MAX_IV_LEN + CIPHER_MAX_HASH_LEN)

typedef uint32_t estp_sid_t;

//
// ESTP Header
//
typedef struct estp_header_s {
#define ESTP_TYPE_CLIENT_HELLO  0
#define ESTP_TYPE_SERVER_HELLO  1
#define ESTP_TYPE_DATA          2
#define ESTP_TYPE_KEEPALIVE     3
#define ESTP_TYPE_CLOSE         4
#define ESTP_TYPE_MAX           5 // Keep last!!!
    uint8_t     type;
    uint8_t     version;
    uint16_t    length;
    estp_sid_t  sid;
} estp_header_t;

//
// ESTP Packet
//
typedef struct estp_packet_s {
    estp_header_t   header;
    union {
        // ESTP_TYPE_CLIENT_HELLO
        struct client_hello_s {
            uint8_t         cipher_type;
            cipher_keys_t   cipher_keys;
        } client_hello;

        // ESTP_TYPE_SERVER_HELLO
        struct server_hello_s {
            uint32_t        client_ip;
            uint32_t        server_ip;
            uint32_t        netmask;
            uint16_t        mtu;
            uint8_t         cipher_type;
            cipher_keys_t   cipher_keys;
        } server_hello;

        // ESTP_TYPE_DATA
        struct {
            uint8_t         data[ESTP_MTU_MAX];
            uint8_t         iv[CIPHER_MAX_IV_LEN];
            uint8_t         mac[CIPHER_MAX_HASH_LEN];
        };
    };
} estp_packet_t;


