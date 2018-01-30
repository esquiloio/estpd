/*
 * Esquilo Secure Tunneling Protocol Daemon (ESTP)
 * 
 * Copyright 2014-2018 Esquilo Corporation - https://esquilo.io/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
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


