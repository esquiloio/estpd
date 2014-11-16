#pragma once

#include <stdint.h>
#include <time.h>

#include "estp.h"
#include "inet.h"
#include "queue.h"

#define AGEING_CHECK_PERIOD     10

typedef struct estp_session_s {
    estp_sid_t      sid;
    sockaddr_t      peer_addr;
    in_addr_t       client_addr;
    cipher_t*       client_cipher;
    cipher_t*       server_cipher;
    uint8_t         cipher_type;

    uint32_t        tx_packets;
    uint32_t        rx_packets;
    uint32_t        idle_rx_time;
    uint32_t        last_rx_packets;

    bool            free_flag;
    int32_t         ref_count;

    TAILQ_ENTRY(estp_session_s) entry;
} estp_session_t;

estp_session_t*
estp_session_get(estp_sid_t sid);

estp_session_t*
estp_session_find(in_addr_t client_addr);

estp_session_t*
estp_session_alloc(uint8_t cipher_type, cipher_keys_t* client_keys, cipher_keys_t* server_keys);

void
estp_session_free(estp_session_t* session);

void
estp_session_unref(estp_session_t* session);

bool
estp_session_init(uint32_t num_sessions, in_addr_t server_addr, in_addr_t netmask);

