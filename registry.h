#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "inet.h"

bool
estp_registry_init();

void
estp_registry_shutdown();

bool
estp_registry_add(in_addr_t client_address, const char* name);

bool
estp_registry_del(in_addr_t client_address);

bool
estp_registry_peer(in_addr_t client_address, in_addr_t peer_address);
