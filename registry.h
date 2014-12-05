#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "inet.h"

bool
estp_registry_init();

void
estp_registry_shutdown();

bool
estp_registry_add(in_addr_t address, const char* name);

bool
estp_registry_del(in_addr_t address);

