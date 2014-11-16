#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "inet.h"

bool
estp_registry_add(in_addr_t address, const char* name);

