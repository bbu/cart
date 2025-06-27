#pragma once

#include <stdint.h>

/* Called in the supervisor */
void hook_execute(const uint64_t id, void *const data);
