#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "include/cart.h"

typedef cart_chan_t chan_t;

chan_t chan_new(void);
bool chan_del(chan_t);
