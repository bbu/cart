#pragma once

#include <stddef.h>
#include <stdbool.h>

#include "include/cart.h"

typedef cart_timer_t timer_t;
typedef cart_timer_repeat_t timer_repeat_t;
typedef cart_timer_interval_t timer_interval_t;
typedef cart_timer_unit_t timer_unit_t;
typedef cart_cb_t timer_cb_t;

#define TIMER_UNIT_SEC CART_TIMER_UNIT_SEC
#define TIMER_UNIT_USEC CART_TIMER_UNIT_USEC
#define TIMER_UNIT_NSEC CART_TIMER_UNIT_NSEC

void timer_accept_timeout(size_t);
timer_cb_t timer_get_cb(size_t);
void timer_delete_all(void);

timer_t timer_new(void);
timer_t timer_add(timer_cb_t, timer_repeat_t, bool, timer_interval_t, timer_unit_t, bool);
bool timer_set_cb(timer_t, timer_cb_t);
bool timer_set_repeat(timer_t, timer_repeat_t);
bool timer_set_interval(timer_t, timer_interval_t, timer_unit_t);
bool timer_pause(timer_t);
bool timer_resume(timer_t);
bool timer_del(timer_t);
