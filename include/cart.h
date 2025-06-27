#pragma once

#include <stdbool.h>
#include <stdint.h>

#define cart_app(id, major, minor) \
    const char *const cart_app_id = (id); \
    const int cart_app_major = (major); \
    const int cart_app_minor = (minor) \

#define cart_load extern bool cart_load(void)
#define cart_cb(name) static void (name)(void)

#define cart_null ((uint64_t) 0)

typedef void (*cart_cb_t)(void);
typedef uint64_t cart_timer_t, cart_chan_t, cart_store_t;
typedef uint64_t cart_timer_interval_t;
typedef uint64_t cart_timer_repeat_t;
typedef uint8_t cart_timer_unit_t;

enum {
    CART_TIMER_UNIT_SEC = 0,
    CART_TIMER_UNIT_USEC,
    CART_TIMER_UNIT_NSEC,
};

void cart_log(const char *const fmt, ...) __attribute__((format(printf, 1, 2)));

#define CART_TIMER_REPEAT_INF ((cart_timer_repeat_t) 0)

cart_timer_t cart_timer_new(void);
cart_timer_t cart_timer_add(cart_cb_t cb, cart_timer_repeat_t repeat, bool run, cart_timer_interval_t interval, cart_timer_unit_t unit, bool autodel);
bool cart_timer_set_cb(cart_timer_t tm, cart_cb_t cb);
bool cart_timer_set_repeat(cart_timer_t tm, cart_timer_repeat_t repeat);
bool cart_timer_set_interval(cart_timer_t tm, cart_timer_interval_t interval, cart_timer_unit_t unit);
bool cart_timer_pause(cart_timer_t tm);
bool cart_timer_resume(cart_timer_t tm);
bool cart_timer_del(cart_timer_t tm);
