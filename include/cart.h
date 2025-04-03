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

void cart_log(const char *const fmt, ...) __attribute__((format(printf, 1, 2)));

#define CART_TIMER_REPEAT ((cart_timer_repeat_t) 0)
#define CART_TIMER_ONESHOT ((cart_timer_repeat_t) 1)

cart_timer_t cart_timer_new(void);
cart_timer_t cart_timer_create(const cart_cb_t cb, const cart_timer_repeat_t repeat, const bool run, const cart_timer_interval_t interval);
bool cart_timer_set_cb(const cart_timer_t tm, const cart_cb_t cb);
bool cart_timer_set_repeat(const cart_timer_t tm, const cart_timer_repeat_t repeat);
bool cart_timer_set_interval(const cart_timer_t tm, const cart_timer_interval_t interval);
bool cart_timer_pause(const cart_timer_t tm);
bool cart_timer_unpause(const cart_timer_t tm);
bool cart_timer_del(const cart_timer_t tm);
