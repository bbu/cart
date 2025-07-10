#include "timer.h"
#include "supervisor.h"
#include "common.h"

#define HANDLE_NULL       ((timer_t) 0x0000000000000000ull)
#define HANDLE_MAGIC_MASK ((timer_t) 0xFF00000000000000ull)
#define HANDLE_MAGIC_BITS ((timer_t) 0xAA00000000000000ull)

static inline bool handle_check_magic(const timer_t tm)
{
    return (tm & HANDLE_MAGIC_MASK) != HANDLE_MAGIC_BITS;
}

static inline size_t handle_remove_magic(const timer_t tm)
{
    return (size_t) (tm ^ HANDLE_MAGIC_BITS);
}

static inline timer_t handle_put_magic(const size_t idx)
{
    return (timer_t) idx | HANDLE_MAGIC_BITS;
}

#define MAX_TIMERS ((size_t) 4096)

static struct {
    bool in_use;
    timer_cb_t cb;
    timer_repeat_t repeat_max, repeat_count;
    timer_interval_t interval;
    timer_unit_t unit;
    bool running, autodel;
} timers[MAX_TIMERS] = {0};

void timer_accept_timeout(const size_t timer_idx)
{
    if (unlikely(!timers[timer_idx].running)) {
        return;
    }

    const timer_repeat_t repeat_count = ++timers[timer_idx].repeat_count;
    const timer_repeat_t repeat_max = timers[timer_idx].repeat_max;

    if (repeat_max && repeat_count >= repeat_max) {
        timers[timer_idx].running = false;

        if (timers[timer_idx].autodel && likely(!supervisor_del_timer(timer_idx))) {
            memset(timers + timer_idx, 0, sizeof(timers[timer_idx]));
        } else if (!timers[timer_idx].autodel) {
            supervisor_disable_timer(timer_idx);
        }
    }
}

timer_cb_t timer_get_cb(const size_t timer_idx)
{
    return timers[timer_idx].cb;
}

void timer_delete_all(void)
{
    for (size_t idx = 0; idx < MAX_TIMERS; ++idx) {
        if (timers[idx].in_use) {
            supervisor_del_timer(idx);
            memset(timers + idx, 0, sizeof(timers[idx]));
        }
    }
}

static inline size_t find_free_timer(void)
{
    static size_t last_allocated_idx = MAX_TIMERS;

    for (size_t idx = last_allocated_idx; idx < MAX_TIMERS; ++idx) {
        if (!timers[idx].in_use) {
            last_allocated_idx = idx;
            return idx;
        }
    }

    for (size_t idx = 0; idx < last_allocated_idx; ++idx) {
        if (!timers[idx].in_use) {
            last_allocated_idx = idx;
            return idx;
        }
    }

    return MAX_TIMERS;
}

static inline size_t check_handle(const timer_t tm)
{
    if (unlikely(tm == HANDLE_NULL)) {
        log_warn("Timer handle is null");
        return MAX_TIMERS;
    }

    if (unlikely(handle_check_magic(tm))) {
        log_warn("Timer handle invalid: %016llX does not have initial 'AA' bits", tm);
        return MAX_TIMERS;
    }

    const size_t idx = handle_remove_magic(tm);

    if (unlikely(idx >= MAX_TIMERS)) {
        log_warn("Timer handle out of bounds (%zu): %016llX", MAX_TIMERS, tm);
        return MAX_TIMERS;
    }

    if (unlikely(!timers[idx].in_use)) {
        log_warn("Timer handle deallocated: %016llX", tm);
        return MAX_TIMERS;
    }

    return idx;
}

timer_t timer_new(void)
{
    const size_t free_idx = find_free_timer();

    if (unlikely(free_idx == MAX_TIMERS)) {
        log_warn("Timer limit of %zu exceeded", MAX_TIMERS);
        return HANDLE_NULL;
    }

    if (unlikely(supervisor_add_timer(free_idx, false, 1, TIMER_UNIT_SEC))) {
        return HANDLE_NULL;
    }

    timers[free_idx].in_use = true;
    timers[free_idx].cb = NULL;
    timers[free_idx].repeat_max = 0;
    timers[free_idx].repeat_count = 0;
    timers[free_idx].interval = 1;
    timers[free_idx].unit = TIMER_UNIT_SEC;
    timers[free_idx].running = false;
    timers[free_idx].autodel = false;

    return handle_put_magic(free_idx);
}

timer_t timer_add(const timer_cb_t cb, const timer_repeat_t repeat, const bool run, const timer_interval_t interval, const timer_unit_t unit, const bool autodel)
{
    const size_t free_idx = find_free_timer();

    if (unlikely(free_idx == MAX_TIMERS)) {
        log_warn("Timer limit of %zu exceeded", MAX_TIMERS);
        return HANDLE_NULL;
    }

    if (unlikely(supervisor_add_timer(free_idx, run, interval, unit))) {
        return HANDLE_NULL;
    }

    timers[free_idx].in_use = true;
    timers[free_idx].cb = cb;
    timers[free_idx].repeat_max = repeat;
    timers[free_idx].repeat_count = 0;
    timers[free_idx].interval = interval;
    timers[free_idx].unit = unit;
    timers[free_idx].running = run;
    timers[free_idx].autodel = autodel;

    return handle_put_magic(free_idx);
}

bool timer_set_cb(const timer_t tm, const timer_cb_t cb)
{
    const size_t idx = check_handle(tm);

    if (unlikely(idx == MAX_TIMERS)) {
        return false;
    }

    timers[idx].cb = cb;
    return true;
}

bool timer_set_repeat(const timer_t tm, const timer_repeat_t repeat)
{
    const size_t idx = check_handle(tm);

    if (unlikely(idx == MAX_TIMERS)) {
        return false;
    }

    timers[idx].repeat_count = 0;
    timers[idx].repeat_max = repeat;
    return true;
}

bool timer_set_interval(const timer_t tm, const timer_interval_t interval, const timer_unit_t unit)
{
    const size_t idx = check_handle(tm);

    if (unlikely(idx == MAX_TIMERS || supervisor_enable_timer(idx, interval, unit))) {
        return false;
    }

    timers[idx].interval = interval;
    timers[idx].unit = unit;
    timers[idx].running = true;
    return true;
}

bool timer_pause(const timer_t tm)
{
    const size_t idx = check_handle(tm);

    if (unlikely(idx == MAX_TIMERS || supervisor_disable_timer(idx))) {
        return false;
    }

    timers[idx].running = false;
    return true;
}

bool timer_resume(const timer_t tm)
{
    const size_t idx = check_handle(tm);

    if (unlikely(idx == MAX_TIMERS || supervisor_enable_timer(idx, timers[idx].interval, timers[idx].unit))) {
        return false;
    }

    timers[idx].running = true;
    return true;
}

bool timer_del(const timer_t tm)
{
    const size_t idx = check_handle(tm);

    if (unlikely(idx == MAX_TIMERS || supervisor_del_timer(idx))) {
        return false;
    }

    memset(timers + idx, 0, sizeof(timers[idx]));
    return true;
}
