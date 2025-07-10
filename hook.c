#include "hook.h"
#include "sandbox.h"
#include "common.h"
#include "assert.h"

#include "timer.h"
#include "chan.h"

#include "include/cart.h"

#include <stdint.h>
#include <inttypes.h>

enum {
    ID_TIMER_NEW,
    ID_TIMER_ADD,
    ID_TIMER_SET_CB,
    ID_TIMER_SET_REPEAT,
    ID_TIMER_SET_INTERVAL,
    ID_TIMER_PAUSE,
    ID_TIMER_RESUME,
    ID_TIMER_DEL,

    ID_CHAN_NEW,
    ID_CHAN_DEL,

    ID_COUNT
};

/*****************************************************************************/

cart_timer_t cart_timer_new(void)
{
    return *(const cart_timer_t *) sandbox_call_supervisor(sizeof(cart_timer_t), ID_TIMER_NEW, NULL, 0);
}

static void hook_timer_new(void *const data)
{
    *((cart_timer_t *) data) = timer_new();
}

/*****************************************************************************/

struct cart_timer_add_args {
    const cart_cb_t cb;
    const cart_timer_repeat_t repeat;
    const bool run;
    const cart_timer_interval_t interval;
    const cart_timer_unit_t unit;
    const bool autodel;
};

cart_timer_t cart_timer_add(const cart_cb_t cb, const cart_timer_repeat_t repeat, const bool run,
    const cart_timer_interval_t interval, const cart_timer_unit_t unit, const bool autodel)
{
    return *(const cart_timer_t *) sandbox_call_supervisor(sizeof(cart_timer_t), ID_TIMER_ADD,
        &(const struct cart_timer_add_args) { cb, repeat, run, interval, unit, autodel },
        sizeof(struct cart_timer_add_args));
}

static void hook_timer_add(void *const data)
{
    const struct cart_timer_add_args *args = data;
    const cart_timer_t handle = timer_add(args->cb, args->repeat, args->run, args->interval, args->unit, args->autodel);
    *((cart_timer_t *) data) = handle;
}

/*****************************************************************************/

struct cart_timer_set_cb_args {
    const cart_timer_t tm;
    const cart_cb_t cb;
};

bool cart_timer_set_cb(const cart_timer_t tm, const cart_cb_t cb)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_TIMER_SET_CB,
        &(const struct cart_timer_set_cb_args) { tm, cb },
        sizeof(struct cart_timer_set_cb_args));
}

static void hook_timer_set_cb(void *const data)
{
    const struct cart_timer_set_cb_args *args = data;
    const bool done = timer_set_cb(args->tm, args->cb);
    *((bool *) data) = done;
}

/*****************************************************************************/

struct cart_timer_set_repeat_args {
    const cart_timer_t tm;
    const cart_timer_repeat_t repeat;
};

bool cart_timer_set_repeat(const cart_timer_t tm, const cart_timer_repeat_t repeat)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_TIMER_SET_REPEAT,
        &(const struct cart_timer_set_repeat_args) { tm, repeat },
        sizeof(struct cart_timer_set_repeat_args));
}

static void hook_timer_set_repeat(void *const data)
{
    const struct cart_timer_set_repeat_args *args = data;
    const bool done = timer_set_repeat(args->tm, args->repeat);
    *((bool *) data) = done;
}

/*****************************************************************************/

struct cart_timer_set_interval_args {
    const cart_timer_t tm;
    const cart_timer_interval_t interval;
    const cart_timer_unit_t unit;
};

bool cart_timer_set_interval(const cart_timer_t tm, const cart_timer_interval_t interval, const cart_timer_unit_t unit)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_TIMER_SET_INTERVAL,
        &(const struct cart_timer_set_interval_args) { tm, interval, unit },
        sizeof(struct cart_timer_set_interval_args));
}

static void hook_timer_set_interval(void *const data)
{
    const struct cart_timer_set_interval_args *args = data;
    const bool done = timer_set_interval(args->tm, args->interval, args->unit);
    *((bool *) data) = done;
}

/*****************************************************************************/

struct cart_timer_pause_args {
    const cart_timer_t tm;
};

bool cart_timer_pause(const cart_timer_t tm)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_TIMER_PAUSE,
        &(const struct cart_timer_pause_args) { tm },
        sizeof(struct cart_timer_pause_args));
}

static void hook_timer_pause(void *const data)
{
    const struct cart_timer_pause_args *args = data;
    const bool done = timer_pause(args->tm);
    *((bool *) data) = done;
}

/*****************************************************************************/

struct cart_timer_resume_args {
    const cart_timer_t tm;
};

bool cart_timer_resume(const cart_timer_t tm)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_TIMER_RESUME,
        &(const struct cart_timer_resume_args) { tm },
        sizeof(struct cart_timer_resume_args));
}

static void hook_timer_resume(void *const data)
{
    const struct cart_timer_resume_args *args = data;
    const bool done = timer_resume(args->tm);
    *((bool *) data) = done;
}

/*****************************************************************************/

struct cart_timer_del_args {
    const cart_timer_t tm;
};

bool cart_timer_del(const cart_timer_t tm)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_TIMER_DEL,
        &(const struct cart_timer_del_args) { tm },
        sizeof(struct cart_timer_del_args));
}

static void hook_timer_del(void *const data)
{
    const struct cart_timer_del_args *args = data;
    const bool done = timer_del(args->tm);
    *((bool *) data) = done;
}

/*****************************************************************************/

cart_chan_t cart_chan_new(void)
{
    return *(const cart_chan_t *) sandbox_call_supervisor(sizeof(cart_chan_t), ID_CHAN_NEW, NULL, 0);
}

static void hook_chan_new(void *const data)
{
    *((cart_chan_t *) data) = chan_new();
}

/*****************************************************************************/

struct cart_chan_del_args {
    const cart_chan_t ch;
};

bool cart_chan_del(const cart_chan_t ch)
{
    return *(const bool *) sandbox_call_supervisor(sizeof(bool), ID_CHAN_DEL,
        &(const struct cart_chan_del_args) { ch },
        sizeof(struct cart_chan_del_args));
}

static void hook_chan_del(void *const data)
{
    const struct cart_chan_del_args *args = data;
    const bool done = chan_del(args->ch);
    *((bool *) data) = done;
}

/*****************************************************************************/

static void (*const hooks[])(void *const) = {
    hook_timer_new,
    hook_timer_add,
    hook_timer_set_cb,
    hook_timer_set_repeat,
    hook_timer_set_interval,
    hook_timer_pause,
    hook_timer_resume,
    hook_timer_del,

    hook_chan_new,
    hook_chan_del,
};

static_assert(countof(hooks) == ID_COUNT, "Hooks are mismatched");

void hook_execute(void *const data)
{
    const uint64_t call_id = *(const uint64_t *) data;

    if (likely(call_id < ID_COUNT)) {
        hooks[call_id]((uint8_t *) data + 16);
    } else {
        log_error("Cannot execute hook number %" PRIu64, call_id);
    }
}
