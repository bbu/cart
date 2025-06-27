#include "hook.h"
#include "sandbox.h"
#include "common.h"
#include "assert.h"

#include "timer.h"

#include "include/cart.h"

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

static_assert(sizeof(struct cart_timer_add_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static_assert(sizeof(struct cart_timer_set_cb_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static_assert(sizeof(struct cart_timer_set_repeat_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static_assert(sizeof(struct cart_timer_set_interval_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static_assert(sizeof(struct cart_timer_pause_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static_assert(sizeof(struct cart_timer_resume_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static_assert(sizeof(struct cart_timer_del_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

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

static void (*const hooks[])(void *const) = {
    hook_timer_new,
    hook_timer_add,
    hook_timer_set_cb,
    hook_timer_set_repeat,
    hook_timer_set_interval,
    hook_timer_pause,
    hook_timer_resume,
    hook_timer_del,
};

static_assert(countof(hooks) == ID_COUNT, "Hooks are mismatched");

void hook_execute(const uint64_t id, void *const data)
{
    if (likely(id < ID_COUNT)) {
        hooks[id](data);
    } else {
        log_error("Cannot execute hook number %" PRIu64, id);
    }
}
