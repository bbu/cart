#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>

#define SANDBOX_SHMEM_SIZE ((size_t) 4096)
#define SANDBOX_SHMEM_DATA_SIZE (SANDBOX_SHMEM_SIZE - offsetof(struct sandbox_shmem_header, data))

enum {
    SANDBOX_MSG_CLEAR = 0, /* Set by supervisor */
    SANDBOX_MSG_LOG,
    SANDBOX_MSG_TIMER_NEW,
    SANDBOX_MSG_TIMER_CREATE,
};

typedef uint8_t sandbox_msg_t;

enum {
    SANDBOX_CTL_CLEAR = 0, /* Set by sandbox */
    SANDBOX_CTL_EXEC,
};

typedef uint8_t sandbox_ctl_t;

enum {
    SANDBOX_STATE_INIT = 0,
    SANDBOX_STATE_WAITING,
    SANDBOX_STATE_EXECUTING,
};

typedef uint8_t sandbox_state_t;

struct sandbox_shmem_header {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    sandbox_ctl_t ctl;
    sandbox_msg_t msg;
    sandbox_state_t state;
    bool do_quit;
    uint8_t data[] __attribute__((aligned(16)));
};

/* Called only from the parent process of the supervisor */
struct sandbox_shmem_header *sandbox_shmem_init(void);
void sandbox_shmem_destroy(struct sandbox_shmem_header *const shmem);
int sandbox_notify_quit(struct sandbox_shmem_header *const shmem);

/* Called only in the sandbox child process */
void sandbox_init(const char *const appname, const int ctlpipe_wfd, struct sandbox_shmem_header *const shmem);
void sandbox_loop(void);

#include "include/cart.h"

struct cart_timer_create_args {
    const cart_cb_t cb;
    const cart_timer_repeat_t repeat;
    const uint8_t run;
    const cart_timer_interval_t interval;
};

static_assert(sizeof(struct cart_timer_create_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");

struct cart_timer_set_cb_args {
    const cart_timer_t tm;
    const cart_cb_t cb;
};

static_assert(sizeof(struct cart_timer_set_cb_args) <= SANDBOX_SHMEM_DATA_SIZE, "Args cannot fit in shared region");
