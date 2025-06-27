#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define SANDBOX_SHMEM_SIZE ((size_t) 4096)
#define SANDBOX_SHMEM_DATA_SIZE (SANDBOX_SHMEM_SIZE - offsetof(struct sandbox_shmem_header, data))

enum {
    SANDBOX_MSG_CLEAR = 0, /* Set by supervisor */
    SANDBOX_MSG_LOG,
    SANDBOX_MSG_CALL,
};

typedef uint8_t sandbox_msg_t;

enum {
    SANDBOX_CTL_CLEAR = 0, /* Set by sandbox */
    SANDBOX_CTL_EXEC,
};

typedef uint8_t sandbox_ctl_t;

enum {
    SANDBOX_STATE_INIT = 0,
    SANDBOX_STATE_IDLE,
    SANDBOX_STATE_EXEC,
};

typedef uint8_t sandbox_state_t;

struct sandbox_shmem_header {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    sandbox_ctl_t ctl;
    sandbox_msg_t msg;
    uint64_t msg_data;
    sandbox_state_t state;
    bool do_quit;
    uint8_t data[] __attribute__((aligned(16)));
};

/* Called only from the parent process of the supervisor */
struct sandbox_shmem_header *sandbox_shmem_init(void);
void sandbox_shmem_destroy(struct sandbox_shmem_header *);
int sandbox_notify_quit(struct sandbox_shmem_header *);

/* Called only in the sandbox child process */
void sandbox_init(const char *appname, int ctlpipe_wfd, struct sandbox_shmem_header *);
void sandbox_loop(void);
const void *sandbox_call_supervisor(size_t ret_size, uint64_t data, const void *args, size_t args_size);
