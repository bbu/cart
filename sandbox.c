#include "sandbox.h"
#include "common.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <stdatomic.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>

static struct {
    const char *appname;
    int ctlpipe_wfd;
    struct sandbox_shmem_header *shmem;
} sandbox = {
    .appname = NULL,
    .ctlpipe_wfd = -1,
    .shmem = NULL,
};

static int get_monotonic_time(uint64_t *const value)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        log_errno("Cannot get monotonic time");
        return -1;
    }

    *value = (uint64_t) ts.tv_sec * (uint64_t) 1000000000 + (uint64_t) ts.tv_nsec;
    return 0;
}

struct sandbox_shmem_header *sandbox_shmem_init(void)
{
    struct sandbox_shmem_header *const shmem = mmap(NULL, SANDBOX_SHMEM_SIZE,
        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (unlikely(shmem == MAP_FAILED)) {
        log_errno("Cannot map shared memory region");
        goto fail;
    }

    pthread_mutexattr_t mutex_attr;

    if (unlikely(pthread_mutexattr_init(&mutex_attr))) {
        log_errno("Cannot init mutex attributes");
        goto fail_unmap;
    }

    if (unlikely(pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED))) {
        log_errno("Cannot set process-shared mutex attribute");
        goto fail_destroy_mutex_attr;
    }

    if (unlikely(pthread_mutex_init(&shmem->lock, &mutex_attr))) {
        log_errno("Cannot init mutex");
        goto fail_destroy_mutex_attr;
    }

    pthread_condattr_t cond_attr;

    if (unlikely(pthread_condattr_init(&cond_attr))) {
        log_errno("Cannot init condition variable attributes");
        goto fail_destroy_mutex;
    }

    if (unlikely(pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED))) {
        log_errno("Cannot set process-shared condition variable attribute");
        goto fail_destroy_cond_attr;
    }

    if (unlikely(pthread_cond_init(&shmem->cond, &cond_attr))) {
        log_errno("Cannot init condition variable");
        goto fail_destroy_cond_attr;
    }

    shmem->ctl = SANDBOX_CTL_CLEAR;
    shmem->msg = SANDBOX_MSG_CLEAR;
    shmem->state = SANDBOX_STATE_INIT;
    shmem->do_quit = false;
    atomic_thread_fence(memory_order_seq_cst);

    if (unlikely(pthread_mutexattr_destroy(&mutex_attr))) {
        log_errno("Cannot destroy mutex attributes");
    }

    if (unlikely(pthread_condattr_destroy(&cond_attr))) {
        log_errno("Cannot destroy condition variable attributes");
    }

    return shmem;

fail_destroy_cond_attr:
    if (unlikely(pthread_condattr_destroy(&cond_attr))) {
        log_errno("Cannot destroy condition variable attributes");
    }
fail_destroy_mutex:
    if (unlikely(pthread_mutex_destroy(&shmem->lock))) {
        log_errno("Cannot destroy mutex");
    }
fail_destroy_mutex_attr:
    if (unlikely(pthread_mutexattr_destroy(&mutex_attr))) {
        log_errno("Cannot destroy mutex attributes");
    }
fail_unmap:
    if (unlikely(munmap(shmem, SANDBOX_SHMEM_SIZE))) {
        log_errno("Cannot destroy shared memory region");
    }
fail:
    return NULL;
}

void sandbox_shmem_destroy(struct sandbox_shmem_header *const shmem)
{
    if (unlikely(pthread_mutex_destroy(&shmem->lock))) {
        log_errno("Cannot destroy mutex");
    }

    if (unlikely(pthread_cond_destroy(&shmem->cond))) {
        log_errno("Cannot destroy condition variable");
    }

    if (unlikely(munmap(shmem, SANDBOX_SHMEM_SIZE))) {
        log_errno("Cannot unmap shared memory region");
    }
}

int sandbox_notify_quit(struct sandbox_shmem_header *const shmem)
{
    if (unlikely(pthread_mutex_lock(&shmem->lock))) {
        log_errno("Cannot lock shared memory mutex");
        return -1;
    }

    shmem->do_quit = true;

    if (unlikely(pthread_cond_signal(&shmem->cond))) {
        log_errno("Cannot signal condition variable");
    }

    if (unlikely(pthread_mutex_unlock(&shmem->lock))) {
        log_errno("Cannot unlock shared memory mutex");
    }

    return 0;
}

void sandbox_init(const char *const appname, const int ctlpipe_wfd, struct sandbox_shmem_header *const shmem)
{
    sandbox.appname = appname;
    sandbox.ctlpipe_wfd = ctlpipe_wfd;
    sandbox.shmem = shmem;
}

static inline void lock_or_abort(pthread_mutex_t *const mutex)
{
    if (unlikely(pthread_mutex_lock(mutex))) {
        log_errno("Cannot lock shared mutex in sandbox");
        abort();
    }
}

static inline void unlock_or_abort(pthread_mutex_t *const mutex)
{
    if (unlikely(pthread_mutex_unlock(mutex))) {
        log_errno("Cannot unlock shared mutex in sandbox");
        abort();
    }
}

static inline void wait_or_abort(pthread_cond_t *const cond, pthread_mutex_t *const mutex)
{
    if (unlikely(pthread_cond_wait(cond, mutex))) {
        log_errno("Cannot wait on shared condition variable in sandbox");
        abort();
    }
}

static inline void signal_supervisor(void)
{
    const ssize_t written = write(sandbox.ctlpipe_wfd, &(const char) {'-'}, 1);

    if (unlikely(written == -1)) {
        log_errno("Cannot signal supervisor from sandbox");
    } else if (unlikely(written != 1)) {
        log_warn("Cannot signal supervisor from sandbox, wrote %zd bytes", written);
    }
}

static inline void signal_and_wait(void)
{
    signal_supervisor();

    do {
        wait_or_abort(&sandbox.shmem->cond, &sandbox.shmem->lock);
    } while (sandbox.shmem->msg != SANDBOX_MSG_CLEAR);
}

const void *sandbox_call_supervisor(const size_t ret_size, const uint64_t call_id, const void *const args, const size_t args_size)
{
    static uint8_t ret[16] __attribute__((aligned(16)));

    lock_or_abort(&sandbox.shmem->lock);
    sandbox.shmem->msg = SANDBOX_MSG_CALL;
    *(uint64_t *) sandbox.shmem->data = call_id;

    if (args_size) {
        memcpy(sandbox.shmem->data + 16, args, args_size);
    }

    signal_and_wait();

    if (ret_size) {
        memcpy(ret, sandbox.shmem->data + 16, ret_size);
    }

    unlock_or_abort(&sandbox.shmem->lock);
    return ret;
}

void cart_log(const char *const fmt, ...)
{
    va_list vargs;
    va_start(vargs, fmt);
    lock_or_abort(&sandbox.shmem->lock);
    sandbox.shmem->msg = SANDBOX_MSG_LOG;
    const ssize_t maxlen = SANDBOX_SHMEM_DATA_SIZE;
    const int nbytes = vsnprintf((char *) sandbox.shmem->data, maxlen, fmt, vargs);

    if (unlikely(nbytes < 0)) {
        *sandbox.shmem->data = '\0';
        log_errno("Cannot format log message");
    } else if (unlikely(nbytes >= maxlen)) {
        log_warn("Truncated log message from %d to %zd bytes", nbytes + 1, maxlen);
    }

    signal_and_wait();
    unlock_or_abort(&sandbox.shmem->lock);
    va_end(vargs);
}

void sandbox_loop(void)
{
    char app_sopath[256];
    sprintf(app_sopath, "./apps/app-%s.so", sandbox.appname);
    void *const dl_handle = dlopen(app_sopath, RTLD_NOW);

    if (dl_handle == NULL) {
        log_warn("Cannot load application: %s", dlerror());
        return;
    }

    const char *const *const app_id = dlsym(dl_handle, "cart_app_id");
    const int *const app_major = dlsym(dl_handle, "cart_app_major");
    const int *const app_minor = dlsym(dl_handle, "cart_app_minor");

    if (likely(app_id && app_major && app_minor)) {
        log_info("Started %s %d.%d", *app_id, *app_major, *app_minor);
    } else {
        log_warn("No application ID and version found");
        goto unload;
    }

    bool (*const loadfn)(void) = (bool (*)(void)) dlsym(dl_handle, "cart_load");

    if (unlikely(!loadfn)) {
        log_warn("No load function found: %s", dlerror());
        goto unload;
    } else if (unlikely(!loadfn())) {
        log_warn("Load function indicated error");
        goto unload;
    }

    for (;;) {
        lock_or_abort(&sandbox.shmem->lock);
        signal_supervisor();
        sandbox.shmem->state = SANDBOX_STATE_IDLE;

        while (sandbox.shmem->ctl != SANDBOX_CTL_EXEC && !sandbox.shmem->do_quit) {
            wait_or_abort(&sandbox.shmem->cond, &sandbox.shmem->lock);
        }

        void (*const callback)(void) = sandbox.shmem->do_quit ? NULL :
            *(void (**const)(void)) sandbox.shmem->data;

        sandbox.shmem->ctl = SANDBOX_CTL_CLEAR;
        sandbox.shmem->state = SANDBOX_STATE_EXEC;
        unlock_or_abort(&sandbox.shmem->lock);

        if (likely(callback)) {
            callback();
        } else {
            break;
        }
    }

unload:
    if (dlclose(dl_handle)) {
        log_error("Cannot close dylib: %s", dlerror());
    }
}
