#include "common.h"
#include "sandbox.h"
#include "supervisor.h"
#include "timer.h"
#include "hook.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>

#define CONTROL_SOCKET_NAME "/tmp/cartctl.sock"
#define CONTROL_SOCKET_BACKLOG 5

#define kevent_ctl_many(kqfd, changes, nchanges) \
    kevent(kqfd, changes, nchanges, NULL, 0, NULL)

#define kevent_ctl(kqfd, filt, id, fl, ffl, d, u) \
    kevent(kqfd, (&(const struct kevent) { \
        .filter = (filt), \
        .ident = (id), \
        .flags = (fl), \
        .fflags = (ffl), \
        .data = (d), \
        .udata = (u), \
    }), 1, NULL, 0, NULL)

#define kevent_wait(kqfd, events, nevents) \
    kevent(kqfd, NULL, 0, events, nevents, NULL)

static struct {
    int kqfd, ctlsockfd, ctlconnfd;
    pid_t sandbox_pid;
    int sandbox_ctlpipe_rfd, sandbox_outpipe_rfd;
    struct sandbox_shmem_header *shmem;
    bool do_quit;
} supervisor = {
    .kqfd = -1,
    .ctlsockfd = -1,
    .ctlconnfd = -1,
    .sandbox_pid = -1,
    .sandbox_ctlpipe_rfd = -1,
    .sandbox_outpipe_rfd = -1,
    .shmem = NULL,
    .do_quit = false,
};

/* needs to be a queue */
static void (*pending_callback)(void) = NULL;

static inline int set_fd_nonblock(const int fd)
{
    const int flags = fcntl(fd, F_GETFL);

    if (unlikely(flags == -1)) {
        log_errno("Cannot get descriptor flags");
        return -1;
    }

    if (unlikely(fcntl(fd, F_SETFL, flags | O_NONBLOCK))) {
        log_errno("Cannot set non-blocking descriptor flag");
        return -1;
    }

    return 0;
}

static inline int set_fd_nosigpipe(const int fd)
{
    if (unlikely(fcntl(fd, F_SETNOSIGPIPE, 1))) {
        log_errno("Cannot set nosigpipe descriptor flag");
        return -1;
    }

    return 0;
}

static void write_control_prompt(void);
static void write_control_response(const char *const fmt, ...);
static void close_control_connection(void);
static inline void execute_control_command(const char *const cmd, const char *const *const args, const size_t argc);
static inline void process_control_command(char *const buf);

static inline int spawn_sandbox(const char *const appname)
{
    int ctlpipe[2];

    if (unlikely(pipe(ctlpipe))) {
        log_errno("Cannot create control pipe pair for sandbox");
        goto fail;
    }

    supervisor.sandbox_ctlpipe_rfd = ctlpipe[0];
    const int sandbox_ctlpipe_wfd = ctlpipe[1];

    if (unlikely(set_fd_nonblock(supervisor.sandbox_ctlpipe_rfd) ||
        set_fd_nonblock(sandbox_ctlpipe_wfd) || set_fd_nosigpipe(sandbox_ctlpipe_wfd))) {

        goto fail_close_ctlpipe;
    }

    if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_READ, supervisor.sandbox_ctlpipe_rfd, EV_ADD, 0, 0, 0))) {
        log_errno("Cannot add control pipe read event");
        goto fail_close_ctlpipe;
    }

    int outpipe[2];

    if (unlikely(pipe(outpipe))) {
        log_errno("Cannot create output pipe pair for sandbox");
        goto fail_close_ctlpipe;
    }

    supervisor.sandbox_outpipe_rfd = outpipe[0];
    const int sandbox_outpipe_wfd = outpipe[1];

    if (unlikely(set_fd_nonblock(supervisor.sandbox_outpipe_rfd) || set_fd_nosigpipe(sandbox_outpipe_wfd))) {
        goto fail_close_outpipe;
    }

    if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_READ, supervisor.sandbox_outpipe_rfd, EV_ADD, 0, 0, 0))) {
        log_errno("Cannot add output pipe read event");
        goto fail_close_outpipe;
    }

    if (unlikely(!(supervisor.shmem = sandbox_shmem_init()))) {
        goto fail_close_outpipe;
    }

    if (unlikely((supervisor.sandbox_pid = fork()) < 0)) {
        log_errno("Cannot fork app sandbox");
        goto fail_destroy_shmem;
    } else if (supervisor.sandbox_pid == 0) {
        close(supervisor.kqfd);
        close(supervisor.ctlconnfd);
        close(supervisor.ctlsockfd);
        close(supervisor.sandbox_ctlpipe_rfd);
        close(supervisor.sandbox_outpipe_rfd);
        close(STDIN_FILENO);
        dup2(sandbox_outpipe_wfd, STDOUT_FILENO);
        close(sandbox_outpipe_wfd);
        close(STDERR_FILENO);
        sandbox_init(appname, sandbox_ctlpipe_wfd, supervisor.shmem);
        sandbox_loop();
        close(sandbox_ctlpipe_wfd);
        munmap(supervisor.shmem, SANDBOX_SHMEM_SIZE);
        exit(0);
    } else {
        if (unlikely(close(sandbox_ctlpipe_wfd))) {
            log_errno("Cannot close write end of pipe");
        }

        if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_PROC, supervisor.sandbox_pid,
            EV_ADD | EV_ONESHOT, NOTE_EXIT | NOTE_EXITSTATUS, 0, 0))) {

            log_errno("Cannot add process event");
        }

        log_info("Spawned sandbox with pid %d", supervisor.sandbox_pid);
    }

    return 0;

fail_destroy_shmem:
    sandbox_shmem_destroy(supervisor.shmem);
    supervisor.shmem = NULL;
fail_close_outpipe:
    close(supervisor.sandbox_outpipe_rfd);
    supervisor.sandbox_outpipe_rfd = -1;
    close(sandbox_outpipe_wfd);
fail_close_ctlpipe:
    close(supervisor.sandbox_ctlpipe_rfd);
    supervisor.sandbox_ctlpipe_rfd = -1;
    close(sandbox_ctlpipe_wfd);
fail:
    return -1;
}

static inline void execute_control_command(const char *const cmd, const char *const *const args, const size_t argc)
{
    if (argc) {
        log_info("Received control command '%s' (%zu arg%s)", cmd, argc, argc == 1 ? "" : "s");        
    } else {
        log_info("Received control command '%s'", cmd);        
    }

    for (size_t i = 0; i < argc; ++i) {
        log_info("Arg %zu: '%s'", i + 1, args[i]);
    }

    if (!strcmp(cmd, "load")) {
        if (argc != 1) {
            write_control_response("Usage: load APPNAME");
        } else if (supervisor.sandbox_pid != -1) {
            write_control_response("There is already a loaded application");
        } else if (unlikely(spawn_sandbox(args[0]))) {
            write_control_response("Cannot spawn app sandbox");
        }
    } else if (!strcmp(cmd, "term")) {
        if (argc != 0) {
            write_control_response("Usage: term");
        } else if (supervisor.sandbox_pid == -1) {
            write_control_response("No application is currently loaded");
        } else {
            sandbox_notify_quit(supervisor.shmem);

            if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 1, EV_ADD | EV_ONESHOT, NOTE_SECONDS, 1, 0))) {
                log_errno("Cannot add sandbox timeout timer");
            }
        }
    } else if (!strcmp(cmd, "stat")) {
        write_control_response("Not implemented");
    } else if (!strcmp(cmd, "exit")) {
        log_info("Closing control connection");
        write_control_response("Bye");
        close_control_connection();
    } else if (!strcmp(cmd, "shut")) {
        log_info("Requested shutdown");
        supervisor.do_quit = true;
    } else if (!strcmp(cmd, "help")) {
        write_control_response("Commands");
        write_control_response(" load APPNAME: load app");
        write_control_response(" term: notify current application to terminate");
        write_control_response(" stat: show statistics");
        write_control_response(" exit: exit control session");
        write_control_response(" shut: exit control session and terminate runtime");
        write_control_response(" help: show this help");
    } else {
        log_warn("Unknown command '%s'", cmd);
        write_control_response("Unknown command '%s'", cmd);
    }

    if (strcmp(cmd, "exit") && strcmp(cmd, "shut")) {
        write_control_prompt();
    }
}

static inline void process_control_command(char *const buf)
{
    enum {
        st_begin,
        st_name,
        st_after_name,
        st_arg,
        st_arg_quoted,
    } state = st_begin;

    const char *cmd = NULL, *arg, *args[8];
    size_t argc = 0;
    char *pch = buf, quote_char;
    bool bailout = false, too_many_args = false;

    for (char ch = *pch; ch; ch = *++pch) {
        switch (state) {
        case st_begin:
            switch (ch) {
            case 'a' ... 'z':
            case 'A' ... 'Z':
            case '_':
                cmd = pch;
                state = st_name;
                break;

            case ' ':
            case '\n':
                break;

            default:
                bailout = true;
                break;
            }
            break;

        case st_name:
            switch (ch) {
            case ' ':
            case '\n':
                *pch = '\0';
                state = st_after_name;
                break;

            case 'a' ... 'z':
            case 'A' ... 'Z':
            case '0' ... '9':
            case '-':
            case '_':
                break;

            default:
                bailout = true;
                break;
            }
            break;

        case st_after_name:
            switch (ch) {
            case ' ':
            case '\n':
                break;

            case 'a' ... 'z':
            case 'A' ... 'Z':
            case '0' ... '9':
            case '-':
            case '_':
                arg = pch;
                state = st_arg;
                break;

            case '"':
            case '\'':
                quote_char = ch;
                arg = pch + 1;
                state = st_arg_quoted;
                break;

            default:
                bailout = true;
                break;            
            }
            break;

        case st_arg:
            switch (ch) {
            case ' ':
            case '\n':
                *pch = '\0';

                if (likely(argc < countof(args))) {
                    args[argc++] = arg;
                    state = st_after_name;
                } else {
                    bailout = true;
                    too_many_args = true;
                }
                break;

            case 'a' ... 'z':
            case 'A' ... 'Z':
            case '0' ... '9':
            case '-':
            case '_':
                break;

            default:
                bailout = true;
                break;            
            }
            break;

        case st_arg_quoted:
            switch (ch) {
            case '"':
            case '\'':
                if (ch == quote_char) {
                    *pch = '\0';

                    if (likely(argc < countof(args))) {
                        args[argc++] = arg;
                        state = st_after_name;
                    } else {
                        bailout = true;
                        too_many_args = true;
                    }
                }
                break;

            case '\n':
                bailout = true;
                break;

            default:
                break;
            }
            break;
        }

        if (bailout) {
            if (too_many_args) {
                write_control_response("Too many args");
            } else if (isprint(ch)) {
                write_control_response("Unexpected character '%c' at position %td", ch, pch - buf);
            } else {
                write_control_response("Unexpected character %%%02X at position %td", ch, pch - buf);
            }

            write_control_prompt();
            log_info("Rejecting malformed command because of %s", too_many_args ? "too many args" : "lexing error");
            break;
        }

        if (ch == '\n') {
            if (!cmd) {
                write_control_response("Please enter command");
                break;
            }

            execute_control_command(cmd, args, argc);
            state = st_begin, cmd = NULL, argc = 0;
        }
    }
}

static inline int arm_filters(void)
{
    assert(supervisor.kqfd != -1);
    assert(supervisor.ctlsockfd != -1);

    const struct kevent events[] = {
        { .filter = EVFILT_SIGNAL, .ident = SIGUSR1, .flags = EV_ADD, .udata = "USR1" },
        { .filter = EVFILT_SIGNAL, .ident = SIGUSR2, .flags = EV_ADD, .udata = "USR2" },
        { .filter = EVFILT_SIGNAL, .ident = SIGINT,  .flags = EV_ADD, .udata = "INT"  },
        { .filter = EVFILT_SIGNAL, .ident = SIGTERM, .flags = EV_ADD, .udata = "TERM" },
        { .filter = EVFILT_SIGNAL, .ident = SIGQUIT, .flags = EV_ADD, .udata = "QUIT" },

        {
            .filter = EVFILT_READ,  
            .ident = supervisor.ctlsockfd,
            .flags = EV_ADD
        },

        {
            .filter = EVFILT_TIMER,
            .ident = 0,
            .flags = EV_ADD,
            .fflags = NOTE_SECONDS,
            .data = 1
        },
    };

    sigset_t sigmask;
    sigemptyset(&sigmask);
 
    for (size_t i = 0; i < countof(events) - 2; ++i) {
        sigaddset(&sigmask, events[i].ident);
    }

    if (unlikely(kevent_ctl_many(supervisor.kqfd, events, countof(events)) < 0)) {
        log_errno("Cannot add kevents");
        return -1;
    }

    if (unlikely(sigprocmask(SIG_BLOCK, &sigmask, NULL))) {
        log_errno("Cannot set signal mask");
        return -1;
    }

    return 0;
}

static inline int create_control_socket(void)
{
    const int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (unlikely(sock_fd == -1)) {
        log_errno("Cannot create control socket");
        goto out;
    }

    if (unlikely(set_fd_nonblock(sock_fd))) {
        goto out_close;
    }

    remove(CONTROL_SOCKET_NAME);

    if (unlikely(bind(sock_fd, (const struct sockaddr *) &(const struct sockaddr_un)
        { .sun_family = AF_UNIX, .sun_path = CONTROL_SOCKET_NAME }, sizeof(struct sockaddr_un)))) {

        log_errno("Cannot bind control socket");
        goto out_close;
    }

    if (unlikely(listen(sock_fd, CONTROL_SOCKET_BACKLOG))) {
        log_errno("Cannot set control socket to listen");
        goto out_close;
    }

    return sock_fd;

out_close:
    close(sock_fd);
out:
    return -1;
}

static inline void close_control_connection(void)
{
    assert(supervisor.ctlconnfd != -1);

    if (unlikely(close(supervisor.ctlconnfd))) {
        log_errno("Cannot close control connection");
    }

    supervisor.ctlconnfd = -1;
}

static void write_control_response(const char *const fmt, ...)
{
    if (supervisor.ctlconnfd == -1) {
        log_warn("Cannot write control response because control connection is closed");
        return;
    }

    va_list vargs;
    va_start(vargs, fmt);
    char buf[256];
    const ssize_t maxlen = sizeof(buf) - 1;
    const int nbytes = vsnprintf(buf, maxlen, fmt, vargs);
    va_end(vargs);

    if (nbytes < 0) {
        log_errno("Cannot format control response");
        return;
    }

    if (nbytes >= maxlen) {
        log_warn("Exceeded buffer size: needed %d, has %zd", nbytes, maxlen);
        return;
    }

    buf[nbytes] = '\n';
    const ssize_t written = write(supervisor.ctlconnfd, buf, nbytes + 1);

    if (written == -1) {
        log_errno("Cannot write to control connection");
    }

    if (written != nbytes + 1) {
        log_warn("Dropping control connection");
        close_control_connection();
    }
}

static void write_control_prompt(void)
{
    if (supervisor.ctlconnfd == -1) {
        return;
    }

    const ssize_t written = write(supervisor.ctlconnfd, "> ", 2);

    if (written == -1) {
        log_errno("Cannot write to control connection");
    }

    if (written != 2) {
        log_warn("Dropping control connection");
        close_control_connection();
    }
}

static inline void accept_control_connection(void)
{
    const int conn_fd = accept(supervisor.ctlsockfd, NULL, NULL);

    if (unlikely(conn_fd == -1)) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            log_errno("Cannot accept control connection");
        }
    } else if (supervisor.ctlconnfd != -1) {
        close(conn_fd);
        log_info("Refusing second control connection");
    } else {
        log_info("Accepted control connection");

        if (unlikely(set_fd_nonblock(conn_fd) || set_fd_nosigpipe(conn_fd))) {
            close(conn_fd);
            return;
        }

        if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_READ, conn_fd, EV_ADD, 0, 0, 0))) {
            log_errno("Cannot add kevent after accepting control connection");
            close(conn_fd);
            return;
        }

        supervisor.ctlconnfd = conn_fd;
        write_control_response("cart v1.0.0");
        write_control_prompt();
    }
}

static inline void read_control_connection(void)
{
    static char buf[4096 + 1];
    const ssize_t nread = read(supervisor.ctlconnfd, buf, sizeof(buf) - 1);

    if (unlikely(nread == -1)) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            log_errno("Cannot read from control connection");
        }
    } else if (unlikely(nread == 0)) {
        log_info("Closing control connection");
        close_control_connection();
    } else if (buf[nread - 1] != '\n') {
        log_warn("Closing control connection because EOL not found");
        close_control_connection();
    } else {
        buf[nread] = '\0';
        process_control_command(buf);
    }
}

static inline void process_sandbox_message(const sandbox_msg_t msg, const uint64_t msg_data, uint8_t *const data)
{
    switch (msg) {
    case SANDBOX_MSG_LOG:
        log_info("%s", data);
        break;

    case SANDBOX_MSG_CALL:
        hook_execute(msg_data, data);
        break;

    default:
        log_warn("Unknown message: %u", msg);
    }
}

static inline void send_pending_callback(void)
{
    if (!supervisor.shmem) {
        return;
    }

    if (unlikely(pthread_mutex_lock(&supervisor.shmem->lock))) {
        log_errno("Cannot lock shared memory mutex");
        return;
    }

    if (supervisor.shmem->state == SANDBOX_STATE_IDLE && pending_callback) {
        supervisor.shmem->ctl = SANDBOX_CTL_EXEC;
        *(void (**const)(void)) supervisor.shmem->data = pending_callback;
        pending_callback = NULL;

        if (unlikely(pthread_cond_signal(&supervisor.shmem->cond))) {
            log_errno("Cannot signal shared memory condition variable");
        }
    }

    if (unlikely(pthread_mutex_unlock(&supervisor.shmem->lock))) {
        log_errno("Cannot unlock shared memory mutex");
    }
}

static inline void read_sandbox_ctlpipe(void)
{
    if (!supervisor.shmem) {
        return;
    }

    char ch;
    const ssize_t nread = read(supervisor.sandbox_ctlpipe_rfd, &ch, 1);

    if (unlikely(nread == -1)) {
        log_errno("Cannot read from control pipe");
    } else if (unlikely(nread == 0)) {
        close(supervisor.sandbox_ctlpipe_rfd);
        supervisor.sandbox_ctlpipe_rfd = -1;
    } else {
        if (unlikely(pthread_mutex_lock(&supervisor.shmem->lock))) {
            log_errno("Cannot lock shared memory mutex");
            return;
        }

        if (likely(supervisor.shmem->msg != SANDBOX_MSG_CLEAR)) {
            process_sandbox_message(supervisor.shmem->msg, supervisor.shmem->msg_data, supervisor.shmem->data);
            supervisor.shmem->msg = SANDBOX_MSG_CLEAR;

            if (unlikely(pthread_cond_signal(&supervisor.shmem->cond))) {
                log_errno("Cannot signal shared memory condition variable");
            }
        } else if (supervisor.shmem->state == SANDBOX_STATE_IDLE && pending_callback) {
            supervisor.shmem->ctl = SANDBOX_CTL_EXEC;
            *(void (**const)(void)) supervisor.shmem->data = pending_callback;
            pending_callback = NULL;

            if (unlikely(pthread_cond_signal(&supervisor.shmem->cond))) {
                log_errno("Cannot signal shared memory condition variable");
            }
        }

        if (unlikely(pthread_mutex_unlock(&supervisor.shmem->lock))) {
            log_errno("Cannot unlock shared memory mutex");
        }
    }
}

static inline void read_sandbox_outpipe(void)
{
    if (!supervisor.shmem) {
        return;
    }

    static char buf[4096];

    do {
        const ssize_t nread = read(supervisor.sandbox_outpipe_rfd, buf, sizeof(buf) - 1);

        if (unlikely(nread == -1)) {
            if (unlikely(errno != EAGAIN)) {
                log_errno("Cannot read from output pipe");
            }

            break;
        } else if (unlikely(nread == 0)) {
            close(supervisor.sandbox_outpipe_rfd);
            supervisor.sandbox_outpipe_rfd = -1;
        } else {
            buf[nread] = '\0';
            fputs(buf, stdout);
        }
    } while (true);
}

static inline int event_loop(void)
{
    bool do_delayed_quit = false;

    while (!supervisor.do_quit) {
        struct kevent events[32];
        const int nev = kevent_wait(supervisor.kqfd, events, countof(events));

        if (unlikely(nev < 0)) {
            log_errno("Wait on kqueue in event loop");
            return EXIT_FAILURE;
        }

        for (int i = 0; i < nev; ++i) {
            const struct kevent *const ev = events + i;

            switch (ev->filter) {
            case EVFILT_READ:
                if ((int) ev->ident == supervisor.ctlsockfd) {
                    accept_control_connection();
                } else if ((int) ev->ident == supervisor.ctlconnfd) {
                    read_control_connection();
                } else if ((int) ev->ident == supervisor.sandbox_ctlpipe_rfd) {
                    read_sandbox_ctlpipe();
                } else if ((int) ev->ident == supervisor.sandbox_outpipe_rfd) {
                    read_sandbox_outpipe();
                }
                break;

            case EVFILT_TIMER:
                if (ev->ident == 0) {
                    //log_info("Idle timer");
                } else if (ev->ident == 1) {
                    if (supervisor.sandbox_pid != -1) {
                        log_info("Killing sandbox with pid %d", supervisor.sandbox_pid);
                        kill(supervisor.sandbox_pid, SIGKILL);
                    }
                } else if (ev->ident >= 4096) {
                    const size_t timer_idx = ev->ident - 4096;

                    /* TODO: needs a proper queue */
                    if ((pending_callback = timer_get_cb(timer_idx))) {
                        send_pending_callback();
                    }

                    timer_accept_timeout(timer_idx);
                }
                break;

            case EVFILT_PROC:
                if ((pid_t) ev->ident == supervisor.sandbox_pid) {
                    if (ev->fflags & NOTE_EXIT) {
                        log_info("Reaping sandbox with pid %d", supervisor.sandbox_pid);
                        int stat_loc;

                        if (unlikely(waitpid(supervisor.sandbox_pid, &stat_loc, WNOHANG) == -1)) {
                            log_errno("Wait for sandbox process");
                        } else if (WIFSIGNALED(stat_loc)) {
                            const int termsig = WTERMSIG(stat_loc);

                            if (termsig == SIGSEGV) {
                                log_warn("Sandbox crashed with SIGSEGV");
                            }
                        }

                        kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 1, EV_DELETE, 0, 0, 0);
                        supervisor.sandbox_pid = -1;
                        sandbox_shmem_destroy(supervisor.shmem);
                        supervisor.shmem = NULL;

                        if (supervisor.sandbox_outpipe_rfd != -1) {
                            close(supervisor.sandbox_outpipe_rfd);
                            supervisor.sandbox_outpipe_rfd = -1;
                        }

                        if (supervisor.sandbox_ctlpipe_rfd != -1) {
                            close(supervisor.sandbox_ctlpipe_rfd);
                            supervisor.sandbox_ctlpipe_rfd = -1;                            
                        }

                        if (do_delayed_quit) {
                            supervisor.do_quit = true;
                        }
                    }
                }

                break;

            case EVFILT_SIGNAL:
                switch (ev->ident) {
                case SIGINT:
                case SIGTERM:
                case SIGQUIT:
                    log_info("Got SIG%s", (const char *) ev->udata);

                    if (supervisor.sandbox_pid == -1) {
                        supervisor.do_quit = true;
                    } else {
                        do_delayed_quit = true;
                        sandbox_notify_quit(supervisor.shmem);

                        if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 1, EV_ADD | EV_ONESHOT, NOTE_SECONDS, 1, 0))) {
                            log_errno("Cannot add sandbox timeout timer");
                        }
                    }
                    break;

                case SIGUSR1:
                case SIGUSR2:
                    log_info("Got SIG%s", (const char *) ev->udata);
                    break;
                }
                break;
            }
        }
    }

    return EXIT_SUCCESS;
}

static inline int timer_unit_to_kqueue_flag(const timer_unit_t unit)
{
    switch (unit) {
    case TIMER_UNIT_SEC:
        return NOTE_SECONDS;

    case TIMER_UNIT_USEC:
        return NOTE_USECONDS;

    case TIMER_UNIT_NSEC:
        return NOTE_NSECONDS;

    default:
        return NOTE_SECONDS;
    }
}

int supervisor_add_timer(const size_t timer_idx, const bool run, const timer_interval_t interval, const timer_unit_t unit)
{
    assert(supervisor.kqfd != -1);

    if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 4096 + timer_idx,
        EV_ADD | (run ? EV_ENABLE : EV_DISABLE), timer_unit_to_kqueue_flag(unit), interval, 0))) {

        log_errno("Cannot add sandbox timeout timer");
        return -1;
    }

    return 0;
}

int supervisor_del_timer(const size_t timer_idx)
{
    assert(supervisor.kqfd != -1);

    if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 4096 + timer_idx, EV_DELETE, 0, 0, 0))) {
        log_errno("Cannot delete sandbox timeout timer");
        return -1;
    }

    return 0;
}

int supervisor_disable_timer(const size_t timer_idx)
{
    assert(supervisor.kqfd != -1);

    if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 4096 + timer_idx, EV_DISABLE, 0, 0, 0))) {
        log_errno("Cannot disable sandbox timeout timer");
        return -1;
    }

    return 0;
}

int supervisor_enable_timer(const size_t timer_idx, const timer_interval_t interval, const timer_unit_t unit)
{
    assert(supervisor.kqfd != -1);

    if (unlikely(kevent_ctl(supervisor.kqfd, EVFILT_TIMER, 4096 + timer_idx, EV_ENABLE, timer_unit_to_kqueue_flag(unit), interval, 0))) {
        log_errno("Cannot enable sandbox timeout timer");
        return -1;
    }

    return 0;
}

int main(const int argc, const char *const *const argv)
{
    int exit_status = EXIT_FAILURE;

    if (unlikely(argc >= 3)) {
        fprintf(stderr, "Usage: %s [appname]\n", argv[0]);
        goto out_exit;
    }

    struct termios oldt, newt;
    
    if (unlikely(tcgetattr(STDIN_FILENO, &oldt))) {
        perror("tcgetattr");
        goto out_exit;
    }

    newt = oldt;
    newt.c_lflag &= ~ECHOCTL;

    if (unlikely(tcsetattr(STDIN_FILENO, TCSANOW, &newt))) {
        perror("tcsetattr");
        goto out_exit;
    }

    setlinebuf(stdout);

    if (unlikely((supervisor.kqfd = kqueue()) == -1)) {
        log_errno("Cannot create kqueue");
        goto out_cleanup;
    }

    if (unlikely((supervisor.ctlsockfd = create_control_socket()) == -1)) {
        goto out_cleanup;
    }

    if (unlikely(arm_filters())) {
        goto out_cleanup;
    }

    if (argc == 2 && spawn_sandbox(argv[1])) {
        goto out_cleanup;
    }

    exit_status = event_loop();

out_cleanup:
    log_info("Cleanup and shutdown");

    if (unlikely(remove(CONTROL_SOCKET_NAME))) {
        log_errno("Cannot remove control socket");
    }

    if (unlikely(supervisor.ctlsockfd != -1 && close(supervisor.ctlsockfd))) {
        log_errno("Cannot close control socket");
    }

    if (unlikely(supervisor.ctlconnfd != -1 && close(supervisor.ctlconnfd))) {
        log_errno("Cannot close control connection socket");
    }

    if (unlikely(supervisor.kqfd != -1 && close(supervisor.kqfd))) {
        log_errno("Cannot close kqueue");
    }

    if (unlikely(tcsetattr(STDIN_FILENO, TCSANOW, &oldt))) {
        log_errno("Cannot restore terminal");
    }

out_exit:
    return exit_status;
}
