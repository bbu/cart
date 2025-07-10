#include "chan.h"
#include "supervisor.h"
#include "common.h"

#include <sys/types.h>
#include <sys/stat.h>

#define HANDLE_NULL       ((chan_t) 0x0000000000000000ull)
#define HANDLE_MAGIC_MASK ((chan_t) 0xFF00000000000000ull)
#define HANDLE_MAGIC_BITS ((chan_t) 0xBB00000000000000ull)

/*
static inline bool handle_check_magic(const chan_t ch)
{
    return (ch & HANDLE_MAGIC_MASK) != HANDLE_MAGIC_BITS;
}

static inline size_t handle_remove_magic(const chan_t ch)
{
    return (size_t) (ch ^ HANDLE_MAGIC_BITS);
}

static inline chan_t handle_put_magic(const size_t idx)
{
    return (chan_t) idx | HANDLE_MAGIC_BITS;
}
*/
#define MAX_CHANS ((size_t) 4096)

chan_t chan_new(void)
{
    return HANDLE_NULL;
}
/*
bool chan_open(const chan_t ch, const char *const name)
{

}

bool chan_readline(const chan_t ch, const char **line)
{

}
*/
bool chan_del(const chan_t ch)
{
    (void) ch;
    return false;
}
