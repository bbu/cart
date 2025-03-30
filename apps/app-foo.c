#include <cart.h>

cart_app("foo-example", 1, 200);

cart_cb(timer_expired);
cart_cb(data_received);

static cart_timer_t tm1, tm2;
static cart_chan_t ch1, ch2;
static cart_store_t st1, st2;

cart_load
{
    cart_log("first log msg from app %d", 42);

    if (!(tm1 = cart_timer_create(timer_expired, CART_TIMER_ONESHOT, true, 30))) {
        return false;
    }

    cart_log("second log msg from app %d %llu", 58, tm1);
    return true;
}

cart_cb(timer_expired)
{
}

cart_cb(data_received)
{
}
