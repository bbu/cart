#include <cart.h>

cart_app("foo-example", 1, 200);

cart_cb(timer_expired);
cart_cb(timer_cb2);
cart_cb(data_received);

static cart_timer_t tm1, tm2;
static cart_chan_t ch1, ch2;
static cart_store_t st1, st2;

cart_load
{
    cart_log("first log msg from app %d", 42);

    tm1 = cart_timer_add(timer_expired, 0, true, 1, CART_TIMER_UNIT_SEC, false);

    if (tm1 == cart_null) {
        return false;
    }

    cart_timer_add(timer_cb2, 0, true, 5, CART_TIMER_UNIT_SEC, false);
    cart_log("second log msg from app %d %016llX", 58, tm1);
    return true;
}

cart_cb(timer_expired)
{
    cart_log("My callback");
}

cart_cb(timer_cb2)
{
    static int i = 0;
    cart_log("Second callback");

    if (i++ % 2 == 0) {
        cart_timer_pause(tm1);
    } else {
        cart_timer_resume(tm1);
    }
}

cart_cb(data_received)
{
}
