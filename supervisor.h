#pragma once

#include "timer.h"

int supervisor_add_timer(size_t, bool, timer_interval_t, timer_unit_t);
int supervisor_del_timer(size_t);
int supervisor_disable_timer(size_t);
int supervisor_enable_timer(size_t, timer_interval_t, timer_unit_t);
