/*
 * afl_once smoke test.
 *
 * Not a measurement: afl_once over 100 concurrent iterations of an initializer
 * that prints "Init" through a compare exchange guard, and complains if the
 * initializer ever runs twice. The iterations are spread over the thread layer
 * (the workers of one process contend on the same once word, which is the whole
 * point of the test). The benchmark runner does not execute this binary; run it
 * directly.
 */
#include <stdint.h>
#include <stdio.h>

#include "afl_thread.h"

#define ONCE_ITERATIONS 100
#define ONCE_WORKERS    4

static afl_once_t once = AFL_ONCE_INIT;
static uint32_t check_once = 0;

void init_function(void)
{
    uint32_t lock = 0;

    if (__atomic_compare_exchange_n(&check_once, &lock, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
        printf("Init\n");
    else
        printf("ERROR: Init already been!\n");
}

static void once_worker(void *argument)
{
    (void) argument;

    for (size_t i = 0; i < ONCE_ITERATIONS / ONCE_WORKERS; i++)
        afl_once(&once, &init_function);
}

int main(void)
{
    afl_thread_t workers[ONCE_WORKERS];

    for (int i = 0; i < ONCE_WORKERS; i++)
        if (afl_thread_create(&workers[i], once_worker, NULL) != 0)
            return 1;

    for (int i = 0; i < ONCE_WORKERS; i++)
        if (afl_thread_join(&workers[i]) != 0)
            return 1;

    /* The initializer has to have run exactly once across every iteration. */
    return check_once == 1 ? 0 : 1;
}
