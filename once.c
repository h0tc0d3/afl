#include <stdio.h>
#include <stdint.h>

#include "afl.h"

static afl_once_t once     = AFL_ONCE_INIT;
static uint32_t check_once = 0;

void init_function(void)
{
    uint32_t lock = 0;
    if (__atomic_compare_exchange_n(&check_once, &lock, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
        printf("Init\n");
    else
        printf("ERROR: Init already been!\n");
}

int main(void)
{
#pragma omp parallel for
    for (size_t i = 0; i < 100; i++) {
        afl_once(&once, &init_function);
    }
    return 0;
}
