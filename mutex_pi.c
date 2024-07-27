#include <linux/futex.h>
#include <math.h>
#include <omp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "afl.h"

#define RUNS_COUNT 100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

#define FIBONACCI_MAX_VALUE 16

static afl_mutex_t am1 = AFL_MUTEX_INIT;
static afl_mutex_t am2 = AFL_MUTEX_INIT;

static timing_t benchmark_atomic_pi_mutex(size_t iters)
{
    timing_t start, stop, duration = 0;
    size_t total_sum = 0;

    for (size_t i = 0; i < iters; i++) {
        TIMING_NOW(start);
        afl_mutex_pi_lock(&am1);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
        total_sum += fibonacci(FIBONACCI_MAX_VALUE - i);
        TIMING_NOW(start);
        afl_mutex_pi_unlock(&am1);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
    }

    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

static timing_t benchmark_atomic_mutex(size_t iters)
{
    timing_t start, stop, duration = 0;
    size_t total_sum = 0;

    for (size_t i = 0; i < iters; i++) {
        TIMING_NOW(start);
        afl_mutex_owner_lock(&am2);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
        total_sum += fibonacci(FIBONACCI_MAX_VALUE - i);
        TIMING_NOW(start);
        afl_mutex_owner_unlock(&am2);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
    }

    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

int main(void)
{
    benchmark_info atomic_mutex    = {.name = "atomic", .func = benchmark_atomic_mutex};
    benchmark_info atomic_pi_mutex = {.name = "atomic_pi", .func = benchmark_atomic_pi_mutex};

    do_bench(&atomic_mutex);
    do_bench(&atomic_pi_mutex);

    print_benchmark(atomic_mutex, atomic_pi_mutex);

    return 0;
}
