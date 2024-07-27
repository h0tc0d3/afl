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

static afl_mutex_t am     = AFL_MUTEX_INIT;
static pthread_mutex_t pm = PTHREAD_MUTEX_INITIALIZER;

static timing_t benchmark_pthread_mutex(size_t iters)
{
    timing_t start, stop, duration = 0;
    size_t total_sum = 0;

    for (size_t i = 0; i < iters; i++) {
        TIMING_NOW(start);
        pthread_mutex_lock(&pm);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
        total_sum += fibonacci(FIBONACCI_MAX_VALUE - i);
        TIMING_NOW(start);
        pthread_mutex_unlock(&pm);
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
        afl_mutex_lock(&am);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
        total_sum += fibonacci(FIBONACCI_MAX_VALUE - i);
        TIMING_NOW(start);
        afl_mutex_unlock(&am);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
    }

    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

int main(void)
{
    benchmark_info pthread_mutex = {.name = "pthread", .func = benchmark_pthread_mutex};
    benchmark_info atomic_mutex  = {.name = "atomic", .func = benchmark_atomic_mutex};

    do_bench(&pthread_mutex);
    do_bench(&atomic_mutex);

    print_benchmark(atomic_mutex, pthread_mutex);

    return 0;
}
