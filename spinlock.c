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

static afl_spinlock_t afl_spinlock;
static pthread_spinlock_t pthread_spinlock;

static timing_t benchmark_pthread_spinlock(size_t iters)
{
    timing_t start, stop, duration = 0;
    size_t total_sum = 0;

    for (size_t i = 0; i < iters; i++) {
        TIMING_NOW(start);
        pthread_spin_lock(&pthread_spinlock);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
        total_sum += fibonacci(FIBONACCI_MAX_VALUE - i);
        TIMING_NOW(start);
        pthread_spin_unlock(&pthread_spinlock);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
    }

    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

static timing_t benchmark_atomic_spinlock(size_t iters)
{
    timing_t start, stop, duration = 0;
    size_t total_sum = 0;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        TIMING_NOW(start);
        afl_spin_lock(&afl_spinlock);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
        total_sum += fibonacci(FIBONACCI_MAX_VALUE - i);
        TIMING_NOW(start);
        afl_spin_unlock(&afl_spinlock);
        TIMING_NOW(stop);
        TIMING_ADD_DIFF(duration, start, stop);
    }

    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

int main(void)
{
    pthread_spin_init(&pthread_spinlock, 0);
    afl_spin_init(&afl_spinlock, 0);

    benchmark_info pthread_spinlock_benchmark = {.name = "pthread", .func = benchmark_pthread_spinlock};
    benchmark_info atomic_spinlock_benchmark  = {.name = "atomic", .func = benchmark_atomic_spinlock};

    do_bench(&atomic_spinlock_benchmark);
    do_bench(&pthread_spinlock_benchmark);

    print_benchmark(atomic_spinlock_benchmark, pthread_spinlock_benchmark);

    return 0;
}
