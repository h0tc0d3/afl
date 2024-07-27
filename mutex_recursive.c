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

static pthread_mutex_t pm;
static afl_mutex_recursive_t am;

size_t fibonacci_pthread(size_t n)
{
    size_t val = 0;
    if (n <= 1)
        return n;
    pthread_mutex_lock(&pm);
    val = fibonacci_pthread(n - 1) + fibonacci_pthread(n - 2);
    pthread_mutex_unlock(&pm);
    return val;
}

size_t fibonacci_atomic(size_t n)
{
    size_t val = 0;
    if (n <= 1)
        return n;
    afl_mutex_recursive_lock(&am);
    val = fibonacci_atomic(n - 1) + fibonacci_atomic(n - 2);
    afl_mutex_recursive_unlock(&am);
    return val;
}

static timing_t benchmark_pthread_mutex(size_t iters)
{
    timing_t start, stop, duration;
    size_t total_sum = 0;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        total_sum += fibonacci_pthread(FIBONACCI_MAX_VALUE - i);
    }
    TIMING_NOW(stop);

    TIMING_DIFF(duration, start, stop);
    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

static timing_t benchmark_atomic_mutex(size_t iters)
{
    timing_t start, stop, duration;
    size_t total_sum = 0;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        total_sum += fibonacci_atomic(FIBONACCI_MAX_VALUE - i);
    }
    TIMING_NOW(stop);

    TIMING_DIFF(duration, start, stop);
    fprintf(stderr, "Total: %zu, Duration: %.2f\n", total_sum, (double) duration);

    return duration;
}

int main(void)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&pm, &attr);
    pthread_mutexattr_destroy(&attr);

    afl_mutex_recursive_init(&am);

    benchmark_info pthread_mutex = {.name = "pthread", .func = benchmark_pthread_mutex};
    benchmark_info atomic_mutex  = {.name = "atomic", .func = benchmark_atomic_mutex};

    do_bench(&pthread_mutex);
    do_bench(&atomic_mutex);

    print_benchmark(atomic_mutex, pthread_mutex);

    return 0;
}
