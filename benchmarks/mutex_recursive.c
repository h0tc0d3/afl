#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT 100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

/*
 * Depth of the recursion. Both implementations take the lock at every level of
 * the tree, so this is also the number of nested lock/unlock pairs that a single
 * iteration performs.
 */
#define FIBONACCI_MAX_VALUE 16

static pthread_mutex_t pm;
static afl_mutex_recursive_t am;

/* Keeps the computed result alive without disturbing the measurement. */
static volatile size_t recursion_sink;

/*
 * The recursion itself is the critical section: every level takes the lock and
 * releases it again on the way back. A recursive mutex has to count the nested
 * acquisitions, a plain one would deadlock on the second level, which is why
 * this benchmark only exists for the recursive mutex.
 */
static size_t fibonacci_pthread(size_t n)
{
    size_t val;

    if (n <= 1)
        return n;

    pthread_mutex_lock(&pm);
    val = fibonacci_pthread(n - 1) + fibonacci_pthread(n - 2);
    pthread_mutex_unlock(&pm);

    return val;
}

static size_t fibonacci_afl(size_t n)
{
    size_t val;

    if (n <= 1)
        return n;

    afl_mutex_recursive_lock(&am);
    val = fibonacci_afl(n - 1) + fibonacci_afl(n - 2);
    afl_mutex_recursive_unlock(&am);

    return val;
}

/*
 * The measured region is the whole recursion, not a single lock/unlock pair, so
 * the split of the lock and unlock times would be misleading and stays unused.
 */
static timing_t benchmark_pthread_recursive(size_t iters, benchmark_split *split)
{
    timing_t start, stop, duration;
    size_t total_sum = 0;

    (void) split;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        total_sum += fibonacci_pthread(FIBONACCI_MAX_VALUE);
    }
    TIMING_NOW(stop);

    recursion_sink = total_sum;

    TIMING_DIFF(duration, start, stop);

    return duration;
}

static timing_t benchmark_afl_recursive(size_t iters, benchmark_split *split)
{
    timing_t start, stop, duration;
    size_t total_sum = 0;

    (void) split;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        total_sum += fibonacci_afl(FIBONACCI_MAX_VALUE);
    }
    TIMING_NOW(stop);

    recursion_sink = total_sum;

    TIMING_DIFF(duration, start, stop);

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

    benchmark_info pthread_recursive = {.name = "pthread", .func = benchmark_pthread_recursive};
    benchmark_info afl_recursive     = {.name = "afl_recursive", .func = benchmark_afl_recursive};

    do_bench(&pthread_recursive);
    do_bench(&afl_recursive);

    print_benchmark(afl_recursive, pthread_recursive);

    return 0;
}
