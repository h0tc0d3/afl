#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT 100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static pthread_mutex_t pm;
static afl_mutex_recursive_t am;

static timing_t benchmark_pthread_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_mutex_lock(&pm), pthread_mutex_unlock(&pm), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_recursive_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_recursive_lock(&am), afl_mutex_recursive_unlock(&am), split);

    return split->lock + split->unlock;
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
    benchmark_info afl_recursive = {.name = "afl_recursive", .func = benchmark_afl_recursive_mutex};

    do_bench(&pthread_mutex);
    do_bench(&afl_recursive);

    print_benchmark(afl_recursive, pthread_mutex);

    return 0;
}
