#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT 100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static afl_mutex_t am     = AFL_MUTEX_INIT;
static pthread_mutex_t pm = PTHREAD_MUTEX_INITIALIZER;

static timing_t benchmark_pthread_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_mutex_lock(&pm), pthread_mutex_unlock(&pm), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_lock(&am), afl_mutex_unlock(&am), split);

    return split->lock + split->unlock;
}

int main(void)
{
    benchmark_info pthread_mutex = {.name = "pthread", .func = benchmark_pthread_mutex};
    benchmark_info afl_mutex     = {.name = "afl", .func = benchmark_afl_mutex};

    do_bench(&pthread_mutex);
    do_bench(&afl_mutex);

    print_benchmark(afl_mutex, pthread_mutex);

    return 0;
}
