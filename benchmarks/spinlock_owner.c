#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT 100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static afl_spinlock_t afl_spinlock;
static pthread_spinlock_t pthread_spinlock;

static timing_t benchmark_pthread_spinlock(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_spin_lock(&pthread_spinlock), pthread_spin_unlock(&pthread_spinlock), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_spin_owner(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_spin_owner_lock(&afl_spinlock), afl_spin_owner_unlock(&afl_spinlock), split);

    return split->lock + split->unlock;
}

int main(void)
{
    pthread_spin_init(&pthread_spinlock, 0);
    afl_spin_init(&afl_spinlock, 0);

    benchmark_info pthread_spinlock = {.name = "pthread", .func = benchmark_pthread_spinlock};
    benchmark_info afl_spin_owner   = {.name = "afl_owner", .func = benchmark_afl_spin_owner};

    do_bench(&pthread_spinlock);
    do_bench(&afl_spin_owner);

    print_benchmark(afl_spin_owner, pthread_spinlock);

    return 0;
}
