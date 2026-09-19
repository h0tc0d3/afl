#include "afl.h"

#define RUNS_COUNT 100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static afl_mutex_t am_owner = AFL_MUTEX_INIT;
static afl_mutex_t am_pi    = AFL_MUTEX_INIT;

/*
 * Owner tracking mutex, used here as the baseline: it is the same lock as in
 * mutex_owner, so that the only difference that is left is the way a contended
 * acquire is served (spin then futex wait against FUTEX_LOCK_PI, which charges
 * the kernel with the priority inheritance bookkeeping).
 */
static timing_t benchmark_afl_owner_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_owner_lock(&am_owner), afl_mutex_owner_unlock(&am_owner), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_pi_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_pi_lock(&am_pi), afl_mutex_pi_unlock(&am_pi), split);

    return split->lock + split->unlock;
}

int main(void)
{
    benchmark_info afl_owner = {.name = "afl_owner", .func = benchmark_afl_owner_mutex};
    benchmark_info afl_pi    = {.name = "afl_pi", .func = benchmark_afl_pi_mutex};

    do_bench(&afl_owner);
    do_bench(&afl_pi);

    print_benchmark(afl_owner, afl_pi);

    return 0;
}
