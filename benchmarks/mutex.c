/*
 * Mutex benchmark.
 *
 * The plain lock/unlock loop of afl_mutex against pthread_mutex, and the same
 * loop through the timed acquires. The timed rows run against a deadline an
 * hour ahead, so nothing ever expires: what is measured is the price of the
 * timed API itself. afl_mutex_timedlock takes its deadline on CLOCK_REALTIME,
 * like pthread_mutex_timedlock, so the abstime is built from that clock once
 * here, outside the loops.
 */
#include <pthread.h>
#include <time.h>

#include "afl.h"

#define RUNS_COUNT     100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static afl_mutex_t am = AFL_MUTEX_INIT;
static afl_mutex_t am_timed = AFL_MUTEX_INIT;
static pthread_mutex_t pm = PTHREAD_MUTEX_INITIALIZER;

static struct timespec timed_abstime;

static void timed_abstime_init(void)
{
    if (afl_clock_gettime(CLOCK_REALTIME, &timed_abstime) != 0) {
        timed_abstime.tv_sec = time(NULL) + 3600;
        timed_abstime.tv_nsec = 0;
    } else {
        timed_abstime.tv_sec += 3600;
    }
}

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

static timing_t benchmark_pthread_mutex_timed(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_mutex_timedlock(&pm, &timed_abstime), (pthread_mutex_unlock(&pm), 0), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_mutex_timed(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_timedlock(&am_timed, &timed_abstime), (afl_mutex_unlock(&am_timed), 0), split);

    return split->lock + split->unlock;
}

int main(void)
{
    benchmark_info pthread_mutex = {.name = "pthread", .func = benchmark_pthread_mutex};
    benchmark_info afl_mutex = {.name = "afl", .func = benchmark_afl_mutex};
    benchmark_info pthread_timed = {.name = "pthread timed", .func = benchmark_pthread_mutex_timed};
    benchmark_info afl_timed = {.name = "afl timed", .func = benchmark_afl_mutex_timed};

    timed_abstime_init();

    print_benchmark_note("the plain loop: an uncontended pair costs a single atomic");
    do_bench(&pthread_mutex);
    do_bench(&afl_mutex);
    print_benchmark(afl_mutex, pthread_mutex);

    print_benchmark_note("the timed loop: the same pairs through the timed acquire, a deadline an hour ahead");
    do_bench(&pthread_timed);
    do_bench(&afl_timed);
    print_benchmark(afl_timed, pthread_timed);

    print_benchmark_note("the timed against the plain afl loop: the price of the deadline path alone");
    print_benchmark(afl_timed, afl_mutex);

    return 0;
}
