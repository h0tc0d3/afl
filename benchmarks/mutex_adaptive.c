/*
 * Adaptive mutex benchmark.
 *
 * The adaptive mutex against the futex mutex of this library and against
 * pthread_mutex_t, in three splits that stress different parts of the spin
 * budget: one thread that never contends, a two thread hand-off that ping-pongs
 * the lock, and a heavy run with one thread per available CPU. The uncontended
 * path must cost the same single compare exchange as afl_mutex_lock, the
 * hand-off is where the adaptive hint earns its keep by keeping the winner
 * inside the spin loop, and the heavy run is reported as it is: there the two
 * futex implementations wait almost always, and the budget only decides how
 * long the attempt before parking lasts.
 *
 * glibc collapses pthread_mutex_lock() to a plain load and store while
 * __libc_single_threaded is still true, which is the state a one thread
 * benchmark would otherwise measure first. The thread layer is initialized
 * before any timing, which performs the same bookkeeping glibc's first thread
 * creation does, and all three tables then show the real atomics; the full
 * story of that shortcut is in benchmarks/uncontended.c.
 */
#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT     100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static afl_mutex_adaptive_t aam = AFL_MUTEX_ADAPTIVE_INIT;
static afl_mutex_t am = AFL_MUTEX_INIT;
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

static timing_t benchmark_afl_mutex_adaptive(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_adaptive_lock(&aam), afl_mutex_adaptive_unlock(&aam), split);

    return split->lock + split->unlock;
}

/*
 * One split of the benchmark: set the thread count, run all three locks over
 * the identical loop, and print the adaptive against each baseline. The locks
 * are independent words, so the same split can be replayed per implementation.
 */
static void run_split(const char *note, int threads)
{
    benchmark_info pthread_mutex = {.name = "pthread", .func = benchmark_pthread_mutex};
    benchmark_info afl_mutex = {.name = "afl futex", .func = benchmark_afl_mutex};
    benchmark_info adaptive = {.name = "afl adaptive", .func = benchmark_afl_mutex_adaptive};

    print_benchmark_note("%s: %d thread%s per run", note, threads, threads == 1 ? "" : "s");

    bench_set_threads(threads);

    do_bench(&pthread_mutex);
    do_bench(&afl_mutex);
    do_bench(&adaptive);

    print_benchmark(adaptive, afl_mutex);
    print_benchmark(adaptive, pthread_mutex);
}

int main(void)
{
    int cpus = bench_thread_count();

    if (cpus < 2)
        cpus = 2;

    afl_thread_init();

    run_split("uncontended: a single thread, the pure fast path", 1);
    run_split("hand-off: two threads ping-pong the lock", 2);
    run_split("heavy contention: one thread per available CPU", cpus);

    return 0;
}
