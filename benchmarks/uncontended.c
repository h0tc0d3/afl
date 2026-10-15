/*
 * The uncontended fast path on its own.
 *
 * Every other benchmark here runs several threads against one lock, so its
 * numbers are dominated by the hand-off: waiting for the current owner and
 * waking it up again. Acquiring and releasing a lock that nobody else wants is
 * a different piece of code -- for afl_mutex_lock it is one compare exchange
 * and one store -- and it deserves a number of its own, which is what this
 * benchmark measures: one thread, lock, payload, unlock.
 *
 * Before pthread can serve as the baseline at all, a second fast path of the
 * libc has to be dealt with. glibc keeps __libc_single_threaded true while the
 * process has never created a second thread, and in that state
 * pthread_mutex_lock() and pthread_mutex_unlock() collapse to a plain load and
 * a plain store, with no atomic operation behind them. That is not what a
 * program with threads gets, and a benchmark that measured it by accident
 * would report a pthread mutex several times cheaper than it is. So both states
 * are measured here, and each table says which one it is:
 *
 *   1. no second thread has ever existed -> the libc shortcut
 *   2. after a thread was created and joined -> the real uncontended path
 *
 * glibc never sets the flag back to true, which fixes the order: the shortcut
 * can only be measured first. Both phases print the value of the flag that was
 * in effect while they ran, so a libc without the flag, or a future one that
 * clears it earlier than pthread_create(), shows up in the output instead of
 * silently changing what the numbers mean.
 *
 * The second table is the one to quote. The first one is printed because the
 * difference between the two is the size of the trap.
 */
#include <pthread.h>
#include <stdbool.h>

#include "afl.h"

#define RUNS_COUNT     100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

/*
 * The flag of the libc, weakly referenced: it is a glibc detail and not part of
 * any standard. On a libc that does not have it the address stays null, and the
 * note says so instead of the binary failing to link.
 */
extern bool __libc_single_threaded __attribute__((weak));

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

/* The flag as this libc reports it: -1 when it has none, 0 or 1 otherwise. */
static int single_threaded_flag(void)
{
    if (&__libc_single_threaded == NULL)
        return -1;

    return __libc_single_threaded ? 1 : 0;
}

/*
 * Report the state the flag was in while a phase ran. Both ends are printed
 * because they have to agree: a phase whose flag flipped halfway through
 * measured a mix of the two paths and its pthread column means nothing.
 */
static void print_flag_note(const char *phase, int before, int after)
{
    if (before < 0) {
        print_benchmark_note("%s: this libc has no __libc_single_threaded", phase);
        print_benchmark_note("%s: the pthread column is the real uncontended path", phase);
        return;
    }

    if (before != after) {
        print_benchmark_note("%s: __libc_single_threaded went from %d to %d while measuring", phase, before, after);
        print_benchmark_note("%s: the pthread column is a mix of both paths, ignore it", phase);
        return;
    }

    if (before == 1) {
        print_benchmark_note("%s: __libc_single_threaded = 1, no second thread has ever existed", phase);
        print_benchmark_note("%s: pthread_mutex_lock/unlock are a plain load and store here", phase);
        return;
    }

    print_benchmark_note("%s: __libc_single_threaded = 0, the atomics of the libc are live", phase);
}

int main(void)
{
    benchmark_info shortcut_afl = {.name = "afl", .func = benchmark_afl_mutex};
    benchmark_info shortcut_pthread = {.name = "pthread", .func = benchmark_pthread_mutex};
    benchmark_info honest_afl = {.name = "afl", .func = benchmark_afl_mutex};
    benchmark_info honest_pthread = {.name = "pthread", .func = benchmark_pthread_mutex};
    int shortcut_before, shortcut_after, honest_before, honest_after;
    int error;

    /*
     * One thread only. That is the definition of uncontended, and it is also
     * what keeps the process single-threaded: a region of one worker runs on
     * the thread that calls bench_parallel and creates no thread of its own, so
     * the harness below does not clear the flag behind the back of the first
     * phase.
     */
    bench_set_threads(1);

    shortcut_before = single_threaded_flag();
    do_bench(&shortcut_afl);
    do_bench(&shortcut_pthread);
    shortcut_after = single_threaded_flag();

    /*
     * The layer's one-time initialization performs the bookkeeping glibc's
     * first thread creation does, which is what clears __libc_single_threaded
     * for good; no thread of the layer's own is created.
     */
    error = afl_thread_init();

    if (error != 0) {
        print_benchmark_note("could not mark the process multithreaded: %s", strerror(error));
        print_benchmark_note("without it the pthread column below is the libc shortcut, not the fast path");
        print_flag_note("shortcut", shortcut_before, shortcut_after);
        print_benchmark(shortcut_afl, shortcut_pthread);

        return EXIT_FAILURE;
    }

    honest_before = single_threaded_flag();
    do_bench(&honest_afl);
    do_bench(&honest_pthread);
    honest_after = single_threaded_flag();

    /*
     * The honest table first: it is the number that applies to a program that
     * has threads, which is every program that needs a lock.
     */
    print_benchmark_note("one thread per lock, uncontended, the atomics of the libc are live");
    print_flag_note("fast path", honest_before, honest_after);
    print_benchmark(honest_afl, honest_pthread);

    print_benchmark_note("the same measurement with the single threaded shortcut of the libc still armed");
    print_flag_note("shortcut", shortcut_before, shortcut_after);
    print_benchmark(shortcut_afl, shortcut_pthread);

    return EXIT_SUCCESS;
}
