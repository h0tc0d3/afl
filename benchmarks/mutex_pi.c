/*
 * Priority inheritance mutex benchmark.
 *
 * Three tables. The first puts afl_mutex_owner_lock against
 * afl_mutex_pi_lock: the owner lock wins a contended hand-off from its spin
 * phase, the PI lock gives the kernel the queueing and the priority
 * inheritance bookkeeping, and that is the trade this binary exists to
 * show. The second puts afl_mutex_pi_lock against a pthread_mutex_t with
 * PTHREAD_PRIO_INHERIT, so the comparison includes the baseline that asks
 * the kernel for the same work. The third puts afl_mutex_pi_lock against
 * afl_mutex_pc_lock, the same PI fast path with the ceiling protocol around
 * it. The process runs at the ceiling priority when the machine grants it,
 * which is the steady state of the ceiling protocol (see main() below); when
 * the kernel or libc refuses the PI protocol or the ceiling, the affected
 * table is replaced by a note and the rest of the run stands on its own.
 */
#define _GNU_SOURCE

#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT     100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

/*
 * The protocol the pthread PI baseline asks for. PTHREAD_PRIO_INHERIT is the
 * only one that matters here; it is a macro so that the skip path of main() can
 * be exercised on a machine where priority inheritance works, by building with
 * -DBENCH_PI_PROTOCOL=<n> for an n the libc has to refuse.
 */
#ifndef BENCH_PI_PROTOCOL
#define BENCH_PI_PROTOCOL PTHREAD_PRIO_INHERIT
#endif

static afl_mutex_t am_owner = AFL_MUTEX_INIT;
static afl_mutex_t am_pi = AFL_MUTEX_INIT;

/*
 * The priority ceiling variants and their pthread counterpart. The afl.h
 * ceilings are on the scale of afl.h (a lower number is a higher priority,
 * inverted onto the SCHED_FIFO range, see afl.h); BENCH_PC_CEILING maps to
 * exactly the kernel priority this process puts itself at before anything is
 * measured, so holding that mutex finds the holder at its ceiling and the
 * borrow is the no-op the protocol prescribes for it: the afl_pc column is the
 * one the plain PI path is compared against. BENCH_PC_BOOST_CEILING maps
 * above that priority, so every pair pays a real elevation and a real
 * restore, and the only fair baseline for that is the libc implementation of
 * the same protocol, pm_protect, whose ceiling is a SCHED_FIFO priority
 * (the pthread scale runs the other way) and is set to the same mapped value.
 *
 * On an unprivileged machine the elevation is refused with EPERM, the protocol
 * tolerates it (see afl.h), and every column degenerates into the plain PI
 * path plus its bookkeeping; the tables still compare like with like.
 */
#define BENCH_PC_CEILING       99
#define BENCH_PC_BOOST_CEILING 10

static afl_mutex_pc_t am_pc;
static afl_mutex_pc_t am_pc_boost;

/* Not statically initializable: the protocol lives in an attribute object. */
static pthread_mutex_t pm_pi;
static pthread_mutex_t pm_protect;

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

static timing_t benchmark_pthread_pi_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_mutex_lock(&pm_pi), pthread_mutex_unlock(&pm_pi), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_pc_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_pc_lock(&am_pc), afl_mutex_pc_unlock(&am_pc), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_pc_boost_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_mutex_pc_lock(&am_pc_boost), afl_mutex_pc_unlock(&am_pc_boost), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_pthread_protect_mutex(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_mutex_lock(&pm_protect), pthread_mutex_unlock(&pm_protect), split);

    return split->lock + split->unlock;
}

/*
 * A pthread mutex with the protocol above. Returns 0, or the error number of
 * the first call that refused; on failure the mutex is left untouched, so the
 * caller must not destroy it.
 */
static int init_pthread_pi(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attributes;
    int error;
    int destroyed;

    error = pthread_mutexattr_init(&attributes);

    if (error != 0)
        return error;

    error = pthread_mutexattr_setprotocol(&attributes, BENCH_PI_PROTOCOL);

    if (error == 0)
        error = pthread_mutex_init(mutex, &attributes);

    destroyed = pthread_mutexattr_destroy(&attributes);

    return error != 0 ? error : destroyed;
}

/*
 * A pthread mutex with the PTHREAD_PRIO_PROTECT protocol and the given
 * ceiling, which on the pthread scale is the SCHED_FIFO priority to run at
 * while the mutex is held (higher is more favoured). Returns 0, or the error
 * number of the first call that refused; on failure the mutex is left
 * untouched, so the caller must not destroy it.
 */
static int init_pthread_protect(pthread_mutex_t *mutex, int ceiling)
{
    pthread_mutexattr_t attributes;
    int error;
    int destroyed;

    error = pthread_mutexattr_init(&attributes);

    if (error != 0)
        return error;

    error = pthread_mutexattr_setprotocol(&attributes, PTHREAD_PRIO_PROTECT);

    if (error == 0)
        error = pthread_mutexattr_setprioceiling(&attributes, ceiling);

    if (error == 0)
        error = pthread_mutex_init(mutex, &attributes);

    destroyed = pthread_mutexattr_destroy(&attributes);

    return error != 0 ? error : destroyed;
}

/*
 * Take and release the mutex once, before it is measured. An attribute object
 * that accepts a protocol is not a promise that the lock can be used: the
 * kernel may refuse the operation for a thread that does not run under a real
 * time policy, and every call would then return the same error, so the
 * benchmark would time a failing call a hundred thousand times and report it
 * as a result. Returns 0, or the error number that made the mutex unusable.
 */
static int probe_pthread_mutex(pthread_mutex_t *mutex, const char *kind)
{
    int error = pthread_mutex_lock(mutex);

    if (error == 0)
        error = pthread_mutex_unlock(mutex);

    if (error != 0) {
        int destroyed = pthread_mutex_destroy(mutex);

        /*
         * The mutex is going to be reported by its own lock error above, which
         * is the informative one. A destroy that refuses as well is said out
         * loud rather than dropped, but it is not the reason to skip.
         */
        if (destroyed != 0)
            print_benchmark_note("could not destroy the refused pthread %s mutex: %s", kind, strerror(destroyed));
    }

    return error;
}

/*
 * Run this thread as SCHED_FIFO at the given priority, before the first region
 * creates any worker, so that every worker the harness makes inherits it.
 * Returns 0, or the error number of the refusal (EPERM on a machine without the
 * privilege, which the ceiling protocol tolerates). The call is afl.h's own raw
 * sched_setscheduler, so it needs no pthread and reads the kernel state rather
 * than a libc cache.
 */
static int bench_become_rt(int prio)
{
    return __afl_sched_setparam(SCHED_FIFO, prio);
}

static void bench_become_normal(void)
{
    (void) __afl_sched_setparam(SCHED_OTHER, 0);
}

int main(void)
{
    benchmark_info afl_owner = {.name = "afl_owner", .func = benchmark_afl_owner_mutex};
    benchmark_info afl_pi = {.name = "afl_pi", .func = benchmark_afl_pi_mutex};
    benchmark_info afl_pc = {.name = "afl_pc", .func = benchmark_afl_pc_mutex};
    benchmark_info afl_pc_boost = {.name = "afl_pc_boost", .func = benchmark_afl_pc_boost_mutex};
    benchmark_info pthread_pi = {.name = "pthread_pi", .func = benchmark_pthread_pi_mutex};
    benchmark_info pthread_protect = {.name = "pthread_protect", .func = benchmark_pthread_protect_mutex};
    int min = sched_get_priority_min(SCHED_FIFO);
    int max = sched_get_priority_max(SCHED_FIFO);
    int ceiling_prio = min + (max - BENCH_PC_CEILING);
    int boost_prio = min + (max - BENCH_PC_BOOST_CEILING);
    int protect_usable;
    int pc_usable;
    int error;

    /*
     * The scheduling state first, before any thread is created: every harness
     * worker inherits the parameters of the thread that creates it, and
     * the steady state of the ceiling protocol (a holder at the ceiling, for
     * which the borrow is a documented no-op) only exists if the workers
     * already run at ceiling_prio. The afl_pi column of the PC table re-runs
     * the same measurement in the same state, so the comparison is like for
     * like. The owner and pthread_pi tables are not affected by the policy:
     * an uncontended or hand-off path goes through the same futex either
     * way, so the same state measures them unchanged.
     */
    error = bench_become_rt(ceiling_prio);

    if (error == 0)
        print_benchmark_note(
          "this process runs as SCHED_FIFO %d, the priority the ceiling %d maps to (see afl.h)", ceiling_prio,
          BENCH_PC_CEILING
        );
    else
        print_benchmark_note(
          "this process could not become SCHED_FIFO %d: %s", ceiling_prio,
          error == EPERM || error == EACCES ? "no privilege (the ceiling elevation is refused and tolerated)"
                                            : strerror(error)
        );

    do_bench(&afl_owner);
    do_bench(&afl_pi);

    print_benchmark(afl_owner, afl_pi);

    error = init_pthread_pi(&pm_pi);

    if (error == 0)
        error = probe_pthread_mutex(&pm_pi, "priority inheritance");

    if (error != 0) {
        print_benchmark_note("no pthread baseline with priority inheritance: %s", strerror(error));
        print_benchmark_note("this kernel or libc does not offer PTHREAD_PRIO_INHERIT for this thread");
        print_benchmark_note("the table above stands on its own: afl_owner against afl_pi");

        return EXIT_SUCCESS;
    }

    do_bench(&pthread_pi);

    print_benchmark_note("afl_pi against a pthread mutex with PTHREAD_PRIO_INHERIT");
    print_benchmark_note("both columns hand a contended acquire to the kernel, so both pay for the bookkeeping");
    print_benchmark(afl_pi, pthread_pi);

    error = pthread_mutex_destroy(&pm_pi);

    if (error != 0)
        print_benchmark_note("could not destroy the pthread priority inheritance mutex: %s", strerror(error));

    /*
     * The priority ceiling mutexes. A refused initialization (the kernel
     * declines the PI futex probe, see afl_mutex_pc_init) takes every ceiling
     * table out: the variant never degrades to a non-PI lock, so there is
     * nothing left to compare here.
     */
    pc_usable = afl_mutex_pc_init(&am_pc, BENCH_PC_CEILING) == 0
             && afl_mutex_pc_init(&am_pc_boost, BENCH_PC_BOOST_CEILING) == 0;

    if (!pc_usable) {
        print_benchmark_note("the afl.h priority ceiling mutex could not be initialized: the kernel declined it");
        print_benchmark_note("the tables above stand on their own");

        return EXIT_SUCCESS;
    }

    /*
     * The bar of the variant: the ceiling bookkeeping may not make the lock
     * measurably slower than the plain PI path. afl_pc is the ceiling %d,
     * which maps to the priority every thread already runs at, so the borrow
     * and the restore are the no-ops of the protocol and what remains on top
     * of afl_pi is the parameter read of the holder. afl_pi is measured again
     * in this state so that the pair sits under the same scheduling policy.
     */
    print_benchmark_note("afl_pi against afl_pc, the same PI fast path with the ceiling protocol around it");
    print_benchmark_note(
      "ceiling %d maps to the running priority %d: the borrow of afl_pc is the no-op of the protocol", BENCH_PC_CEILING,
      ceiling_prio
    );
    do_bench(&afl_pi);
    do_bench(&afl_pc);
    print_benchmark(afl_pi, afl_pc);

    /*
     * The boost state: a ceiling above the running priority, so every pair
     * pays a real elevation and a real restore. The baseline is the libc
     * implementation of the same protocol, which performs its own priority
     * system calls across the hold; its ceiling is the same kernel priority,
     * expressed on the pthread scale.
     */
    protect_usable = init_pthread_protect(&pm_protect, boost_prio) == 0
                  && probe_pthread_mutex(&pm_protect, "priority protect") == 0;

    print_benchmark_note(
      "afl_pc with ceiling %d (kernel priority %d) against a pthread mutex with PTHREAD_PRIO_PROTECT %d",
      BENCH_PC_BOOST_CEILING, boost_prio, boost_prio
    );

    do_bench(&afl_pc_boost);

    /*
     * Nothing to destroy on this path: a refused init left the mutex
     * untouched, and a refused probe destroyed the mutex it was given before
     * it reported the error (see probe_pthread_mutex).
     */
    if (!protect_usable) {
        print_benchmark_note("no pthread PTHREAD_PRIO_PROTECT baseline: the protocol was refused here");
        print_benchmark_note("the boost column stands against the no-op column of the same variant");

        print_benchmark(afl_pc, afl_pc_boost);

        bench_become_normal();

        return EXIT_SUCCESS;
    }

    do_bench(&pthread_protect);

    print_benchmark(afl_pc_boost, pthread_protect);

    error = pthread_mutex_destroy(&pm_protect);

    if (error != 0)
        print_benchmark_note("could not destroy the pthread priority protect mutex: %s", strerror(error));

    bench_become_normal();

    return EXIT_SUCCESS;
}
