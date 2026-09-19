/*
 * Test suite for afl.h
 *
 * Every test prints a single line and the exit status is non zero if any of
 * them failed. The tests cover the mutual exclusion that the locks promise, the
 * error codes of the owner tracking variants, the blocking paths and the
 * condition variables: a lock or a condition variable that loses a wake up does
 * not return a wrong value, it hangs, so a watchdog turns a stuck test run into a
 * failure instead of a hung build.
 *
 * The sizes are taken from the environment:
 *
 *   AFL_TEST_THREADS     threads per contention test        (default 8)
 *   AFL_TEST_ITERATIONS  lock/unlock pairs per thread       (default 50000)
 *   AFL_TEST_TIMEOUT_MS  watchdog timeout of the whole run  (default 120000)
 */
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "afl.h"

#define TEST_THREADS_DEFAULT 8
#define TEST_ITERATIONS_DEFAULT 50000
#define TEST_TIMEOUT_MS_DEFAULT 120000
#define TEST_CRIT_SPINS_DEFAULT 20
#define TEST_MAX_THREADS 64

/* Critical section of the contention tests, in PAUSE iterations. The long one is
   longer than the spin phase of the locks, so that the waiters really block. */
#define TEST_CRIT_SPINS_LONG 200

static unsigned test_threads    = TEST_THREADS_DEFAULT;
static unsigned test_iterations = TEST_ITERATIONS_DEFAULT;
static unsigned test_timeout_ms = TEST_TIMEOUT_MS_DEFAULT;

static unsigned tests_passed;
static unsigned tests_failed;

/* Locks used by the contention tests. */
static afl_spinlock_t spinlock;
static afl_mutex_t mutex;
static afl_mutex_recursive_t recursive_mutex;

/* State shared by the contention tests. */
static _Atomic long counter;    /* successful acquisitions */
static _Atomic long inside;     /* threads currently inside the critical section */
static _Atomic long overlaps;   /* times a second thread was found inside */
static _Atomic long bad_return; /* lock/unlock calls that reported a failure */

static unsigned crit_spins = TEST_CRIT_SPINS_DEFAULT;

typedef void *(*thread_function_t)(void *);

static void test_pass(const char *name)
{
    tests_passed++;
    printf("  \033[0;32m[ ok ]\033[0m %s\n", name);
}

static void test_fail(const char *name, const char *format, ...)
{
    va_list args;

    tests_failed++;
    printf("  \033[0;31m[FAIL]\033[0m %s: ", name);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

#define CHECK(name, condition, ...)       \
    do {                                  \
        if (condition) {                  \
            test_pass(name);              \
        } else {                          \
            test_fail(name, __VA_ARGS__); \
        }                                 \
    } while (0)

#define CHECK_TRUE(name, condition) CHECK(name, (condition), "condition is false")
#define CHECK_EQ(name, got, want) CHECK(name, (got) == (int) (want), "expected %d, got %d", (int) (want), (int) (got))

/*
 * A lock that loses a wake up hangs instead of returning an error, so the whole
 * run is put under a watchdog: it aborts with a failure instead of keeping a CI
 * job busy forever.
 */
static void *watchdog(void *arg)
{
    struct timespec delay;

    (void) arg;

    delay.tv_sec  = (time_t) (test_timeout_ms / 1000);
    delay.tv_nsec = (long) (test_timeout_ms % 1000) * 1000000L;

    nanosleep(&delay, NULL);

    fprintf(stderr, "\n  \033[0;31m[FAIL]\033[0m the test suite did not finish within %u ms\n", test_timeout_ms);
    fflush(NULL);
    _exit(EXIT_FAILURE);
}

static int start_threads(pthread_t *thread, unsigned threads, thread_function_t function, void **args)
{
    for (unsigned i = 0; i < threads; i++) {
        void *arg = args ? args[i] : NULL;

        if (pthread_create(&thread[i], NULL, function, arg) != 0) {
            for (unsigned j = 0; j < i; j++)
                pthread_join(thread[j], NULL);
            return -1;
        }
    }

    return 0;
}

static void join_threads(pthread_t *thread, unsigned threads)
{
    for (unsigned i = 0; i < threads; i++)
        pthread_join(thread[i], NULL);
}

static int run_threads(unsigned threads, thread_function_t function, void **args)
{
    pthread_t thread[TEST_MAX_THREADS];

    if (threads > TEST_MAX_THREADS)
        threads = TEST_MAX_THREADS;

    if (start_threads(thread, threads, function, args) != 0)
        return -1;

    join_threads(thread, threads);

    return 0;
}

/*
 * The critical section of the contention tests. It reports an overlap when a
 * second thread is inside at the same time and spins for a while, so that the
 * other threads really do reach the lock while it is held.
 */
static void crit_enter(void)
{
    if (atomic_fetch_add_explicit(&inside, 1, memory_order_acq_rel) != 0)
        atomic_fetch_add_explicit(&overlaps, 1, memory_order_relaxed);

    atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);

    for (unsigned i = 0; i < crit_spins; i++)
        __afl_pause;
}

static void crit_leave(void)
{
    atomic_fetch_sub_explicit(&inside, 1, memory_order_acq_rel);
}

static void crit_reset(void)
{
    atomic_store(&counter, 0);
    atomic_store(&inside, 0);
    atomic_store(&overlaps, 0);
    atomic_store(&bad_return, 0);
}

/*
 * A worker that takes, uses and releases a single lock. A lock that hands itself
 * out twice is caught by the overlap counter, a lock that reports a failure for a
 * call that has to succeed by the bad return counter.
 */
#define DEFINE_CONTENTION_WORKER(name, LOCK, UNLOCK)                             \
    static void *worker_##name(void *arg)                                        \
    {                                                                            \
        (void) arg;                                                              \
                                                                                 \
        for (unsigned i = 0; i < test_iterations; i++) {                         \
            if ((LOCK) != 0) {                                                   \
                atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed); \
                continue;                                                        \
            }                                                                    \
            crit_enter();                                                        \
            crit_leave();                                                        \
            if ((UNLOCK) != 0)                                                   \
                atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed); \
        }                                                                        \
                                                                                 \
        return NULL;                                                             \
    }

/*
 * Contention tests. Every worker increments the counter with the lock held, so a
 * lock that is handed out twice shows up as an overlap, and a lock that reports a
 * failure for a call that has to succeed shows up as a bad return.
 */
DEFINE_CONTENTION_WORKER(spinlock, afl_spin_lock(&spinlock), afl_spin_unlock(&spinlock))
DEFINE_CONTENTION_WORKER(spinlock_owner, afl_spin_owner_lock(&spinlock), afl_spin_owner_unlock(&spinlock))
DEFINE_CONTENTION_WORKER(mutex, afl_mutex_lock(&mutex), afl_mutex_unlock(&mutex))
DEFINE_CONTENTION_WORKER(mutex_owner, afl_mutex_owner_lock(&mutex), afl_mutex_owner_unlock(&mutex))
DEFINE_CONTENTION_WORKER(mutex_pi, afl_mutex_pi_lock(&mutex), afl_mutex_pi_unlock(&mutex))

/* The recursive mutex is taken twice per iteration, so one of them has to nest. */
static void *worker_mutex_recursive(void *arg)
{
    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (afl_mutex_recursive_lock(&recursive_mutex) != 0 || afl_mutex_recursive_lock(&recursive_mutex) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            continue;
        }

        crit_enter();
        crit_leave();

        if (afl_mutex_recursive_unlock(&recursive_mutex) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
        if (afl_mutex_recursive_unlock(&recursive_mutex) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
    }

    return NULL;
}

/*
 * The owner tracking locks have to reject a release by a thread that does not own
 * them, and the rejected release must not disturb the lock.
 */
static _Atomic int foreign_return;

static void *worker_foreign_spin_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_spin_owner_unlock((afl_spinlock_t *) arg));

    return NULL;
}

static void *worker_foreign_plain_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_unlock((afl_mutex_t *) arg));

    return NULL;
}

static void *worker_foreign_mutex_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_owner_unlock((afl_mutex_t *) arg));

    return NULL;
}

static void *worker_foreign_recursive_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_recursive_unlock((afl_mutex_recursive_t *) arg));

    return NULL;
}

static int run_foreign_unlock(thread_function_t function, void *lock)
{
    void *args[1] = {lock};

    atomic_store(&foreign_return, 0);

    return run_threads(1, function, args);
}

static void check_mutual_exclusion(const char *name, thread_function_t function, unsigned threads)
{
    long expected = (long) threads * (long) test_iterations;

    crit_reset();

    if (run_threads(threads, function, NULL) != 0) {
        test_fail(name, "could not create %u threads", threads);
        return;
    }

    CHECK(
      name, atomic_load(&overlaps) == 0 && atomic_load(&bad_return) == 0 && atomic_load(&counter) == expected,
      "counter %ld/%ld, overlaps %ld, bad returns %ld", atomic_load(&counter), expected, atomic_load(&overlaps),
      atomic_load(&bad_return)
    );
}

static void test_spinlock(void)
{
    afl_spinlock_t s;

    CHECK_EQ("spinlock: init", afl_spin_init(&s, 0), 0);
    CHECK_EQ("spinlock: uncontended lock", afl_spin_lock(&s), 0);
    CHECK_EQ("spinlock: unlock", afl_spin_unlock(&s), 0);
    CHECK_EQ("spinlock: lock again after the unlock", afl_spin_lock(&s), 0);
    CHECK_EQ("spinlock: unlock again", afl_spin_unlock(&s), 0);
    CHECK_EQ("spinlock: destroy", afl_spin_destroy(&s), 0);

    /* A destroyed lock is left in the free state, so it can be used again. */
    CHECK_EQ("spinlock: the lock is free after the destroy", afl_spin_owner_lock(&s), 0);
    CHECK_EQ("spinlock: unlock after the destroy", afl_spin_owner_unlock(&s), 0);

    /* The shared flag is accepted, the locks are futex private either way. */
    CHECK_EQ("spinlock: init with the shared flag", afl_spin_init(&s, 1), 0);
    CHECK_EQ("spinlock: lock after a shared init", afl_spin_lock(&s), 0);
    CHECK_EQ("spinlock: unlock after a shared init", afl_spin_unlock(&s), 0);
}

static void test_spinlock_owner(void)
{
    afl_spinlock_t s;

    afl_spin_init(&s, 0);

    CHECK_EQ("spinlock owner: first lock", afl_spin_owner_lock(&s), 0);
    CHECK_EQ("spinlock owner: relock by the owner reports EDEADLOCK", afl_spin_owner_lock(&s), EDEADLOCK);

    /*
     * The rejected relock must not have touched the lock: the owner still has to
     * be able to release it and the lock has to be usable afterwards.
     */
    CHECK_EQ("spinlock owner: unlock after the rejected relock", afl_spin_owner_unlock(&s), 0);
    CHECK_EQ("spinlock owner: unlock of an unlocked lock reports EPERM", afl_spin_owner_unlock(&s), EPERM);
    CHECK_EQ("spinlock owner: the lock still works", afl_spin_owner_lock(&s), 0);
    CHECK_TRUE(
      "spinlock owner: a foreign thread can not release it",
      run_foreign_unlock(worker_foreign_spin_unlock, &s) == 0 && atomic_load(&foreign_return) == EPERM
    );
    CHECK_EQ("spinlock owner: final unlock", afl_spin_owner_unlock(&s), 0);
}

static void test_mutex(void)
{
    afl_mutex_t m = AFL_MUTEX_INIT;

    CHECK_TRUE("mutex: the init macro is the free value", __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_UNLOCKED);
    CHECK_EQ("mutex: uncontended lock", afl_mutex_lock(&m), 0);
    CHECK_TRUE(
      "mutex: the uncontended fast path leaves the waiters bit clear",
      (__atomic_load_n(&m, __ATOMIC_RELAXED) & AFL_HAVE_WAITERS) == 0
    );
    CHECK_EQ("mutex: unlock", afl_mutex_unlock(&m), 0);
    CHECK_TRUE("mutex: unlock restores the free value", __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_UNLOCKED);
    CHECK_EQ("mutex: lock again after the unlock", afl_mutex_lock(&m), 0);
    CHECK_EQ("mutex: unlock again", afl_mutex_unlock(&m), 0);
    CHECK_EQ("mutex: destroy", afl_mutex_destroy(&m), 0);
    CHECK_TRUE("mutex: the destroyed mutex is free", __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_UNLOCKED);

    /*
     * This variant has no owner tracking, so a different thread is allowed to
     * release it. Only the owner tracked variants reject that.
     */
    CHECK_EQ("mutex: lock without owner tracking", afl_mutex_lock(&m), 0);
    CHECK_TRUE(
      "mutex: a foreign thread may release it (there is no owner tracking)",
      run_foreign_unlock(worker_foreign_plain_unlock, &m) == 0 && atomic_load(&foreign_return) == 0
    );
}

static void test_mutex_owner(void)
{
    afl_mutex_t m = AFL_MUTEX_INIT;

    CHECK_EQ("mutex owner: first lock", afl_mutex_owner_lock(&m), 0);
    CHECK_EQ("mutex owner: relock by the owner reports EDEADLOCK", afl_mutex_owner_lock(&m), EDEADLOCK);
    CHECK_EQ("mutex owner: unlock after the rejected relock", afl_mutex_owner_unlock(&m), 0);
    CHECK_EQ("mutex owner: unlock of an unlocked mutex reports EPERM", afl_mutex_owner_unlock(&m), EPERM);
    CHECK_EQ("mutex owner: the mutex still works", afl_mutex_owner_lock(&m), 0);

    CHECK_TRUE(
      "mutex owner: a foreign thread can not release it",
      run_foreign_unlock(worker_foreign_mutex_unlock, &m) == 0 && atomic_load(&foreign_return) == EPERM
    );
    CHECK_EQ("mutex owner: the owner can still release it", afl_mutex_owner_unlock(&m), 0);
}

static void test_mutex_pi(void)
{
    afl_mutex_t m = AFL_MUTEX_INIT;

    CHECK_EQ("priority inheritance mutex: uncontended lock", afl_mutex_pi_lock(&m), 0);
    CHECK_EQ("priority inheritance mutex: relock by the owner reports EDEADLOCK", afl_mutex_pi_lock(&m), EDEADLOCK);
    CHECK_EQ("priority inheritance mutex: unlock after the rejected relock", afl_mutex_pi_unlock(&m), 0);
    CHECK_EQ("priority inheritance mutex: unlock of an unlocked mutex reports EPERM", afl_mutex_pi_unlock(&m), EPERM);
    CHECK_EQ("priority inheritance mutex: the mutex still works", afl_mutex_pi_lock(&m), 0);
    CHECK_EQ("priority inheritance mutex: final unlock", afl_mutex_pi_unlock(&m), 0);
}

static void test_mutex_recursive(void)
{
    const unsigned depth = 8;
    afl_mutex_recursive_t m;
    int rc = 0;

    afl_mutex_recursive_init(&m);

    CHECK_TRUE(
      "recursive mutex: init leaves the lock free",
      __atomic_load_n(&m.lock, __ATOMIC_RELAXED) == AFL_UNLOCKED && m.count == 0
    );

    for (unsigned i = 0; i < depth; i++)
        rc |= afl_mutex_recursive_lock(&m);

    CHECK_EQ("recursive mutex: nested acquisitions succeed", rc, 0);
    CHECK_TRUE("recursive mutex: the counter tracks the depth", m.count == depth);
    CHECK_TRUE(
      "recursive mutex: a nested acquisition leaves the waiters bit clear",
      (__atomic_load_n(&m.lock, __ATOMIC_RELAXED) & AFL_HAVE_WAITERS) == 0
    );

    rc = 0;
    for (unsigned i = 0; i < depth; i++)
        rc |= afl_mutex_recursive_unlock(&m);

    CHECK_EQ("recursive mutex: nested releases succeed", rc, 0);
    CHECK_TRUE(
      "recursive mutex: the lock is free after the last release",
      __atomic_load_n(&m.lock, __ATOMIC_RELAXED) == AFL_UNLOCKED && m.count == 0
    );

    CHECK_EQ("recursive mutex: lock after the last release", afl_mutex_recursive_lock(&m), 0);
    CHECK_TRUE(
      "recursive mutex: a foreign thread can not release it",
      run_foreign_unlock(worker_foreign_recursive_unlock, &m) == 0 && atomic_load(&foreign_return) == EPERM
    );
    CHECK_EQ("recursive mutex: the owner can still release it", afl_mutex_recursive_unlock(&m), 0);
    CHECK_EQ("recursive mutex: destroy", afl_mutex_recursive_destroy(&m), 0);
}

/*
 * afl_once
 */
#define TEST_ONCE_CALLS 32
#define TEST_ONCE_INIT_US 20000

static afl_once_t once_control = AFL_ONCE_INIT;
static _Atomic long once_runs;
static _Atomic long once_ready;
static _Atomic long once_calls;
static long once_observed[TEST_MAX_THREADS];

static void once_initializer(void)
{
    /* Slow on purpose: all the other threads have to wait for it. */
    usleep(TEST_ONCE_INIT_US);

    atomic_store_explicit(&once_ready, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&once_runs, 1, memory_order_relaxed);
}

static void *worker_once(void *arg)
{
    long *observed = arg;

    for (unsigned i = 0; i < TEST_ONCE_CALLS; i++) {
        if (afl_once(&once_control, once_initializer) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
    }

    /*
     * afl_once pairs the writes of the initializer with an acquire, so what the
     * initializer published has to be visible here, including for the threads
     * that had to wait for it.
     */
    if (atomic_load_explicit(&once_ready, memory_order_relaxed) == 1)
        *observed = 1;

    atomic_fetch_add_explicit(&once_calls, 1, memory_order_relaxed);

    return NULL;
}

static void test_once(void)
{
    void *args[TEST_MAX_THREADS];
    unsigned threads  = test_threads > TEST_MAX_THREADS ? TEST_MAX_THREADS : test_threads;
    unsigned observed = 0;

    atomic_store(&bad_return, 0);
    atomic_store(&once_runs, 0);
    atomic_store(&once_ready, 0);
    atomic_store(&once_calls, 0);
    memset(once_observed, 0, sizeof(once_observed));

    for (unsigned i = 0; i < threads; i++)
        args[i] = &once_observed[i];

    if (run_threads(threads, worker_once, args) != 0) {
        test_fail("once: racers", "could not create %u threads", threads);
        return;
    }

    for (unsigned i = 0; i < threads; i++)
        if (once_observed[i] == 1)
            observed++;

    CHECK_EQ("once: the initializer ran exactly once", once_runs, 1);
    CHECK_EQ("once: every call returned success", bad_return, 0);
    CHECK_EQ("once: every thread went through it", once_calls, threads);
    CHECK_EQ("once: the initialization is visible to every thread", observed, threads);
}

/*
 * afl_cond
 *
 * A condition variable hands off a wake up instead of a lock, so the tests are
 * about the two ways that can go wrong: the wake up is missed, in which case the
 * waiter sleeps until the watchdog kills the run, or it is handed out to the
 * wrong number of waiters, one signal that wakes two threads or a broadcast that
 * leaves one behind.
 */
#define TEST_COND_SIGNAL_MS 50
#define TEST_COND_TIMED_MS 2000
#define TEST_WAIT_SPINS 100000000L

static afl_cond_t cond        = AFL_COND_INIT;
static afl_mutex_t cond_mutex = AFL_MUTEX_INIT;
static _Atomic long cond_ready; /* the predicate the waiters wait for */
static _Atomic long cond_woken; /* waits that returned and released the mutex */

/*
 * One condition variable per thread. A signal is addressed to a single condition
 * variable, so a signal that wakes more than its own waiter shows up as a second
 * thread that returns from a condition variable nobody signalled.
 *
 * The header aligns a condition variable to a cache line, and an array of a type
 * like that needs elements whose size is a multiple of that alignment, which the
 * raw type is not: only the array needs the slot, a single condition variable is
 * used as it comes.
 */
#define TEST_COND_SLOT_SIZE 64

typedef struct
{
    afl_cond_t cond;
    unsigned char padding[TEST_COND_SLOT_SIZE - sizeof(afl_cond_t)];
} cond_slot_t;

static cond_slot_t cond_single[TEST_MAX_THREADS];
static _Atomic long cond_single_ready[TEST_MAX_THREADS];
static _Atomic long cond_single_done[TEST_MAX_THREADS];

/*
 * Spin until a counter reaches a value. The watchdog of the suite is the real
 * backstop against a lost wake up, the bound only keeps a stuck test from
 * sitting in a spin loop for the whole timeout.
 */
static int wait_for(_Atomic long *value, long wanted)
{
    for (long i = 0; i < TEST_WAIT_SPINS; i++) {
        if (atomic_load_explicit(value, memory_order_relaxed) == wanted)
            return 0;

        __afl_pause;
    }

    return -1;
}

static struct timespec deadline_after(long milliseconds)
{
    struct timespec deadline;

    clock_gettime(CLOCK_MONOTONIC, &deadline);

    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (milliseconds % 1000) * 1000000L;

    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_nsec -= 1000000000L;
        deadline.tv_sec++;
    }

    if (deadline.tv_nsec < 0) {
        deadline.tv_nsec += 1000000000L;
        deadline.tv_sec--;
    }

    return deadline;
}

static unsigned elapsed_ms(const struct timespec *start)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    return (unsigned) ((now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000);
}

/*
 * A signaller that takes the mutex first and only then sleeps and signals. The
 * lock has to come first: a waiter registers itself while it still holds the
 * mutex, so a signaller that has acquired the mutex knows that the waiter is
 * registered and cannot miss it. The sleep makes the wake up arrive while the
 * waiter is really asleep.
 */
static unsigned cond_signal_after_ms;

static void *worker_cond_signal_after(void *arg)
{
    struct timespec delay;

    (void) arg;

    if (afl_mutex_lock(&cond_mutex) != 0) {
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
        return NULL;
    }

    delay.tv_sec  = cond_signal_after_ms / 1000;
    delay.tv_nsec = (long) (cond_signal_after_ms % 1000) * 1000000L;
    nanosleep(&delay, NULL);

    atomic_store_explicit(&cond_ready, 1, memory_order_relaxed);

    if (afl_cond_signal(&cond) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    if (afl_mutex_unlock(&cond_mutex) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    return NULL;
}

static void test_cond_state(void)
{
    afl_cond_t c = AFL_COND_INIT;

    CHECK_TRUE("cond: AFL_COND_INIT starts with no signal and no waiter", c.sequence == 0 && c.waiters == 0);

    CHECK_EQ("cond: init", afl_cond_init(&c), 0);
    CHECK_EQ("cond: signal with nobody waiting", afl_cond_signal(&c), 0);
    CHECK_EQ("cond: broadcast with nobody waiting", afl_cond_broadcast(&c), 0);

    /*
     * The sequence number is the futex word of the condition variable, so a wake
     * up that has nobody to receive it has to leave the word alone: that is what
     * keeps the common "the predicate is already true" case out of the kernel.
     */
    CHECK_TRUE("cond: a wake up that nobody receives does not reach the futex", c.sequence == 0 && c.waiters == 0);

    CHECK_EQ("cond: destroy", afl_cond_destroy(&c), 0);
    CHECK_TRUE("cond: destroy resets the condition variable", c.sequence == 0 && c.waiters == 0);
}

static void *worker_cond_broadcast(void *arg)
{
    (void) arg;

    if (afl_mutex_lock(&cond_mutex) != 0) {
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
        return NULL;
    }

    while (atomic_load_explicit(&cond_ready, memory_order_relaxed) == 0) {
        if (afl_cond_wait(&cond, &cond_mutex) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            break;
        }
    }

    /*
     * The wait has to come back with the mutex held, so the critical section
     * below is the same mutual exclusion test that the locks go through.
     */
    crit_enter();
    crit_leave();

    atomic_fetch_add_explicit(&cond_woken, 1, memory_order_relaxed);

    if (afl_mutex_unlock(&cond_mutex) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    return NULL;
}

static void test_cond_broadcast(void)
{
    pthread_t thread[TEST_MAX_THREADS];
    unsigned threads = test_threads > TEST_MAX_THREADS ? TEST_MAX_THREADS : test_threads;

    afl_cond_init(&cond);
    afl_mutex_destroy(&cond_mutex); /* leaves the mutex in the free state */
    crit_reset();
    atomic_store(&cond_ready, 0);
    atomic_store(&cond_woken, 0);
    atomic_store(&bad_return, 0);

    if (start_threads(thread, threads, worker_cond_broadcast, NULL) != 0) {
        test_fail("cond: broadcast", "could not create %u threads", threads);
        return;
    }

    /* Everybody has to be registered before the wake up is sent. */
    for (long i = 0; i < TEST_WAIT_SPINS; i++) {
        if (__atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == threads)
            break;

        __afl_pause;
    }

    CHECK_TRUE(
      "cond: every thread is inside afl_cond_wait", __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == threads
    );
    CHECK_EQ("cond: nobody left before the wake up", cond_woken, 0);

    if (afl_mutex_lock(&cond_mutex) != 0) {
        test_fail("cond: broadcast", "could not take the mutex");
        join_threads(thread, threads);
        return;
    }

    atomic_store(&cond_ready, 1);
    CHECK_EQ("cond: broadcast", afl_cond_broadcast(&cond), 0);
    afl_mutex_unlock(&cond_mutex);

    join_threads(thread, threads);

    CHECK_EQ("cond: the broadcast woke every waiter", cond_woken, threads);
    CHECK_EQ("cond: every wait returned success", bad_return, 0);
    CHECK_EQ("cond: the waiters were serialized by the mutex", overlaps, 0);
    CHECK_EQ("cond: the waiter count is back to zero", cond.waiters, 0);
}

/*
 * One signal per condition variable, so the number of threads that come back is
 * the number of wake ups that were really delivered.
 */
static void *worker_cond_single(void *arg)
{
    unsigned id = (unsigned) (uintptr_t) arg;

    if (afl_mutex_lock(&cond_mutex) != 0) {
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
        return NULL;
    }

    while (atomic_load_explicit(&cond_single_ready[id], memory_order_relaxed) == 0) {
        if (afl_cond_wait(&cond_single[id].cond, &cond_mutex) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            break;
        }
    }

    atomic_fetch_add_explicit(&cond_woken, 1, memory_order_relaxed);
    atomic_store_explicit(&cond_single_done[id], 1, memory_order_relaxed);

    if (afl_mutex_unlock(&cond_mutex) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    return NULL;
}

static void test_cond_signal(void)
{
    const unsigned threads = 4;
    const unsigned target  = 2;
    pthread_t thread[4];
    void *args[4];
    unsigned woke_others = 0;

    for (unsigned i = 0; i < threads; i++) {
        afl_cond_init(&cond_single[i].cond);
        atomic_store(&cond_single_ready[i], 0);
        atomic_store(&cond_single_done[i], 0);
        args[i] = (void *) (uintptr_t) i;
    }

    afl_mutex_destroy(&cond_mutex);
    atomic_store(&cond_woken, 0);
    atomic_store(&bad_return, 0);

    if (start_threads(thread, threads, worker_cond_single, args) != 0) {
        test_fail("cond: signal", "could not create %u threads", threads);
        return;
    }

    for (long i = 0; i < TEST_WAIT_SPINS; i++) {
        unsigned waiting = 0;

        for (unsigned t = 0; t < threads; t++)
            waiting += __atomic_load_n(&cond_single[t].cond.waiters, __ATOMIC_RELAXED);

        if (waiting == threads)
            break;

        __afl_pause;
    }

    /* Exactly one wake up, so exactly one thread may come back. */
    if (afl_mutex_lock(&cond_mutex) != 0) {
        test_fail("cond: signal", "could not take the mutex");
        join_threads(thread, threads);
        return;
    }

    atomic_store(&cond_single_ready[target], 1);
    CHECK_EQ("cond: signal", afl_cond_signal(&cond_single[target].cond), 0);
    afl_mutex_unlock(&cond_mutex);

    CHECK_EQ("cond: a signal wakes its own waiter", wait_for(&cond_single_done[target], 1), 0);

    for (unsigned t = 0; t < threads; t++)
        if (t != target && atomic_load_explicit(&cond_single_done[t], memory_order_relaxed) != 0)
            woke_others++;

    CHECK_EQ("cond: a signal wakes exactly one waiter", woke_others, 0);

    /* Release the remaining waiters. */
    afl_mutex_lock(&cond_mutex);

    for (unsigned t = 0; t < threads; t++)
        atomic_store(&cond_single_ready[t], 1);

    for (unsigned t = 0; t < threads; t++)
        afl_cond_signal(&cond_single[t].cond);

    afl_mutex_unlock(&cond_mutex);

    join_threads(thread, threads);

    CHECK_EQ("cond: every waiter was released in the end", cond_woken, threads);
    CHECK_EQ("cond: every wait returned success", bad_return, 0);
}

static void test_cond_timedwait(void)
{
    struct timespec start, deadline;
    pthread_t signaller;
    int signaled;

    afl_cond_init(&cond);
    afl_mutex_destroy(&cond_mutex);
    atomic_store(&cond_ready, 0);
    atomic_store(&bad_return, 0);

    CHECK_EQ("cond: lock for the timed waits", afl_mutex_lock(&cond_mutex), 0);

    /* A deadline that is already behind reports the timeout without waiting. */
    deadline = deadline_after(-1);
    CHECK_EQ(
      "cond: an expired timed wait reports ETIMEDOUT", afl_cond_timedwait(&cond, &cond_mutex, &deadline), ETIMEDOUT
    );
    CHECK_TRUE(
      "cond: an expired timed wait does not register a waiter", __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
    );
    CHECK_TRUE(
      "cond: the mutex is still held after the expired timed wait",
      __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );

    /* Nothing signals this one, so it has to sleep until its own deadline. */
    start    = deadline_after(0);
    deadline = deadline_after(TEST_COND_SIGNAL_MS);
    signaled = afl_cond_timedwait(&cond, &cond_mutex, &deadline);

    CHECK_EQ("cond: a timed wait that nobody signals reports ETIMEDOUT", signaled, ETIMEDOUT);
    CHECK_TRUE("cond: the timed wait slept for its timeout", elapsed_ms(&start) >= TEST_COND_SIGNAL_MS);
    CHECK_TRUE(
      "cond: a timed out waiter is removed from the condition variable",
      __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
    );

    /* A signal before the deadline returns success well before it expires. */
    start                = deadline_after(0);
    deadline             = deadline_after(TEST_COND_TIMED_MS);
    cond_signal_after_ms = TEST_COND_SIGNAL_MS;

    if (start_threads(&signaller, 1, worker_cond_signal_after, NULL) != 0) {
        test_fail("cond: timed wait", "could not create the signaller thread");
    } else {
        signaled = afl_cond_timedwait(&cond, &cond_mutex, &deadline);

        CHECK_EQ("cond: a timed wait that is signalled returns success", signaled, 0);
        CHECK_TRUE(
          "cond: the signalled timed wait returned before its deadline", elapsed_ms(&start) < TEST_COND_TIMED_MS / 4
        );
        join_threads(&signaller, 1);
    }

    CHECK_TRUE(
      "cond: the mutex is held after the signalled timed wait",
      __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );
    CHECK_EQ("cond: the signaller did not report a failure", bad_return, 0);
    CHECK_EQ("cond: final unlock", afl_mutex_unlock(&cond_mutex), 0);
}

/*
 * The suite is sized from the environment so that a slow or a busy machine can
 * trade coverage for time without a rebuild.
 */
static unsigned env_unsigned(const char *name, unsigned fallback)
{
    const char *value = getenv(name);
    long parsed;

    if (value == NULL || *value == '\0')
        return fallback;

    parsed = strtol(value, NULL, 10);

    return parsed > 0 ? (unsigned) parsed : fallback;
}

int main(void)
{
    pthread_t watchdog_id;
    unsigned cores = (unsigned) sysconf(_SC_NPROCESSORS_ONLN);
    unsigned parked_threads;
    unsigned parked_iterations;

    test_threads    = env_unsigned("AFL_TEST_THREADS", TEST_THREADS_DEFAULT);
    test_iterations = env_unsigned("AFL_TEST_ITERATIONS", TEST_ITERATIONS_DEFAULT);
    test_timeout_ms = env_unsigned("AFL_TEST_TIMEOUT_MS", TEST_TIMEOUT_MS_DEFAULT);

    /* More threads than cores, so that the waiters really do get parked. */
    parked_threads    = cores * 3;
    parked_iterations = test_iterations / 10 ? test_iterations / 10 : 1;

    printf(
      "afl.h test suite: %u threads, %u iterations, %u ms timeout, %u cores\n", test_threads, test_iterations,
      test_timeout_ms, cores
    );
    printf("run it under more pressure with: AFL_TEST_THREADS=64 AFL_TEST_ITERATIONS=200000 make check\n\n");

    if (pthread_create(&watchdog_id, NULL, watchdog, NULL) != 0) {
        fprintf(stderr, "could not start the watchdog thread\n");
        return EXIT_FAILURE;
    }
    pthread_detach(watchdog_id);

    /* Return values, error codes and the state of the lock words. */
    test_spinlock();
    test_spinlock_owner();
    test_mutex();
    test_mutex_owner();
    test_mutex_pi();
    test_mutex_recursive();

    /* Mutual exclusion while every thread hammers the same lock. */
    afl_spin_init(&spinlock, 0);
    afl_mutex_destroy(&mutex); /* leaves the mutex in the free state */
    afl_mutex_recursive_init(&recursive_mutex);

    check_mutual_exclusion("spinlock: mutual exclusion under contention", worker_spinlock, test_threads);
    check_mutual_exclusion("spinlock owner: mutual exclusion under contention", worker_spinlock_owner, test_threads);
    check_mutual_exclusion("mutex: mutual exclusion under contention", worker_mutex, test_threads);
    check_mutual_exclusion("mutex owner: mutual exclusion under contention", worker_mutex_owner, test_threads);
    check_mutual_exclusion(
      "priority inheritance mutex: mutual exclusion under contention", worker_mutex_pi, test_threads
    );
    check_mutual_exclusion(
      "recursive mutex: mutual exclusion under contention (nested)", worker_mutex_recursive, test_threads
    );

    /*
     * Parked hand off: more threads than cores and a critical section that is
     * longer than the spin phase of the locks, so the waiters block on the futex
     * and the wake up chain is what is being tested. A lost wake up does not
     * return a wrong value, it hangs, which the watchdog reports as a failure.
     */
    crit_spins      = TEST_CRIT_SPINS_LONG;
    test_iterations = parked_iterations;

    check_mutual_exclusion("mutex: mutual exclusion with parked waiters", worker_mutex, parked_threads);
    check_mutual_exclusion("mutex owner: mutual exclusion with parked waiters", worker_mutex_owner, parked_threads);
    check_mutual_exclusion(
      "recursive mutex: mutual exclusion with parked waiters", worker_mutex_recursive, parked_threads
    );

    crit_spins = TEST_CRIT_SPINS_DEFAULT;

    /* One shot initialization. */
    test_once();

    /* Condition variables: the hand off of a wake up. */
    test_cond_state();
    test_cond_broadcast();
    test_cond_signal();
    test_cond_timedwait();

    printf("\n  %u passed, %u failed\n", tests_passed, tests_failed);
    printf("  %s\n\n", tests_failed ? "\033[0;31mFAIL\033[0m" : "\033[0;32mPASS\033[0m");

    return tests_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
