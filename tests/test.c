/*
 * Test suite for afl.h
 *
 * Every test prints a single line, with how long the check took, and the exit
 * status is non zero if any of them failed. The tests cover the mutual exclusion
 * that the locks promise, the error codes of the owner tracking variants, the
 * non blocking answers of the trylocks, the destroy semantics, the blocking
 * paths and the condition variables: a lock or a
 * condition variable that loses a wake up does not return a wrong value, it
 * hangs, so a watchdog turns a stuck test run into a failure instead of a hung
 * build.
 *
 * The sizes are taken from the environment:
 *
 *   AFL_TEST_THREADS     threads per contention test        (default 8)
 *   AFL_TEST_ITERATIONS  lock/unlock pairs per thread       (default 50000)
 *   AFL_TEST_TIMEOUT_MS  watchdog timeout of the whole run  (default 120000)
 *
 * A build with -DAFL_DEBUG (make check-debug) additionally runs the misuse cases
 * with stderr captured and asserts that the header reports each of them.
 */
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "afl.h"
#include "afl_thread.h"

/* Each Makefile target supplies its expected backend independently of detection. */
#ifdef AFL_TEST_EXPECT_PTHREAD
_Static_assert(__AFL_THREAD_WITH_PTHREAD == AFL_TEST_EXPECT_PTHREAD, "unexpected thread backend");
#endif

#define TEST_THREADS_DEFAULT    8
#define TEST_ITERATIONS_DEFAULT 50000
#define TEST_TIMEOUT_MS_DEFAULT 120000
#define TEST_CRIT_SPINS_DEFAULT 20
#define TEST_MAX_THREADS        64

/* The compiler this translation unit was built with, for the header line. */
#if defined(__clang__)
#define TEST_COMPILER "clang " __clang_version__
#elif defined(__GNUC__)
#define TEST_COMPILER "gcc " __VERSION__
#else
#define TEST_COMPILER "unknown compiler"
#endif

/* Critical section of the contention tests, in PAUSE iterations. The long one is
   longer than the spin phase of the locks, so that the waiters really block. */
#define TEST_CRIT_SPINS_LONG 200

static unsigned test_threads = TEST_THREADS_DEFAULT;
static unsigned test_iterations = TEST_ITERATIONS_DEFAULT;
static unsigned test_timeout_ms = TEST_TIMEOUT_MS_DEFAULT;

static unsigned tests_passed;
static unsigned tests_failed;

/* Locks used by the contention tests. */
static afl_spinlock_t spinlock;
static afl_mutex_t mutex;
static afl_mutex_recursive_t recursive_mutex;
static afl_mutex_adaptive_t adaptive_mutex;
static afl_mutex_pc_t pc_mutex = AFL_MUTEX_PC_INIT;

/* State shared by the contention tests. */
static _Atomic long counter;    /* successful acquisitions */
static _Atomic long inside;     /* threads currently inside the critical section */
static _Atomic long overlaps;   /* times a second thread was found inside */
static _Atomic long bad_return; /* lock/unlock calls that reported a failure */

static unsigned crit_spins = TEST_CRIT_SPINS_DEFAULT;

typedef void *(*thread_function_t)(void *);

/*
 * Every check is timed, so a check that only passes because it slept or spun for
 * an unexpectedly long time shows up in the log instead of hiding behind the
 * suite total. The clock is monotonic: a wall clock step would make the elapsed
 * time of a check meaningless.
 */
static struct timespec check_started;

static double elapsed_seconds(const struct timespec *start)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    return (double) (now.tv_sec - start->tv_sec) + (double) (now.tv_nsec - start->tv_nsec) / 1e9;
}

static void check_clock_restart(void)
{
    clock_gettime(CLOCK_MONOTONIC, &check_started);
}

static void test_pass(const char *name)
{
    double seconds = elapsed_seconds(&check_started);

    tests_passed++;
    printf("  \033[0;32m[ ok ]\033[0m %-64s %8.2f ms\n", name, seconds * 1000.0);
    check_clock_restart();
}

static void test_fail(const char *name, const char *format, ...)
{
    double seconds = elapsed_seconds(&check_started);
    va_list args;

    tests_failed++;
    printf("  \033[0;31m[FAIL]\033[0m %-64s %8.2f ms: ", name, seconds * 1000.0);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    check_clock_restart();
}

/* A check that is skipped because the machine cannot express it, counted apart
   from the pass/fail tally so that a skip never looks like a pass. */
static unsigned tests_skipped;

static void test_skip(const char *name, const char *format, ...)
{
    double seconds = elapsed_seconds(&check_started);
    va_list args;

    tests_skipped++;
    printf("  \033[0;33m[SKIP]\033[0m %-64s %8.2f ms: ", name, seconds * 1000.0);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    check_clock_restart();
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
#define CHECK_EQ(name, got, want)   CHECK(name, (got) == (int) (want), "expected %d, got %d", (int) (want), (int) (got))

/*
 * A lock that loses a wake up hangs instead of returning an error, so the whole
 * run is put under a watchdog: it aborts with a failure instead of keeping a CI
 * job busy forever.
 *
 * The interrupted wait test sends SIGALRM with tgkill, addressed to one
 * named thread, so this nanosleep is never the one that is cut short by it.
 */
static void watchdog(void *arg)
{
    struct timespec delay;

    (void) arg;

    delay.tv_sec = (time_t) (test_timeout_ms / 1000);
    delay.tv_nsec = (long) (test_timeout_ms % 1000) * 1000000L;

    nanosleep(&delay, NULL);

    fprintf(stderr, "\n  \033[0;31m[FAIL]\033[0m the test suite did not finish within %u ms\n", test_timeout_ms);
    fflush(NULL);
    _exit(EXIT_FAILURE);
}

/*
 * The thread functions of the suite have the libc shape, one void pointer in
 * and one out, and the layer calls a function of its own shape, so every
 * started thread carries its function and argument in one of these and one
 * trampoline of the layer's shape reads them back. The record is one heap
 * allocation per thread, freed by the thread itself the moment it has read it:
 * two calls of start_threads can have threads in flight at the same time (the
 * interrupted timed acquire starts its raiser while its holder still runs), so
 * a table of fixed slots shared by all calls would be rewritten under a running
 * thread.
 */
typedef struct
{
    thread_function_t function;
    void *argument;
} test_thread_start_t;

static void test_thread_entry(void *argument)
{
    test_thread_start_t *start = argument;
    thread_function_t function = start->function;
    void *inner = start->argument;

    free(start);

    (void) function(inner);
}

static int start_threads(afl_thread_t *thread, unsigned threads, thread_function_t function, void **args)
{
    for (unsigned i = 0; i < threads; i++) {
        test_thread_start_t *start = malloc(sizeof(*start));

        if (start == NULL) {
            for (unsigned j = 0; j < i; j++)
                afl_thread_join(&thread[j]);

            return -1;
        }

        start->function = function;
        start->argument = args ? args[i] : NULL;

        if (afl_thread_create(&thread[i], test_thread_entry, start) != 0) {
            free(start);

            for (unsigned j = 0; j < i; j++)
                afl_thread_join(&thread[j]);

            return -1;
        }
    }

    return 0;
}

static void join_threads(afl_thread_t *thread, unsigned threads)
{
    for (unsigned i = 0; i < threads; i++)
        afl_thread_join(&thread[i]);
}

static int run_threads(unsigned threads, thread_function_t function, void **args)
{
    afl_thread_t thread[TEST_MAX_THREADS];

    /*
     * No silent clamp: a run that asked for more threads than the suite can hold
     * has to fail loudly. Clamping here would also desynchronize the callers,
     * which compute the expected number of acquisitions from the count they asked
     * for.
     */
    if (threads > TEST_MAX_THREADS) {
        test_fail("thread pool", "asked for %u threads, the suite holds %d at most", threads, TEST_MAX_THREADS);
        return -1;
    }

    if (start_threads(thread, threads, function, args) != 0)
        return -1;

    join_threads(thread, threads);

    return 0;
}

typedef struct
{
    long kernel_tid;
    uint32_t first, repeated;
} tid_cache_result_t;

static void *worker_tid_cache(void *argument)
{
    tid_cache_result_t *result = argument;

    result->kernel_tid = __afl_syscall(__NR_gettid, 0, 0, 0, 0);
    if (result->kernel_tid <= 0)
        return NULL; /* The joined result reports the failed lookup. */

    result->first = __afl_gettid();
    result->repeated = __afl_gettid();
    return NULL;
}

static void test_tid_cache(void)
{
    static const char *const cases[] = {
      "thread id: first worker caches its own kernel id",
      "thread id: second worker caches its own kernel id",
      "thread id: third worker caches its own kernel id",
      "thread id: fourth worker caches its own kernel id",
    };
    tid_cache_result_t results[sizeof(cases) / sizeof(cases[0])] = {0};
    void *args[sizeof(cases) / sizeof(cases[0])];
    uint32_t parent = __afl_gettid();

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        args[i] = &results[i];

    /* All workers are joined before reading their results or leaving the stack
     * that owns them. A warm parent cache must not become a child's owner id. */
    int rc = run_threads(sizeof(cases) / sizeof(cases[0]), worker_tid_cache, args);
    CHECK_EQ("thread id: create and join cache workers", rc, 0);
    if (rc != 0)
        return;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK_TRUE(
          cases[i], results[i].kernel_tid > 0 && results[i].first == results[i].kernel_tid
                      && results[i].repeated == results[i].first && results[i].first != parent
        );
    }
    CHECK_TRUE("thread id: worker lookups preserve the parent cache", __afl_gettid() == parent);
}

/*
 * test_kill_thread sends sig to one named thread of this process, identified by
 * the kernel thread id afl_thread_self answers, which is what the interrupted
 * wait tests used pthread_kill for. The raw tgkill system call takes the
 * process (its thread group) and the thread as separate arguments, so a signal
 * lands on exactly one thread and never on another.
 */
static int test_kill_thread(unsigned long tid, int sig)
{
    return __afl_syscall(__NR_tgkill, (long) getpid(), (long) tid, (long) sig, 0) == 0 ? 0 : -1;
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

static _Atomic unsigned spin_mixed_next;

/* Both interfaces use the same word. A plain acquire must not overwrite a
 * racing owner's tid; each worker releases through the interface it took. */
static void *worker_spinlock_mixed(void *arg)
{
    static const struct
    {
        int (*lock)(afl_spinlock_t *);
        int (*unlock)(afl_spinlock_t *);
    } cases[] = {
      {afl_spin_lock,       afl_spin_unlock      },
      {afl_spin_owner_lock, afl_spin_owner_unlock},
    };
    unsigned which = atomic_fetch_add_explicit(&spin_mixed_next, 1, memory_order_relaxed) % 2;
    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (cases[which].lock(&spinlock) != 0) {
            atomic_fetch_add(&bad_return, 1);
            continue;
        }
        crit_enter();
        crit_leave();
        if (cases[which].unlock(&spinlock) != 0) {
            atomic_fetch_add(&bad_return, 1);
            /* This thread acquired the lock. Release a corrupted owner word
             * so the regression reports an error without stranding waiters. */
            if (afl_spin_unlock(&spinlock) != 0)
                atomic_fetch_add(&bad_return, 1);
        }
    }
    return NULL;
}

DEFINE_CONTENTION_WORKER(mutex, afl_mutex_lock(&mutex), afl_mutex_unlock(&mutex))
DEFINE_CONTENTION_WORKER(mutex_owner, afl_mutex_owner_lock(&mutex), afl_mutex_owner_unlock(&mutex))
DEFINE_CONTENTION_WORKER(mutex_pi, afl_mutex_pi_lock(&mutex), afl_mutex_pi_unlock(&mutex))
DEFINE_CONTENTION_WORKER(
  mutex_adaptive, afl_mutex_adaptive_lock(&adaptive_mutex), afl_mutex_adaptive_unlock(&adaptive_mutex)
)
DEFINE_CONTENTION_WORKER(mutex_pc, afl_mutex_pc_lock(&pc_mutex), afl_mutex_pc_unlock(&pc_mutex))

/*
 * The trylock stress worker, the trylock shape of DEFINE_CONTENTION_WORKER. A
 * trylock on a held lock answers the documented EBUSY rather than failing, so
 * the worker retries with the backoff of the header until the lock opens and
 * counts only anything else as a bad return; the acquisitions it does make run
 * the same overlap critical section as every other contention worker. The
 * shared locks are the same words the plain workers use, so a plain worker and
 * a try worker of one family also hammer each other.
 */
#define DEFINE_TRYLOCK_WORKER(name, TRY, UNLOCK)                                 \
    static void *worker_##name##_try(void *arg)                                  \
    {                                                                            \
        (void) arg;                                                              \
                                                                                 \
        for (unsigned i = 0; i < test_iterations; i++) {                         \
            __afl_spin_backoff_t backoff;                                        \
            int error;                                                           \
                                                                                 \
            __afl_spin_backoff_init(&backoff);                                   \
                                                                                 \
            for (;;) {                                                           \
                error = (TRY);                                                   \
                if (error == 0 || error != EBUSY)                                \
                    break;                                                       \
                __afl_spin_backoff(&backoff);                                    \
            }                                                                    \
                                                                                 \
            if (error != 0) {                                                    \
                atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed); \
                continue;                                                        \
            }                                                                    \
                                                                                 \
            crit_enter();                                                        \
            crit_leave();                                                        \
                                                                                 \
            if ((UNLOCK) != 0)                                                   \
                atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed); \
        }                                                                        \
                                                                                 \
        return NULL;                                                             \
    }

DEFINE_TRYLOCK_WORKER(spinlock, afl_spin_trylock(&spinlock), afl_spin_unlock(&spinlock))
DEFINE_TRYLOCK_WORKER(spinlock_owner, afl_spin_owner_trylock(&spinlock), afl_spin_owner_unlock(&spinlock))
DEFINE_TRYLOCK_WORKER(mutex, afl_mutex_trylock(&mutex), afl_mutex_unlock(&mutex))
DEFINE_TRYLOCK_WORKER(mutex_owner, afl_mutex_owner_trylock(&mutex), afl_mutex_owner_unlock(&mutex))
DEFINE_TRYLOCK_WORKER(mutex_pi, afl_mutex_pi_trylock(&mutex), afl_mutex_pi_unlock(&mutex))
DEFINE_TRYLOCK_WORKER(
  mutex_recursive, afl_mutex_recursive_trylock(&recursive_mutex), afl_mutex_recursive_unlock(&recursive_mutex)
)

/*
 * The trylock stress worker. EBUSY is the documented answer of a trylock on a
 * held mutex, so instead of treating it as a failure the worker retries with
 * the backoff of the header until the mutex opens; anything else it returns is
 * a bad return, and the acquisitions it does make run the same overlap
 * critical section as every other contention worker.
 */
static void *worker_mutex_pc_try(void *arg)
{
    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        __afl_spin_backoff_t backoff;
        int error;

        __afl_spin_backoff_init(&backoff);

        for (;;) {
            error = afl_mutex_pc_trylock(&pc_mutex);

            if (error == 0)
                break;

            if (error != EBUSY) {
                atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
                break;
            }

            __afl_spin_backoff(&backoff);
        }

        if (error != 0)
            continue;

        crit_enter();
        crit_leave();

        if (afl_mutex_pc_unlock(&pc_mutex) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
    }

    return NULL;
}

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

static void *worker_foreign_pi_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_pi_unlock((afl_mutex_t *) arg));

    return NULL;
}

static void *worker_foreign_adaptive_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_adaptive_unlock((afl_mutex_adaptive_t *) arg));

    return NULL;
}

static void *worker_foreign_pc_unlock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_pc_unlock((afl_mutex_pc_t *) arg));

    return NULL;
}

static void *worker_foreign_pc_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_pc_trylock((afl_mutex_pc_t *) arg));

    return NULL;
}

/*
 * The foreign trylock workers: a trylock on a lock held by another thread is
 * refused with EBUSY and must leave the word exactly as it was, so the return
 * value is stored for the caller (the owner) to check, like for the foreign
 * releases.
 */
static void *worker_foreign_spin_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_spin_trylock((afl_spinlock_t *) arg));

    return NULL;
}

static void *worker_foreign_spin_owner_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_spin_owner_trylock((afl_spinlock_t *) arg));

    return NULL;
}

static void *worker_foreign_mutex_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_trylock((afl_mutex_t *) arg));

    return NULL;
}

static void *worker_foreign_mutex_owner_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_owner_trylock((afl_mutex_t *) arg));

    return NULL;
}

static void *worker_foreign_pi_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_pi_trylock((afl_mutex_t *) arg));

    return NULL;
}

static void *worker_foreign_recursive_trylock(void *arg)
{
    atomic_store(&foreign_return, afl_mutex_recursive_trylock((afl_mutex_recursive_t *) arg));

    return NULL;
}

/*
 * A foreign release has to be refused and has to leave the lock word exactly as
 * it was, so that the real owner can still release it. The caller of this
 * function is the owner in every use below.
 */
static int run_foreign_unlock(thread_function_t function, void *lock)
{
    void *args[1] = {lock};

    atomic_store(&foreign_return, 0);

    return run_threads(1, function, args);
}

/* The owner field of a lock word, that is the word without the waiters bit. */
static uint32_t lock_owner_of(const uint32_t *word)
{
    return __atomic_load_n(word, __ATOMIC_RELAXED) & AFL_TID_MASK;
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

    /*
     * The trylock of a free lock takes it with one exchange; a lock that
     * shows a holder is refused with EBUSY without a write, by this thread
     * as well as by a foreign one.
     */
    CHECK_EQ("spinlock: trylock of a free lock succeeds", afl_spin_trylock(&s), 0);
    CHECK_TRUE("spinlock: the trylock left the locked value", __atomic_load_n(&s, __ATOMIC_RELAXED) == AFL_LOCKED);
    CHECK_EQ("spinlock: trylock by the holder reports EBUSY", afl_spin_trylock(&s), EBUSY);
    CHECK_TRUE(
      "spinlock: the rejected trylock left the word alone",
      __atomic_load_n(&s, __ATOMIC_RELAXED) == AFL_LOCKED && afl_spin_unlock(&s) == 0
    );
    CHECK_EQ("spinlock: lock it for the foreign attempt", afl_spin_lock(&s), 0);
    CHECK_TRUE(
      "spinlock: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_spin_trylock, &s) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    CHECK_EQ("spinlock: unlock after the foreign trylock", afl_spin_unlock(&s), 0);
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

    /*
     * The owner trylock records the caller as the owner of a free lock and
     * refuses every hold with EBUSY - a foreign one and the caller's own
     * alike, unlike the EDEADLOCK of the blocking acquire - leaving the
     * word of the real owner alone.
     */
    CHECK_EQ("spinlock owner: trylock of a free lock succeeds", afl_spin_owner_trylock(&s), 0);
    CHECK_TRUE("spinlock owner: the trylock recorded the owner", lock_owner_of(&s) == __afl_gettid());
    CHECK_EQ("spinlock owner: trylock by the owner reports EBUSY", afl_spin_owner_trylock(&s), EBUSY);
    CHECK_TRUE("spinlock owner: the rejected trylock left the owner in the word", lock_owner_of(&s) == __afl_gettid());
    CHECK_TRUE(
      "spinlock owner: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_spin_owner_trylock, &s) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    CHECK_TRUE(
      "spinlock owner: the rejected foreign trylock left the owner in the word", lock_owner_of(&s) == __afl_gettid()
    );
    CHECK_EQ("spinlock owner: the owner can still release it", afl_spin_owner_unlock(&s), 0);
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
    afl_mutex_unlock(&m);

    /* The trylock follows the same word states as the blocking acquire. */
    CHECK_EQ("mutex: trylock of a free mutex succeeds", afl_mutex_trylock(&m), 0);
    CHECK_TRUE("mutex: the trylock left the locked value", __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_LOCKED);
    CHECK_EQ("mutex: trylock by the holder reports EBUSY", afl_mutex_trylock(&m), EBUSY);
    CHECK_TRUE(
      "mutex: the rejected trylock left the word alone",
      __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_LOCKED && afl_mutex_unlock(&m) == 0
    );
    CHECK_EQ("mutex: lock again for the foreign attempt", afl_mutex_lock(&m), 0);
    CHECK_TRUE(
      "mutex: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_mutex_trylock, &m) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    CHECK_TRUE(
      "mutex: the rejected foreign trylock left the word alone", __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_LOCKED
    );
    CHECK_EQ("mutex: unlock after the trylock sequence", afl_mutex_unlock(&m), 0);
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
    CHECK_TRUE(
      "mutex owner: the rejected foreign release left the owner in the word", lock_owner_of(&m) == __afl_gettid()
    );
    CHECK_EQ("mutex owner: the owner can still release it", afl_mutex_owner_unlock(&m), 0);
    CHECK_TRUE("mutex owner: the release left the word free", lock_owner_of(&m) == AFL_UNLOCKED);

    /* The owner trylock, with the same owner checks as the owner release. */
    CHECK_EQ("mutex owner: trylock of a free mutex succeeds", afl_mutex_owner_trylock(&m), 0);
    CHECK_TRUE("mutex owner: the trylock recorded the caller as the owner", lock_owner_of(&m) == __afl_gettid());
    CHECK_EQ("mutex owner: trylock by the owner reports EBUSY", afl_mutex_owner_trylock(&m), EBUSY);
    CHECK_TRUE("mutex owner: the rejected trylock left the owner in the word", lock_owner_of(&m) == __afl_gettid());
    CHECK_TRUE(
      "mutex owner: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_mutex_owner_trylock, &m) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    CHECK_EQ("mutex owner: the owner can still release after the trylocks", afl_mutex_owner_unlock(&m), 0);
}

static void test_mutex_pi(void)
{
    afl_mutex_t m = AFL_MUTEX_INIT;

    CHECK_EQ("priority inheritance mutex: uncontended lock", afl_mutex_pi_lock(&m), 0);
    CHECK_EQ("priority inheritance mutex: relock by the owner reports EDEADLOCK", afl_mutex_pi_lock(&m), EDEADLOCK);
    CHECK_EQ("priority inheritance mutex: unlock after the rejected relock", afl_mutex_pi_unlock(&m), 0);
    CHECK_EQ("priority inheritance mutex: unlock of an unlocked mutex reports EPERM", afl_mutex_pi_unlock(&m), EPERM);
    CHECK_EQ("priority inheritance mutex: the mutex still works", afl_mutex_pi_lock(&m), 0);
    CHECK_TRUE(
      "priority inheritance mutex: a foreign thread can not release it",
      run_foreign_unlock(worker_foreign_pi_unlock, &m) == 0 && atomic_load(&foreign_return) == EPERM
    );
    CHECK_TRUE(
      "priority inheritance mutex: the rejected foreign release left the owner in the word",
      lock_owner_of(&m) == __afl_gettid()
    );
    CHECK_EQ("priority inheritance mutex: the owner can still release it", afl_mutex_pi_unlock(&m), 0);
    CHECK_TRUE("priority inheritance mutex: the release left the word free", lock_owner_of(&m) == AFL_UNLOCKED);

    /*
     * The PI trylock is the userspace fast path of the blocking acquire and
     * nothing else: the kernel is never introduced to the mutex by a try, so
     * a free word is taken with one exchange and a held word is refused with
     * EBUSY, word and kernel PI state untouched.
     */
    CHECK_EQ("priority inheritance mutex: trylock of a free mutex succeeds", afl_mutex_pi_trylock(&m), 0);
    CHECK_TRUE("priority inheritance mutex: the trylock recorded the caller", lock_owner_of(&m) == __afl_gettid());
    CHECK_EQ("priority inheritance mutex: trylock by the owner reports EBUSY", afl_mutex_pi_trylock(&m), EBUSY);
    CHECK_TRUE(
      "priority inheritance mutex: the rejected trylock left the owner in the word", lock_owner_of(&m) == __afl_gettid()
    );
    CHECK_TRUE(
      "priority inheritance mutex: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_pi_trylock, &m) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    /* The blocking acquire and the release still work on the tried word. */
    CHECK_EQ("priority inheritance mutex: the owner can still release after the trylocks", afl_mutex_pi_unlock(&m), 0);
    CHECK_EQ("priority inheritance mutex: a plain lock after the trylocks", afl_mutex_pi_lock(&m), 0);
    CHECK_EQ("priority inheritance mutex: and its release", afl_mutex_pi_unlock(&m), 0);

    /* Linux cannot assign this TID. A failed kernel acquire must not report
     * success and let the caller enter an unprotected critical section. */
    __atomic_store_n(&m, AFL_TID_MASK, __ATOMIC_RELAXED);
    CHECK_EQ("priority inheritance mutex: nonexistent owner reports ESRCH", afl_mutex_pi_lock(&m), ESRCH);
    CHECK_EQ("priority inheritance mutex: reset after nonexistent owner", afl_mutex_destroy(&m), 0);
}

/*
 * Priority ceiling mutex. The ceiling scale is the SCHED_FIFO range inverted so
 * that a lower number means a higher priority (see the header comment in
 * afl.h), so the boundary values the suite asks for are min and max themselves,
 * and the invalid ones sit one step outside of them.
 */
#define TEST_PC_CEILING 10

/*
 * The kernel parameters of the calling thread, or -1 on the first error read.
 * The observer goes through the libc sched_getscheduler and sched_getparam
 * wrappers, which ask the kernel on every call, and not through
 * pthread_getschedparam: that one answers from the thread control block cache
 * glibc keeps, and the raw interface the header now borrows through does not
 * update it. The sched_getscheduler result may carry the SCHED_RESET_ON_FORK
 * flag in bit 30; the kernel value is spelled here because glibc names it only
 * under _GNU_SOURCE.
 */
static int thread_priority(int *policy)
{
    struct sched_param param;
    long scheduler = sched_getscheduler(0);

    if (scheduler < 0)
        return -1;

    if (sched_getparam(0, &param) != 0)
        return -1;

    *policy = (int) scheduler & ~0x40000000; // SCHED_RESET_ON_FORK

    return param.sched_priority;
}

/*
 * Try to make this thread a SCHED_FIFO thread below every ceiling the
 * borrowing test uses. Returns 0 on success, or the error number of the call
 * that refused it; EPERM is what an unprivileged run gets, and every check
 * that can only be observed through a real elevation skips on it.
 */
static int pc_make_sub_ceiling(int *saved_policy, struct sched_param *saved_param, int prio)
{
    int policy;
    int error;

    error = __afl_sched_getparam(&policy, &saved_param->sched_priority);

    if (error != 0)
        return error;

    *saved_policy = policy;

    if (policy == SCHED_FIFO || policy == SCHED_RR) {
        /* Already real time: a priority at or below the mapped targets is enough. */
        if (saved_param->sched_priority > prio)
            return EPERM;

        return 0;
    }

    /*
     * The whole helper reads and writes the kernel directly, through the same
     * raw interface the header borrows through, so the read above and the final
     * undo below always describe the state the header left behind: nothing
     * caches the scheduling parameters in between.
     */
    return __afl_sched_setparam(SCHED_FIFO, prio);
}

static void test_mutex_pc(void)
{
    afl_mutex_pc_t m;
    int min = sched_get_priority_min(SCHED_FIFO);
    int max = sched_get_priority_max(SCHED_FIFO);
    int ceiling;
    int policy;
    int prio;

    CHECK_TRUE("priority ceiling mutex: the SCHED_FIFO range is readable", min >= 0 && max >= 0);

    /* Initialization validates the ceiling before it touches the word. */
    CHECK_EQ("priority ceiling mutex: init with a ceiling below the range", afl_mutex_pc_init(&m, min - 1), EINVAL);
    CHECK_EQ("priority ceiling mutex: init with a ceiling above the range", afl_mutex_pc_init(&m, max + 1), EINVAL);
    CHECK_EQ("priority ceiling mutex: init with a null mutex", afl_mutex_pc_init(NULL, min), EINVAL);
    CHECK_EQ("priority ceiling mutex: init at the top of the range", afl_mutex_pc_init(&m, min), 0);
    CHECK_EQ("priority ceiling mutex: init at the bottom of the range", afl_mutex_pc_init(&m, max), 0);
    CHECK_EQ("priority ceiling mutex: init with the test ceiling", afl_mutex_pc_init(&m, TEST_PC_CEILING), 0);

    /* The static initializer is a usable mutex with the documented default ceiling. */
    {
        afl_mutex_pc_t s = AFL_MUTEX_PC_INIT;

        CHECK_EQ("priority ceiling mutex: the static default ceiling", afl_mutex_pc_getceiling(&s, &ceiling), 0);
        CHECK_TRUE("priority ceiling mutex: the default is the weakest ceiling", ceiling == max);
        CHECK_EQ("priority ceiling mutex: the static mutex locks", afl_mutex_pc_lock(&s), 0);
        CHECK_TRUE("priority ceiling mutex: the static word shows the owner", lock_owner_of(&s.lock) == __afl_gettid());
        CHECK_EQ("priority ceiling mutex: the static mutex unlocks", afl_mutex_pc_unlock(&s), 0);

        /* Init is a reset, like every other init of the header: it replaces the ceiling. */
        CHECK_EQ("priority ceiling mutex: init is a reset", afl_mutex_pc_init(&s, min), 0);
        CHECK_EQ("priority ceiling mutex: the reset ceiling is readable", afl_mutex_pc_getceiling(&s, &ceiling), 0);
        CHECK_TRUE("priority ceiling mutex: init replaced the default ceiling", ceiling == min);

        CHECK_EQ("priority ceiling mutex: destroy", afl_mutex_pc_destroy(&s), 0);
        CHECK_EQ("priority ceiling mutex: the destroyed ceiling reads back", afl_mutex_pc_getceiling(&s, &ceiling), 0);
        CHECK_TRUE("priority ceiling mutex: destroy restored the default ceiling", ceiling == max);
    }

    /* Bookkeeping: get and set while unlocked, validation on both sides. */
    CHECK_EQ("priority ceiling mutex: getceiling with a null word", afl_mutex_pc_getceiling(NULL, &ceiling), EINVAL);
    CHECK_EQ("priority ceiling mutex: getceiling with a null ceiling", afl_mutex_pc_getceiling(&m, NULL), EINVAL);
    CHECK_EQ("priority ceiling mutex: getceiling", afl_mutex_pc_getceiling(&m, &ceiling), 0);
    CHECK_TRUE("priority ceiling mutex: init stored the ceiling", ceiling == TEST_PC_CEILING);
    CHECK_EQ("priority ceiling mutex: setceiling out of range", afl_mutex_pc_setceiling(&m, max + 1), EINVAL);
    CHECK_EQ("priority ceiling mutex: setceiling with a null word", afl_mutex_pc_setceiling(NULL, min), EINVAL);
    CHECK_EQ("priority ceiling mutex: setceiling while unlocked", afl_mutex_pc_setceiling(&m, min), 0);
    CHECK_EQ("priority ceiling mutex: the new ceiling is readable", afl_mutex_pc_getceiling(&m, &ceiling), 0);
    CHECK_TRUE("priority ceiling mutex: setceiling stored the value", ceiling == min);
    CHECK_EQ(
      "priority ceiling mutex: setceiling back for the borrowing test", afl_mutex_pc_setceiling(&m, TEST_PC_CEILING), 0
    );

    /* Locking contract, in the uncontended order. */
    CHECK_EQ("priority ceiling mutex: uncontended lock", afl_mutex_pc_lock(&m), 0);
    CHECK_TRUE("priority ceiling mutex: the word shows the owner", lock_owner_of(&m.lock) == __afl_gettid());
    CHECK_EQ("priority ceiling mutex: relock by the owner reports EDEADLOCK", afl_mutex_pc_lock(&m), EDEADLOCK);
    CHECK_EQ("priority ceiling mutex: trylock by the owner reports EBUSY", afl_mutex_pc_trylock(&m), EBUSY);
    CHECK_EQ("priority ceiling mutex: setceiling while held reports EBUSY", afl_mutex_pc_setceiling(&m, max), EBUSY);
    CHECK_EQ("priority ceiling mutex: the held mutex kept its ceiling", afl_mutex_pc_getceiling(&m, &ceiling), 0);
    CHECK_TRUE("priority ceiling mutex: the rejected setceiling changed nothing", ceiling == TEST_PC_CEILING);
    CHECK_EQ("priority ceiling mutex: unlock after the rejected relock", afl_mutex_pc_unlock(&m), 0);
    CHECK_TRUE("priority ceiling mutex: the release left the word free", lock_owner_of(&m.lock) == AFL_UNLOCKED);
    CHECK_EQ("priority ceiling mutex: unlock of an unlocked mutex reports EPERM", afl_mutex_pc_unlock(&m), EPERM);
    CHECK_EQ("priority ceiling mutex: the mutex still works", afl_mutex_pc_lock(&m), 0);
    CHECK_EQ("priority ceiling mutex: the mutex still unlocks", afl_mutex_pc_unlock(&m), 0);
    CHECK_TRUE(
      "priority ceiling mutex: a foreign thread can not release it",
      run_foreign_unlock(worker_foreign_pc_unlock, &m) == 0 && atomic_load(&foreign_return) == EPERM
    );
    CHECK_EQ("priority ceiling mutex: lock for the foreign probes", afl_mutex_pc_lock(&m), 0);
    CHECK_TRUE(
      "priority ceiling mutex: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_pc_trylock, &m) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    CHECK_TRUE(
      "priority ceiling mutex: the rejected foreign trylock left the owner in the word",
      lock_owner_of(&m.lock) == __afl_gettid()
    );
    CHECK_EQ("priority ceiling mutex: release after the rejected foreign probes", afl_mutex_pc_unlock(&m), 0);

    /*
     * The borrowing contract. Without the privilege to change scheduling
     * parameters the elevation attempt is refused with EPERM and the protocol
     * tolerates it, so the two checks that can only be observed through a real
     * elevation say so and skip; the bookkeeping checks run either way.
     */
    {
        struct sched_param saved_param;
        int saved_policy;
        int target;
        int error = pc_make_sub_ceiling(&saved_policy, &saved_param, TEST_PC_CEILING + 5);

        if (error == EPERM || error == EACCES) {
            test_skip(
              "priority ceiling mutex: the holder borrows the ceiling",
              "the elevation attempt returned EPERM, this process has no CAP_SYS_NICE (unprivileged run)"
            );
            test_skip(
              "priority ceiling mutex: the unlock restores the previous priority",
              "the elevation attempt returned EPERM, this process has no CAP_SYS_NICE (unprivileged run)"
            );
        } else if (error != 0) {
            test_skip("priority ceiling mutex: the holder borrows the ceiling", "the probe failed: %s", strerror(error));
            test_skip("priority ceiling mutex: the unlock restores the previous priority", "setup failed");
        } else {
            prio = thread_priority(&policy);

            if (prio >= min + (max - TEST_PC_CEILING)) {
                /*
                 * Already at or above the mapped ceiling: the protocol never
                 * lowers a holder, there is nothing left to observe.
                 */
                test_skip(
                  "priority ceiling mutex: the holder borrows the ceiling",
                  "this thread is already above the mapped ceiling (priority %d)", prio
                );
                test_skip(
                  "priority ceiling mutex: the unlock restores the previous priority", "nothing was left to borrow"
                );
            } else {
                int policy_at_lock;
                int prio_at_lock = thread_priority(&policy_at_lock);

                CHECK_EQ("priority ceiling mutex: the sub-ceiling thread locks", afl_mutex_pc_lock(&m), 0);

                target = min + (max - TEST_PC_CEILING);
                prio = thread_priority(&policy);

                CHECK_TRUE(
                  "priority ceiling mutex: the holder borrows the ceiling",
                  prio >= target && (policy == SCHED_FIFO || policy == SCHED_RR)
                );

                CHECK_EQ("priority ceiling mutex: the unlock restores", afl_mutex_pc_unlock(&m), 0);

                prio = thread_priority(&policy);

                /*
                 * The contract is the deterministic restore of what the
                 * acquire saved, which is the parameter set this thread had
                 * when it won the word - not whatever the thread had before
                 * this test elevated it, which is the saved_policy of the
                 * probe above and not the state the mutex ever saw.
                 */
                CHECK_TRUE(
                  "priority ceiling mutex: the unlock restores the previous priority",
                  prio == prio_at_lock && policy == policy_at_lock
                );
            }

            /*
             * The elevation, if there was one, is undone here so that the rest
             * of the suite runs with the parameters it started with; a thread
             * that never borrowed needs nothing back. Through the same raw
             * interface the rest of the file uses.
             */
            __afl_sched_setparam(saved_policy, saved_param.sched_priority);
        }
    }

    CHECK_EQ("priority ceiling mutex: destroy", afl_mutex_pc_destroy(&m), 0);
    CHECK_TRUE("priority ceiling mutex: the destroyed word is free", lock_owner_of(&m.lock) == AFL_UNLOCKED);
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
    CHECK_TRUE(
      "recursive mutex: the rejected foreign release left the owner and the count alone",
      lock_owner_of(&m.lock) == __afl_gettid() && m.count == 1
    );
    CHECK_EQ("recursive mutex: the owner can still release it", afl_mutex_recursive_unlock(&m), 0);
    CHECK_EQ("recursive mutex: destroy", afl_mutex_recursive_destroy(&m), 0);

    /*
     * The recursive trylock is recursive by design, matching
     * pthread_mutex_trylock: a free mutex is taken with count 1, a
     * re-acquisition by the owner returns 0 and bumps count, and a foreign
     * hold is refused with EBUSY and leaves word and count untouched. The
     * counter overflow boundary belongs to the AFL_DEBUG misuse cases.
     */
    CHECK_EQ("recursive mutex: trylock of a free mutex succeeds", afl_mutex_recursive_trylock(&m), 0);
    CHECK_TRUE("recursive mutex: the trylock started the count at 1", m.count == 1);
    CHECK_EQ("recursive mutex: trylock by the owner re-acquires", afl_mutex_recursive_trylock(&m), 0);
    CHECK_TRUE("recursive mutex: the re-acquisition bumped the count", m.count == 2);
    CHECK_EQ("recursive mutex: release of the second try acquisition", afl_mutex_recursive_unlock(&m), 0);
    CHECK_EQ("recursive mutex: release of the first try acquisition", afl_mutex_recursive_unlock(&m), 0);
    CHECK_TRUE("recursive mutex: the try sequence left the mutex free", m.lock == AFL_UNLOCKED && m.count == 0);
    CHECK_EQ("recursive mutex: lock it for the foreign attempt", afl_mutex_recursive_lock(&m), 0);
    CHECK_TRUE(
      "recursive mutex: a foreign thread can not take it with trylock",
      run_foreign_unlock(worker_foreign_recursive_trylock, &m) == 0 && atomic_load(&foreign_return) == EBUSY
    );
    CHECK_TRUE(
      "recursive mutex: the rejected foreign trylock left the owner and the count alone",
      lock_owner_of(&m.lock) == __afl_gettid() && m.count == 1
    );
    CHECK_EQ("recursive mutex: the owner can still release after the trylocks", afl_mutex_recursive_unlock(&m), 0);
}

/*
 * The nesting depth boundary. A deep nest has to leave the counter at zero again,
 * and the mutex has to be acquirable by a different thread afterwards: that is
 * the only way to show that the last release really freed the lock word instead
 * of leaving the tid of the first owner in it, which would hang every later user.
 */
#define TEST_RECURSIVE_DEPTH 64

static afl_mutex_recursive_t depth_mutex;
static _Atomic int depth_acquired;
static _Atomic long depth_count_seen;

static void *worker_recursive_depth_other(void *arg)
{
    (void) arg;

    if (afl_mutex_recursive_lock(&depth_mutex) != 0) {
        atomic_store(&depth_acquired, 0);
        return NULL;
    }

    atomic_store(&depth_count_seen, (long) depth_mutex.count);
    atomic_store(&depth_acquired, 1);

    crit_enter();
    crit_leave();

    if (afl_mutex_recursive_unlock(&depth_mutex) != 0)
        atomic_store(&depth_acquired, 0);

    return NULL;
}

static void test_mutex_recursive_depth(void)
{
    int rc = 0;

    afl_mutex_recursive_init(&depth_mutex);
    crit_reset();
    atomic_store(&depth_acquired, 0);
    atomic_store(&depth_count_seen, 0);

    for (unsigned i = 0; i < TEST_RECURSIVE_DEPTH; i++)
        rc |= afl_mutex_recursive_lock(&depth_mutex);

    CHECK_EQ("recursive mutex: a deep nest is accepted", rc, 0);
    CHECK_TRUE("recursive mutex: the counter reached the nesting depth", depth_mutex.count == TEST_RECURSIVE_DEPTH);

    rc = 0;
    for (unsigned i = 0; i < TEST_RECURSIVE_DEPTH; i++)
        rc |= afl_mutex_recursive_unlock(&depth_mutex);

    CHECK_EQ("recursive mutex: a deep nest is released level by level", rc, 0);
    CHECK_TRUE(
      "recursive mutex: the counter is back to zero after the deep nest",
      depth_mutex.count == 0 && __atomic_load_n(&depth_mutex.lock, __ATOMIC_RELAXED) == AFL_UNLOCKED
    );

    CHECK_TRUE(
      "recursive mutex: a different thread can acquire it after the deep nest",
      run_threads(1, worker_recursive_depth_other, NULL) == 0 && atomic_load(&depth_acquired) == 1
    );
    CHECK_TRUE("recursive mutex: the other thread started from a counter of one", atomic_load(&depth_count_seen) == 1);
    CHECK_EQ("recursive mutex: the reused mutex kept the critical section exclusive", overlaps, 0);
    CHECK_EQ("recursive mutex: destroy after the deep nest", afl_mutex_recursive_destroy(&depth_mutex), 0);
}

/*
 * Destroy semantics. Every destroy resets the storage so that it can be used
 * again, which is a contract of its own: a caller that keeps the object inside a
 * larger struct, or that recycles the storage of a pooled object, relies on it.
 * Nothing here is held while it is destroyed, so no destroy reports a misuse.
 */
static void test_destroy_semantics(void)
{
    afl_mutex_recursive_t r;
    afl_mutex_t m = AFL_MUTEX_INIT;
    afl_spinlock_t s;
    afl_cond_t c;

    afl_mutex_recursive_init(&r);
    afl_spin_init(&s, 0);
    afl_cond_init(&c);

    CHECK_EQ("destroy: destroying a free spinlock succeeds", afl_spin_destroy(&s), 0);
    CHECK_EQ("destroy: the destroyed spinlock locks again", afl_spin_lock(&s), 0);
    CHECK_EQ("destroy: the destroyed spinlock unlocks again", afl_spin_unlock(&s), 0);
    CHECK_TRUE("destroy: the reused spinlock is free again", __atomic_load_n(&s, __ATOMIC_RELAXED) == AFL_UNLOCKED);

    CHECK_EQ("destroy: destroying a free mutex succeeds", afl_mutex_destroy(&m), 0);
    CHECK_EQ("destroy: the destroyed mutex locks again", afl_mutex_lock(&m), 0);
    CHECK_EQ("destroy: the destroyed mutex unlocks again", afl_mutex_unlock(&m), 0);
    CHECK_TRUE("destroy: the reused mutex is free again", __atomic_load_n(&m, __ATOMIC_RELAXED) == AFL_UNLOCKED);

    /* The owner tracking variants put a tid in the word, so both of them have to
       work on the storage of one destroyed mutex. */
    CHECK_EQ("destroy: destroying a mutex clears the owner", afl_mutex_destroy(&m), 0);
    CHECK_EQ("destroy: the owner variant locks the destroyed mutex", afl_mutex_owner_lock(&m), 0);
    CHECK_TRUE("destroy: the owner variant recorded its owner", lock_owner_of(&m) == __afl_gettid());
    CHECK_EQ("destroy: the owner variant unlocks the destroyed mutex", afl_mutex_owner_unlock(&m), 0);

    CHECK_EQ("destroy: destroying a mutex clears it for the PI variant", afl_mutex_destroy(&m), 0);
    CHECK_EQ("destroy: the priority inheriting variant locks it", afl_mutex_pi_lock(&m), 0);
    CHECK_TRUE("destroy: the priority inheriting variant recorded its owner", lock_owner_of(&m) == __afl_gettid());
    CHECK_EQ("destroy: the priority inheriting variant unlocks it", afl_mutex_pi_unlock(&m), 0);

    CHECK_EQ("destroy: destroying a free recursive mutex succeeds", afl_mutex_recursive_destroy(&r), 0);
    CHECK_EQ("destroy: the destroyed recursive mutex locks again", afl_mutex_recursive_lock(&r), 0);
    CHECK_TRUE("destroy: the reused recursive mutex started from a counter of one", r.count == 1);
    CHECK_EQ("destroy: the destroyed recursive mutex unlocks again", afl_mutex_recursive_unlock(&r), 0);
    CHECK_TRUE(
      "destroy: the reused recursive mutex is free again",
      r.count == 0 && __atomic_load_n(&r.lock, __ATOMIC_RELAXED) == AFL_UNLOCKED
    );

    CHECK_EQ("destroy: destroying a condition variable succeeds", afl_cond_destroy(&c), 0);
    CHECK_TRUE("destroy: the destroyed condition variable has no state left", c.sequence == 0 && c.waiters == 0);
    CHECK_EQ("destroy: a signal on the reused condition variable succeeds", afl_cond_signal(&c), 0);
    CHECK_EQ("destroy: a broadcast on the reused condition variable succeeds", afl_cond_broadcast(&c), 0);
    CHECK_EQ("destroy: destroying the reused condition variable succeeds", afl_cond_destroy(&c), 0);
}

/*
 * afl_once
 */
#define TEST_ONCE_CALLS   32
#define TEST_ONCE_INIT_US 20000
#define TEST_ONCE_VALUE   0xA5A5A5A5UL

static afl_once_t once_control = AFL_ONCE_INIT;
static _Atomic long once_runs;
static _Atomic long once_ready;
static _Atomic long once_calls;
static _Atomic long once_values;
static long once_observed[TEST_MAX_THREADS];

/* Written by the initializer and read by every thread, plain on purpose: what
   publishes it is the release exchange of the control word and the acquire load
   on the other side, and an atomic here would hide a missing pairing. */
static unsigned long once_value;

static void once_initializer(void)
{
    /* Slow on purpose: all the other threads have to wait for it. */
    usleep(TEST_ONCE_INIT_US);

    once_value = TEST_ONCE_VALUE;

    atomic_store_explicit(&once_ready, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&once_runs, 1, memory_order_relaxed);
}

static void *worker_once(void *arg)
{
    long *observed = arg;

    for (unsigned i = 0; i < TEST_ONCE_CALLS; i++) {
        if (afl_once(&once_control, once_initializer) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

        /* Check publication immediately: a later successful acquire must
         * not mask a missing acquire on the first call's losing CAS. */
        if (i == 0 && once_value == TEST_ONCE_VALUE)
            atomic_fetch_add_explicit(&once_values, 1, memory_order_relaxed);
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
    unsigned threads = test_threads > TEST_MAX_THREADS ? TEST_MAX_THREADS : test_threads;
    unsigned observed = 0;

    atomic_store(&bad_return, 0);
    atomic_store(&once_runs, 0);
    atomic_store(&once_ready, 0);
    atomic_store(&once_calls, 0);
    atomic_store(&once_values, 0);
    once_value = 0;
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

    /*
     * The value the initializer wrote, and not only the flag it published: a
     * release exchange that is not paired with an acquire read would let a thread
     * see the finished control word and the stale data it guards at the same time.
     */
    CHECK_TRUE("once: the initializer wrote its value", once_value == TEST_ONCE_VALUE);
    CHECK_EQ("once: every thread read the value of the initializer", once_values, threads);

    /*
     * After the initialization the control word holds the success bit, and a later
     * call returns on that fast path without running the initializer again.
     */
    CHECK_TRUE(
      "once: a finished control word holds the success bit",
      __atomic_load_n(&once_control, __ATOMIC_RELAXED) == AFL_SUCCESS
    );
    CHECK_EQ("once: a second call after the success returns success", afl_once(&once_control, once_initializer), 0);
    CHECK_EQ("once: a second call after the success does not run the initializer", once_runs, 1);
    CHECK_TRUE("once: a second call leaves the value alone", once_value == TEST_ONCE_VALUE);
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
#define TEST_COND_TIMED_MS  2000
#define TEST_WAIT_SPINS     100000000L

static afl_cond_t cond = AFL_COND_INIT;
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

/*
 * The CLOCK_REALTIME twin of deadline_after(), for the timed mutex acquires,
 * which take an absolute CLOCK_REALTIME deadline like pthread_mutex_timedlock.
 * A negative value normalizes so that tv_nsec stays in range and the deadline
 * really lies behind now.
 */
static struct timespec realtime_after(long milliseconds)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);

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

    delay.tv_sec = cond_signal_after_ms / 1000;
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
    afl_thread_t thread[TEST_MAX_THREADS];
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
    const unsigned target = 2;
    afl_thread_t thread[4];
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

static int cond_relock_payload;

/* The signaller keeps the mutex until the condition wait has ended, forcing
 * the waiter to reacquire a held mutex, including after a timed-out wait. */
static void *worker_cond_relock(void *arg)
{
    int signal_waiter = *(const int *) arg;

    if (afl_mutex_lock(&cond_mutex) != 0) {
        atomic_fetch_add(&bad_return, 1);
        return NULL;
    }

    crit_enter();
    if (signal_waiter && afl_cond_signal(&cond) != 0)
        atomic_fetch_add(&bad_return, 1);

    long spin;
    for (spin = 0; spin < TEST_WAIT_SPINS; spin++) {
        if (__atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0)
            break;
        __afl_pause;
    }
    if (spin == TEST_WAIT_SPINS)
        atomic_fetch_add(&bad_return, 1);

    cond_relock_payload = 42;
    crit_leave();
    if (afl_mutex_unlock(&cond_mutex) != 0)
        atomic_fetch_add(&bad_return, 1);
    return NULL;
}

static void test_cond_relock(void)
{
    static const struct
    {
        const char *name;
        int timed, signal_waiter, expected;
    } cases[] = {
      {"cond: signal reacquires a held mutex",       0, 1, 0        },
      {"cond: timed signal reacquires a held mutex", 1, 1, 0        },
      {"cond: timeout reacquires a held mutex",      1, 0, ETIMEDOUT},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        afl_thread_t signaller;
        int signal_waiter = cases[i].signal_waiter;
        void *args[] = {&signal_waiter};
        int rc;

        CHECK_EQ("cond: initialize relock case", afl_cond_init(&cond), 0);
        CHECK_EQ("cond: reset relock mutex", afl_mutex_destroy(&cond_mutex), 0);
        crit_reset();
        atomic_store(&bad_return, 0);
        cond_relock_payload = 0;

        rc = afl_mutex_lock(&cond_mutex);
        CHECK_EQ("cond: lock before relock case", rc, 0);
        if (rc != 0)
            continue;
        if (start_threads(&signaller, 1, worker_cond_relock, args) != 0) {
            CHECK_EQ("cond: unlock after signaller creation failure", afl_mutex_unlock(&cond_mutex), 0);
            test_fail(cases[i].name, "could not create signaller");
            continue;
        }

        if (cases[i].timed) {
            struct timespec deadline = deadline_after(signal_waiter ? TEST_COND_TIMED_MS : TEST_COND_SIGNAL_MS);
            rc = afl_cond_timedwait(&cond, &cond_mutex, &deadline);
        } else {
            rc = afl_cond_wait(&cond, &cond_mutex);
        }
        CHECK_EQ(cases[i].name, rc, cases[i].expected);
        crit_enter();
        CHECK_EQ("cond: relock observes the signaller's protected write", cond_relock_payload, 42);
        CHECK_EQ("cond: relock excludes the signaller", overlaps, 0);
        crit_leave();
        CHECK_EQ("cond: unlock after relock", afl_mutex_unlock(&cond_mutex), 0);

        /* Join before the next case reuses the signaller's stack argument. */
        join_threads(&signaller, 1);
        CHECK_EQ("cond: relock signaller completed without errors", bad_return, 0);
        CHECK_EQ("cond: relock leaves no registered waiters", cond.waiters, 0);
    }
}

static void test_cond_timedwait(void)
{
    struct timespec start, deadline;
    afl_thread_t signaller;
    int signaled;

    afl_cond_init(&cond);
    afl_mutex_destroy(&cond_mutex);
    atomic_store(&cond_ready, 0);
    atomic_store(&bad_return, 0);

    CHECK_EQ("cond: lock for the timed waits", afl_mutex_lock(&cond_mutex), 0);

    /* A deadline that is already behind reports the timeout without waiting. */
    start = deadline_after(0);
    deadline = deadline_after(-1);
    CHECK_EQ(
      "cond: an expired timed wait reports ETIMEDOUT", afl_cond_timedwait(&cond, &cond_mutex, &deadline), ETIMEDOUT
    );
    CHECK_TRUE("cond: an expired timed wait returns at once", elapsed_ms(&start) < TEST_COND_SIGNAL_MS);
    CHECK_TRUE(
      "cond: an expired timed wait does not register a waiter", __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
    );
    CHECK_TRUE(
      "cond: the mutex is still held after the expired timed wait",
      __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );

    /*
     * A deadline of exactly now, that is a zero relative timeout. Whether the
     * subtraction lands on zero or one nanosecond behind depends on how much time
     * passed between the two clock reads, so both the early return and the
     * FUTEX_WAIT with a zero timeout have to end the same way: a timeout, with the
     * caller back in possession of the mutex and no waiter left behind.
     */
    start = deadline_after(0);
    deadline = deadline_after(0);
    CHECK_EQ(
      "cond: a timed wait with a zero timeout reports ETIMEDOUT", afl_cond_timedwait(&cond, &cond_mutex, &deadline),
      ETIMEDOUT
    );
    CHECK_TRUE("cond: a zero timeout does not sleep", elapsed_ms(&start) < TEST_COND_SIGNAL_MS);
    CHECK_TRUE("cond: a zero timeout leaves no waiter behind", __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0);
    CHECK_TRUE(
      "cond: the mutex is still held after the zero timeout",
      __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );

    /*
     * Out of range nanosecond fields are refused before anything is touched, the
     * way pthread_cond_timedwait() refuses them. Table driven, static cases,
     * both boundaries of the valid interval: a bad value must be refused here,
     * never converted into a relative timeout the waiter would then sleep for.
     */
    static const long bad_nsec[] = {1000000000L, 2000000000L, -1L, -1000000000L};

    for (unsigned i = 0; i < sizeof(bad_nsec) / sizeof(bad_nsec[0]); i++) {
        start = deadline_after(0);
        deadline.tv_nsec = bad_nsec[i];
        CHECK_EQ(
          "cond: a timed wait with a bad nanosecond field reports EINVAL",
          afl_cond_timedwait(&cond, &cond_mutex, &deadline), EINVAL
        );
        CHECK_TRUE("cond: a refused timed wait returns at once", elapsed_ms(&start) < 1);
        CHECK_TRUE(
          "cond: a refused timed wait does not register a waiter", __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
        );
        CHECK_TRUE(
          "cond: the mutex is still held after the refused timed wait",
          __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
        );
    }

    /*
     * A missing deadline is refused the same way, on the validator every timed
     * entry point of the header shares: all six report EINVAL for a NULL
     * abstime before they touch any state. The state pins are the ones the bad
     * nanosecond cases above use.
     */
    start = deadline_after(0);
    CHECK_EQ(
      "cond: a timed wait with a NULL abstime reports EINVAL", afl_cond_timedwait(&cond, &cond_mutex, NULL), EINVAL
    );
    CHECK_TRUE("cond: the NULL deadline timed wait returns at once", elapsed_ms(&start) < 1);
    CHECK_TRUE(
      "cond: the NULL deadline timed wait registers no waiter", __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
    );
    CHECK_TRUE(
      "cond: the mutex is still held after the NULL deadline timed wait",
      __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );

    /* Nothing signals this one, so it has to sleep until its own deadline. */
    start = deadline_after(0);
    deadline = deadline_after(TEST_COND_SIGNAL_MS);
    signaled = afl_cond_timedwait(&cond, &cond_mutex, &deadline);

    CHECK_EQ("cond: a timed wait that nobody signals reports ETIMEDOUT", signaled, ETIMEDOUT);
    CHECK_TRUE("cond: the timed wait slept for its timeout", elapsed_ms(&start) >= TEST_COND_SIGNAL_MS);
    CHECK_TRUE(
      "cond: a timed out waiter is removed from the condition variable",
      __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
    );

    /* A signal before the deadline returns success well before it expires. */
    start = deadline_after(0);
    deadline = deadline_after(TEST_COND_TIMED_MS);
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
 * An interrupted wait. FUTEX_WAIT comes back with -EINTR when a signal reaches the
 * sleeping thread, and afl_cond_timedwait has to turn that into the documented
 * spurious wake up - success, with the mutex held again - instead of reporting a
 * timeout that never happened. The predicate loop of the caller is what decides.
 *
 * The signal is SIGALRM, sent with tgkill to one named thread by a helper.
 * Two details make the check reliable instead of flaky:
 *
 *   - the helper only raises it once the waiter has registered itself, and then
 *     lets a moment pass so that the waiter really is inside FUTEX_WAIT: a signal
 *     that arrives before the system call starts leaves the wait to run to its own
 *     deadline, and a signal that arrives after it returned does nothing at all,
 *   - an attempt whose signal missed the wait is therefore simply retried, a
 *     bounded number of times, rather than being reported as a failure.
 *
 * The handler is async signal safe: it only stores into a lock free atomic, which
 * a handler may touch, and which keeps the thread sanitizer from reporting the
 * handler and the reader as racing.
 */
#define TEST_EINTR_DEADLINE_MS 200
#define TEST_EINTR_ATTEMPTS    8
#define TEST_EINTR_SETTLE_MS   1

static _Atomic sig_atomic_t eintr_raised;

static void eintr_handler(int signo)
{
    (void) signo;

    atomic_store_explicit(&eintr_raised, 1, memory_order_relaxed);
}

typedef struct
{
    unsigned long target; /* the kernel thread id the signal goes to */
    afl_cond_t *cond;
    _Atomic int fired; /* 1 raised, -1 the helper could not do its job */
} eintr_helper_t;

static void *worker_eintr_raise(void *arg)
{
    eintr_helper_t *helper = arg;
    struct timespec start, delay;
    sigset_t blocked;

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);

    /* The signal is addressed to one thread, but this one must not let a stray
       SIGALRM cut its own nanosleep short. */
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) {
        atomic_store(&helper->fired, -1);
        return NULL;
    }

    /*
     * The registration is the earliest point at which the wait is reachable: it
     * happens while the waiter still holds the mutex, before the release and before
     * the system call. Waiting for it and then settling for a moment is what puts
     * the signal inside the FUTEX_WAIT.
     */
    start = deadline_after(0);

    while (__atomic_load_n(&helper->cond->waiters, __ATOMIC_RELAXED) != 1) {
        if (elapsed_ms(&start) > TEST_EINTR_DEADLINE_MS) {
            atomic_store(&helper->fired, -1);
            return NULL;
        }

        __afl_pause;
    }

    delay.tv_sec = 0;
    delay.tv_nsec = TEST_EINTR_SETTLE_MS * 1000000L;
    nanosleep(&delay, NULL);

    atomic_store(&helper->fired, test_kill_thread(helper->target, SIGALRM) == 0 ? 1 : -1);

    return NULL;
}

static void test_cond_timedwait_eintr(void)
{
    struct sigaction action, previous;
    struct timespec start, deadline;
    eintr_helper_t helper;
    sigset_t unblocked, previous_mask;
    afl_thread_t raiser;
    double raised_ms = 0.0;
    int raised = 0;
    int signaled = -1;

    CHECK_TRUE("cond: the interrupted wait flag is lock free", atomic_is_lock_free(&eintr_raised));

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = eintr_handler;
    /* No SA_RESTART: the FUTEX_WAIT has to come back with EINTR instead of being
       restarted behind the back of the header. */
    action.sa_flags = 0;

    if (sigaction(SIGALRM, &action, &previous) != 0) {
        test_skip("cond: an interrupted timed wait", "could not install the SIGALRM handler");
        return;
    }

    sigemptyset(&unblocked);
    sigaddset(&unblocked, SIGALRM);

    if (sigprocmask(SIG_UNBLOCK, &unblocked, &previous_mask) != 0) {
        test_skip("cond: an interrupted timed wait", "could not unblock SIGALRM in this thread");
        sigaction(SIGALRM, &previous, NULL);
        return;
    }

    afl_cond_init(&cond);
    afl_mutex_destroy(&cond_mutex);
    atomic_store(&bad_return, 0);

    helper.target = afl_thread_self();
    helper.cond = &cond;
    atomic_store(&helper.fired, 0);

    if (afl_mutex_lock(&cond_mutex) != 0) {
        test_fail("cond: an interrupted timed wait", "could not take the mutex");
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        sigaction(SIGALRM, &previous, NULL);
        return;
    }

    for (unsigned attempt = 0; attempt < TEST_EINTR_ATTEMPTS && !raised; attempt++) {
        void *args[1] = {&helper};
        double ms;

        atomic_store(&helper.fired, 0);
        atomic_store_explicit(&eintr_raised, 0, memory_order_relaxed);

        if (start_threads(&raiser, 1, worker_eintr_raise, args) != 0) {
            test_fail("cond: an interrupted timed wait", "could not create the signaller thread");
            break;
        }

        start = deadline_after(0);
        deadline = deadline_after(TEST_EINTR_DEADLINE_MS);
        signaled = afl_cond_timedwait(&cond, &cond_mutex, &deadline);
        ms = elapsed_seconds(&start) * 1000.0;

        join_threads(&raiser, 1);

        if (
          atomic_load(&helper.fired) == 1 && signaled == 0
          && atomic_load_explicit(&eintr_raised, memory_order_relaxed) != 0 && ms < TEST_EINTR_DEADLINE_MS
        ) {
            raised = 1;
            raised_ms = ms;
        }
    }

    CHECK(
      "cond: an interrupted timed wait is a spurious wake up", raised == 1,
      "no attempt came back early with success (last return %d)", signaled
    );
    CHECK(
      "cond: the interrupted timed wait returned before its deadline", raised_ms < TEST_EINTR_DEADLINE_MS,
      "%.2f ms against a %d ms deadline", raised_ms, TEST_EINTR_DEADLINE_MS
    );
    CHECK_TRUE(
      "cond: the mutex is held after the interrupted timed wait",
      __atomic_load_n(&cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );
    CHECK_TRUE(
      "cond: the interrupted waiter is removed from the condition variable",
      __atomic_load_n(&cond.waiters, __ATOMIC_RELAXED) == 0
    );
    CHECK_EQ("cond: unlock after the interrupted timed wait", afl_mutex_unlock(&cond_mutex), 0);

    /* Leave no handler and no unblocked signal behind for the tests that follow. */
    sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    sigaction(SIGALRM, &previous, NULL);
}

/*
 * Timed mutex lock tests.
 *
 * The timed acquires mirror pthread_mutex_timedlock: a free mutex is taken
 * even when abstime lies in the past, a contended one is refused with
 * ETIMEDOUT exactly at the deadline, and a NULL or malformed abstime is
 * EINVAL before any state is touched. The deadline is CLOCK_REALTIME, so
 * these tests build it with a realtime helper of their own; deadline_after()
 * belongs to CLOCK_MONOTONIC and must not be mixed in.
 */
#define TEST_TIMED_MS                 50
#define TEST_TIMED_EINTR_DEADLINE_MS  1000
#define TEST_TIMED_EINTR_HOLD_MS      25
#define TEST_TIMED_EINTR_LONG_HOLD_MS 600
#define TEST_TIMED_STRETCH_MS         300
#define TEST_TIMED_EXPIRY_SLACK_MS    250

static struct timespec timed_deadline;
static _Atomic long timed_rc;
static unsigned timed_hold_ms;

static uint32_t timed_word(void)
{
    return __atomic_load_n(&mutex, __ATOMIC_RELAXED);
}

/*
 * The timed contention workers take the far deadline once, so the acquire
 * loop itself is measured and never a timeout: a correct timed lock has to
 * behave exactly like its untimed twin under contention.
 */
static void *worker_mutex_timed(void *arg)
{
    const struct timespec far = realtime_after(10 * 60 * 1000);

    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (afl_mutex_timedlock(&mutex, &far) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            continue;
        }

        crit_enter();
        crit_leave();

        if (afl_mutex_unlock(&mutex) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
    }

    return NULL;
}

static void *worker_mutex_owner_timed(void *arg)
{
    const struct timespec far = realtime_after(10 * 60 * 1000);

    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (afl_mutex_owner_timedlock(&mutex, &far) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            continue;
        }

        crit_enter();
        crit_leave();

        if (afl_mutex_owner_unlock(&mutex) != 0)
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
    }

    return NULL;
}

/* The recursive timed mutex is taken twice per iteration, so one has to nest. */
static void *worker_mutex_recursive_timed(void *arg)
{
    const struct timespec far = realtime_after(10 * 60 * 1000);

    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (
          afl_mutex_recursive_timedlock(&recursive_mutex, &far) != 0
          || afl_mutex_recursive_timedlock(&recursive_mutex, &far) != 0
        ) {
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

/* The holder sleeps timed_hold_ms with the mutex taken, then releases it. */
static void *worker_timed_holder(void *arg)
{
    struct timespec hold;

    (void) arg;

    if (afl_mutex_lock(&mutex) != 0) {
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
        return NULL;
    }

    hold.tv_sec = timed_hold_ms / 1000;
    hold.tv_nsec = (long) (timed_hold_ms % 1000) * 1000000L;
    nanosleep(&hold, NULL);

    if (afl_mutex_unlock(&mutex) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    return NULL;
}

/* Waiters that report their timed return code through timed_rc. */
static void *worker_timed_waiter(void *arg)
{
    (void) arg;

    atomic_store_explicit(&timed_rc, afl_mutex_timedlock(&mutex, &timed_deadline), memory_order_release);

    return NULL;
}

static void *worker_timed_owner_waiter(void *arg)
{
    (void) arg;

    atomic_store_explicit(&timed_rc, afl_mutex_owner_timedlock(&mutex, &timed_deadline), memory_order_release);

    return NULL;
}

static void *worker_timed_recursive_waiter(void *arg)
{
    (void) arg;

    atomic_store_explicit(
      &timed_rc, afl_mutex_recursive_timedlock(&recursive_mutex, &timed_deadline), memory_order_release
    );

    return NULL;
}

/*
 * A timed acquire is refused with ETIMEDOUT at its deadline while a holder
 * keeps the lock; the holder has to come out of it untouched and the lock has
 * to work normally afterwards. The masked word check keeps the waiters bit of
 * the giving up waiter out of the comparison: it costs one extra wake up and
 * can never lose one. The caller owns the mutex before it is called and
 * releases it after it returns.
 */
static void check_timed_timeout_behind_holder(const char *variant, thread_function_t waiter, uint32_t held_word)
{
    struct timespec start;
    afl_thread_t thread[1];

    timed_deadline = realtime_after(TEST_TIMED_MS);
    atomic_store(&timed_rc, 0);

    if (start_threads(thread, 1, waiter, NULL) != 0) {
        test_fail(variant, "could not create the waiter thread");
        return;
    }

    start = deadline_after(0);
    join_threads(thread, 1);

    CHECK_EQ(variant, atomic_load(&timed_rc), ETIMEDOUT);
    CHECK(
      "timed mutex: the waiter slept until its deadline", elapsed_ms(&start) >= TEST_TIMED_MS - 10, "%u ms",
      elapsed_ms(&start)
    );
    CHECK(
      "timed mutex: the waiter never slept past its deadline",
      elapsed_ms(&start) < TEST_TIMED_MS + TEST_TIMED_EXPIRY_SLACK_MS, "%u ms", elapsed_ms(&start)
    );
    CHECK_TRUE(
      "timed mutex: the timed out acquire did not disturb the holder",
      (timed_word() & (AFL_LOCKED | AFL_TID_MASK)) == held_word
    );
}

static void check_timed_timeout_behind_recursive_holder(const char *variant)
{
    struct timespec start;
    afl_thread_t thread[1];
    size_t nests = recursive_mutex.count;

    timed_deadline = realtime_after(TEST_TIMED_MS);
    atomic_store(&timed_rc, 0);

    if (start_threads(thread, 1, worker_timed_recursive_waiter, NULL) != 0) {
        test_fail(variant, "could not create the waiter thread");
        return;
    }

    start = deadline_after(0);
    join_threads(thread, 1);

    CHECK_EQ(variant, atomic_load(&timed_rc), ETIMEDOUT);
    CHECK(
      "recursive timed mutex: the waiter slept until its deadline", elapsed_ms(&start) >= TEST_TIMED_MS - 10, "%u ms",
      elapsed_ms(&start)
    );
    CHECK(
      "recursive timed mutex: the waiter never slept past its deadline",
      elapsed_ms(&start) < TEST_TIMED_MS + TEST_TIMED_EXPIRY_SLACK_MS, "%u ms", elapsed_ms(&start)
    );
    CHECK_TRUE(
      "recursive timed mutex: the timed out acquire left the owner alone",
      lock_owner_of(&recursive_mutex.lock) == __afl_gettid()
    );
    CHECK_TRUE("recursive timed mutex: the timed out acquire left the count alone", recursive_mutex.count == nests);
}

/* Wait until the holder shows in the word, so the acquire below really contends. */
static void timed_wait_for_holder(void)
{
    for (long i = 0; i < TEST_WAIT_SPINS; i++) {
        if (timed_word() != AFL_UNLOCKED)
            return;

        __afl_pause;
    }
}

static void test_mutex_timed(void)
{
    struct timespec start, deadline, zero = {0, 0};
    struct timespec expired[2];
    afl_thread_t thread[1];

    static const long bad_nsec[] = {1000000000L, 2000000000L, -1L, -1000000000L};

    afl_mutex_destroy(&mutex);
    afl_mutex_recursive_init(&recursive_mutex);
    atomic_store(&bad_return, 0);

    expired[0] = zero;
    expired[1] = realtime_after(-1);

    /* A NULL abstime is EINVAL on every variant, before any state is touched. */
    CHECK_EQ("timed mutex: a NULL abstime is refused", afl_mutex_timedlock(&mutex, NULL), EINVAL);
    CHECK_EQ("timed mutex owner: a NULL abstime is refused", afl_mutex_owner_timedlock(&mutex, NULL), EINVAL);
    CHECK_EQ(
      "recursive timed mutex: a NULL abstime is refused", afl_mutex_recursive_timedlock(&recursive_mutex, NULL), EINVAL
    );
    CHECK_TRUE("timed mutex: a refused acquire does not touch the word", timed_word() == AFL_UNLOCKED);
    CHECK_TRUE(
      "recursive timed mutex: a refused acquire does not touch the word",
      __atomic_load_n(&recursive_mutex.lock, __ATOMIC_RELAXED) == AFL_UNLOCKED
    );

    /* Out of range nanosecond fields are refused the same way, table driven. */
    for (unsigned i = 0; i < sizeof(bad_nsec) / sizeof(bad_nsec[0]); i++) {
        start = deadline_after(0);
        deadline = realtime_after(TEST_TIMED_MS);
        deadline.tv_nsec = bad_nsec[i];

        CHECK_EQ("timed mutex: a bad nanosecond field reports EINVAL", afl_mutex_timedlock(&mutex, &deadline), EINVAL);
        CHECK_EQ(
          "timed mutex owner: a bad nanosecond field reports EINVAL", afl_mutex_owner_timedlock(&mutex, &deadline),
          EINVAL
        );
        CHECK_EQ(
          "recursive timed mutex: a bad nanosecond field reports EINVAL",
          afl_mutex_recursive_timedlock(&recursive_mutex, &deadline), EINVAL
        );
        CHECK_TRUE("timed mutex: a refused acquire returns at once", elapsed_ms(&start) < 1);
        CHECK_TRUE("timed mutex: a refused acquire leaves the word free", timed_word() == AFL_UNLOCKED);
    }

    /*
     * A free mutex is taken even with a past or zero abstime, exactly as
     * pthread_mutex_timedlock does: the uncontended path never consults the
     * deadline. The divergence from afl_cond_timedwait and the rwlock timed
     * acquires, which refuse a past deadline before anything is touched, is
     * documented in afl.h.
     */
    for (unsigned i = 0; i < 2; i++) {
        start = deadline_after(0);

        CHECK_EQ("timed mutex: a free mutex is taken with a past deadline", afl_mutex_timedlock(&mutex, &expired[i]), 0);
        CHECK_TRUE("timed mutex: taking with a past deadline does not sleep", elapsed_ms(&start) < 1);
        CHECK_TRUE("timed mutex: the acquire with a past deadline held the lock", timed_word() == AFL_LOCKED);
        CHECK_EQ("timed mutex: unlock after the past deadline acquire", afl_mutex_unlock(&mutex), 0);

        CHECK_EQ(
          "timed mutex owner: a free mutex is taken with a past deadline",
          afl_mutex_owner_timedlock(&mutex, &expired[i]), 0
        );
        CHECK_EQ("timed mutex owner: owner unlock after the past deadline acquire", afl_mutex_owner_unlock(&mutex), 0);

        CHECK_EQ(
          "recursive timed mutex: a free mutex is taken with a past deadline",
          afl_mutex_recursive_timedlock(&recursive_mutex, &expired[i]), 0
        );
        CHECK_TRUE("recursive timed mutex: the acquire with a past deadline counted one", recursive_mutex.count == 1);
        CHECK_EQ(
          "recursive timed mutex: unlock after the past deadline acquire", afl_mutex_recursive_unlock(&recursive_mutex),
          0
        );
    }

    CHECK_TRUE("timed mutex: the word is free after the past deadline round", timed_word() == AFL_UNLOCKED);

    /* Contended, a past deadline is a timeout at once, holder undisturbed. */
    CHECK_EQ("timed mutex: the test holds the mutex", afl_mutex_lock(&mutex), 0);

    start = deadline_after(0);
    CHECK_EQ(
      "timed mutex: a contended acquire with a past deadline reports ETIMEDOUT at once",
      afl_mutex_timedlock(&mutex, &expired[0]), ETIMEDOUT
    );
    CHECK_TRUE("timed mutex: an expired contended deadline does not sleep", elapsed_ms(&start) < 1);
    CHECK_TRUE(
      "timed mutex: the refused acquire did not disturb the holder",
      (timed_word() & (AFL_LOCKED | AFL_TID_MASK)) == AFL_LOCKED
    );
    CHECK_EQ("timed mutex: unlock after the fast expiry check", afl_mutex_unlock(&mutex), 0);

    /*
     * Re-acquisition by the owner is invalid use, not a timeout: EDEADLOCK is
     * reported before the deadline is consulted, even for a past abstime.
     */
    CHECK_EQ("timed mutex owner: the test owns the mutex", afl_mutex_owner_lock(&mutex), 0);

    start = deadline_after(0);
    CHECK_EQ(
      "timed mutex owner: a timed re-acquisition by the owner reports EDEADLOCK",
      afl_mutex_owner_timedlock(&mutex, &expired[0]), EDEADLOCK
    );
    CHECK_TRUE("timed mutex owner: the EDEADLOCK comes back at once", elapsed_ms(&start) < 1);
    CHECK_TRUE(
      "timed mutex owner: the refused re-acquisition left the owner alone", lock_owner_of(&mutex) == __afl_gettid()
    );

    /* A foreign owner timed acquire times out behind the real owner. */
    check_timed_timeout_behind_holder(
      "timed mutex owner: a foreign timed acquire reports ETIMEDOUT", worker_timed_owner_waiter, __afl_gettid()
    );
    CHECK_EQ("timed mutex owner: owner unlock after the foreign timeout", afl_mutex_owner_unlock(&mutex), 0);
    CHECK_TRUE("timed mutex owner: the word is free after the foreign timeout", timed_word() == AFL_UNLOCKED);

    /* A foreign timed acquire behind the plain holder times out too. */
    CHECK_EQ("timed mutex: the test holds the mutex again", afl_mutex_lock(&mutex), 0);
    check_timed_timeout_behind_holder(
      "timed mutex: a timed acquire behind a holder reports ETIMEDOUT", worker_timed_waiter, AFL_LOCKED
    );
    CHECK_EQ("timed mutex: unlock after the timeout", afl_mutex_unlock(&mutex), 0);

    /* The lock works normally after a timeout: nothing was left half held. */
    CHECK_EQ("timed mutex: plain lock after the timeout", afl_mutex_lock(&mutex), 0);
    CHECK_EQ("timed mutex: plain unlock after the timeout", afl_mutex_unlock(&mutex), 0);
    CHECK_TRUE("timed mutex: the word is free after the timeout cycle", timed_word() == AFL_UNLOCKED);

    /*
     * The recursive owner bypass: re-acquisition returns 0 whatever the
     * abstime says, past or malformed, and only a NULL is refused.
     */
    CHECK_EQ("recursive timed mutex: the test holds it", afl_mutex_recursive_lock(&recursive_mutex), 0);

    CHECK_EQ(
      "recursive timed mutex: the owner re-acquires with a past deadline",
      afl_mutex_recursive_timedlock(&recursive_mutex, &expired[0]), 0
    );
    CHECK_TRUE("recursive timed mutex: the bypass counted the nesting", recursive_mutex.count == 2);

    deadline = realtime_after(TEST_TIMED_MS);
    deadline.tv_nsec = bad_nsec[0];
    CHECK_EQ(
      "recursive timed mutex: the owner re-acquires even with a bad nanosecond field",
      afl_mutex_recursive_timedlock(&recursive_mutex, &deadline), 0
    );
    CHECK_TRUE("recursive timed mutex: the second bypass counted too", recursive_mutex.count == 3);
    CHECK_EQ(
      "recursive timed mutex: the owner times out nothing with a NULL abstime",
      afl_mutex_recursive_timedlock(&recursive_mutex, NULL), EINVAL
    );
    CHECK_TRUE("recursive timed mutex: the refused NULL left the count alone", recursive_mutex.count == 3);

    /*
     * A foreign timed acquire behind the recursive owner times out at once...
     * from a worker thread: the test thread owns the mutex here, so its own
     * acquire with a past deadline would be the bypass above, not a timeout.
     */
    timed_deadline = realtime_after(-1);
    atomic_store(&timed_rc, 0);

    if (start_threads(thread, 1, worker_timed_recursive_waiter, NULL) != 0) {
        test_fail("recursive timed mutex: fast expiry", "could not create the waiter thread");
        return;
    }

    start = deadline_after(0);
    join_threads(thread, 1);

    CHECK_EQ(
      "recursive timed mutex: a contended acquire with a past deadline reports ETIMEDOUT at once",
      atomic_load(&timed_rc), ETIMEDOUT
    );
    CHECK_TRUE("recursive timed mutex: the fast expiry did not sleep", elapsed_ms(&start) < TEST_TIMED_MS);
    CHECK_TRUE(
      "recursive timed mutex: the fast expiry left the owner alone",
      lock_owner_of(&recursive_mutex.lock) == __afl_gettid()
    );
    CHECK_TRUE("recursive timed mutex: the fast expiry left the count alone", recursive_mutex.count == 3);

    /* ...and with a real deadline it waits, then gives up. */
    check_timed_timeout_behind_recursive_holder("recursive timed mutex: a foreign timed acquire reports ETIMEDOUT");

    for (size_t nests = recursive_mutex.count; nests > 0; nests--)
        CHECK_EQ("recursive timed mutex: unwinding the nesting", afl_mutex_recursive_unlock(&recursive_mutex), 0);
    CHECK_TRUE(
      "recursive timed mutex: the word is free after the owner tests",
      __atomic_load_n(&recursive_mutex.lock, __ATOMIC_RELAXED) == AFL_UNLOCKED
    );

    /*
     * A waiter that parks behind a holder releases at its deadline with the
     * holder sleeping past it, and acquires when the holder releases early.
     */
    timed_hold_ms = TEST_TIMED_MS * 2;

    if (start_threads(thread, 1, worker_timed_holder, NULL) != 0) {
        test_fail("timed mutex: parked expiry", "could not create the holder thread");
        return;
    }

    timed_wait_for_holder();

    start = deadline_after(0);
    deadline = realtime_after(TEST_TIMED_MS);
    CHECK_EQ(
      "timed mutex: a parked waiter that nobody releases reports ETIMEDOUT", afl_mutex_timedlock(&mutex, &deadline),
      ETIMEDOUT
    );
    CHECK_TRUE("timed mutex: the parked waiter slept until its deadline", elapsed_ms(&start) >= TEST_TIMED_MS - 10);
    CHECK(
      "timed mutex: the parked waiter never slept past its deadline",
      elapsed_ms(&start) < TEST_TIMED_MS + TEST_TIMED_EXPIRY_SLACK_MS, "%u ms", elapsed_ms(&start)
    );

    join_threads(thread, 1);
    CHECK_TRUE("timed mutex: the word is free after the parked expiry", timed_word() == AFL_UNLOCKED);

    timed_hold_ms = TEST_TIMED_MS;

    if (start_threads(thread, 1, worker_timed_holder, NULL) != 0) {
        test_fail("timed mutex: early release", "could not create the holder thread");
        return;
    }

    timed_wait_for_holder();

    start = deadline_after(0);
    deadline = realtime_after(10 * TEST_TIMED_MS);
    CHECK_EQ(
      "timed mutex: a waiter taken behind a holder acquires once it is released",
      afl_mutex_timedlock(&mutex, &deadline), 0
    );
    CHECK(
      "timed mutex: the waiter woke with the release, not with the deadline",
      elapsed_ms(&start) >= TEST_TIMED_MS - 10 && elapsed_ms(&start) < 9 * TEST_TIMED_MS, "%u ms", elapsed_ms(&start)
    );
    CHECK_EQ("timed mutex: unlock after the early release", afl_mutex_unlock(&mutex), 0);

    join_threads(thread, 1);
    CHECK_TRUE("timed mutex: the word is free after the early release", timed_word() == AFL_UNLOCKED);
    CHECK_EQ("timed mutex: no bad holder return in the timed tests", atomic_load(&bad_return), 0);
}

/*
 * The interrupted timed acquire. A signal makes FUTEX_WAIT come back with
 * EINTR, and the timed mutex has to re-arm the remaining timeout from the
 * absolute deadline: a spurious wake up neither loses the acquire when the
 * lock is released before abstime, nor stretches the wait past abstime when
 * it is not. The raiser waits for the waiters bit, which a timed acquire
 * plants just before it parks, then lets a moment pass so the signal really
 * lands inside the system call, exactly as the cond wait test does.
 */
typedef struct
{
    unsigned long target; /* the kernel thread id the signal goes to */
    _Atomic int fired;    /* 1 raised, -1 the helper could not do its job */
} timed_eintr_helper_t;

static void *worker_timed_eintr_raise(void *arg)
{
    timed_eintr_helper_t *helper = arg;
    struct timespec start, delay;
    sigset_t blocked;

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);

    /* The signal is addressed to one thread, but this one must not let a stray
       SIGALRM cut its own nanosleep short. */
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) {
        atomic_store(&helper->fired, -1);
        return NULL;
    }

    start = deadline_after(0);

    while ((timed_word() & AFL_HAVE_WAITERS) == 0) {
        if (elapsed_ms(&start) > TEST_EINTR_DEADLINE_MS) {
            atomic_store(&helper->fired, -1);
            return NULL;
        }

        __afl_pause;
    }

    delay.tv_sec = 0;
    delay.tv_nsec = TEST_EINTR_SETTLE_MS * 1000000L;
    nanosleep(&delay, NULL);

    atomic_store(&helper->fired, test_kill_thread(helper->target, SIGALRM) == 0 ? 1 : -1);

    return NULL;
}

static void test_mutex_timed_eintr(void)
{
    struct sigaction action, previous;
    struct timespec start, deadline;
    timed_eintr_helper_t helper;
    sigset_t unblocked, previous_mask;
    afl_thread_t raiser, holder;
    void *args[1] = {&helper};
    double raised_ms = 0.0;
    int raised = 0;
    int acquired = -1;
    int stretched = -1;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = eintr_handler;
    /* No SA_RESTART: the FUTEX_WAIT has to come back with EINTR instead of being
       restarted behind the back of the header. */
    action.sa_flags = 0;

    if (sigaction(SIGALRM, &action, &previous) != 0) {
        test_skip("timed mutex: an interrupted timed acquire", "could not install the SIGALRM handler");
        return;
    }

    sigemptyset(&unblocked);
    sigaddset(&unblocked, SIGALRM);

    if (sigprocmask(SIG_UNBLOCK, &unblocked, &previous_mask) != 0) {
        test_skip("timed mutex: an interrupted timed acquire", "could not unblock SIGALRM in this thread");
        sigaction(SIGALRM, &previous, NULL);
        return;
    }

    helper.target = afl_thread_self();

    /*
     * Case one: the holder releases at 25 ms, the deadline lies a full second
     * away. The interrupted waiter has to re-arm the rest of it and acquire
     * when the holder releases - an EINTR mistaken for a timeout would report
     * ETIMEDOUT after a few milliseconds here. An attempt whose signal missed
     * the park is retried, bounded, like the cond wait test.
     */
    afl_mutex_destroy(&mutex);

    for (unsigned attempt = 0; attempt < TEST_EINTR_ATTEMPTS && !raised; attempt++) {
        double ms;

        atomic_store(&helper.fired, 0);
        atomic_store_explicit(&eintr_raised, 0, memory_order_relaxed);

        timed_hold_ms = TEST_TIMED_EINTR_HOLD_MS;

        if (start_threads(&holder, 1, worker_timed_holder, NULL) != 0) {
            test_fail("timed mutex: an interrupted timed acquire", "could not create the holder thread");
            break;
        }

        timed_wait_for_holder();

        if (start_threads(&raiser, 1, worker_timed_eintr_raise, args) != 0) {
            test_fail("timed mutex: an interrupted timed acquire", "could not create the raiser thread");
            join_threads(&holder, 1);
            break;
        }

        start = deadline_after(0);
        deadline = realtime_after(TEST_TIMED_EINTR_DEADLINE_MS);
        acquired = afl_mutex_timedlock(&mutex, &deadline);
        ms = elapsed_seconds(&start) * 1000.0;

        join_threads(&raiser, 1);
        join_threads(&holder, 1);

        if (acquired == 0)
            afl_mutex_unlock(&mutex);

        if (
          atomic_load(&helper.fired) == 1 && acquired == 0
          && atomic_load_explicit(&eintr_raised, memory_order_relaxed) != 0 && ms >= TEST_TIMED_EINTR_HOLD_MS - 10
          && ms < TEST_TIMED_EINTR_DEADLINE_MS - 50
        ) {
            raised = 1;
            raised_ms = ms;
        }

        afl_mutex_destroy(&mutex);
    }

    CHECK(
      "timed mutex: an interrupted timed acquire re-arms and acquires", raised == 1,
      "no attempt came back with a successful acquire (last return %d)", acquired
    );
    CHECK(
      "timed mutex: the re-armed acquire waited for the release, not for the deadline",
      raised_ms >= TEST_TIMED_EINTR_HOLD_MS - 10 && raised_ms < TEST_TIMED_EINTR_DEADLINE_MS - 50, "%.2f ms", raised_ms
    );

    /*
     * Case two: the holder keeps the mutex for twice the deadline. The
     * interrupted waiter has to come back with ETIMEDOUT at abstime, not
     * stretch on a stale or dropped timeout: an elapsed bound well under the
     * hold catches a re-arm that ignored the deadline.
     */
    afl_mutex_destroy(&mutex);
    atomic_store_explicit(&eintr_raised, 0, memory_order_relaxed);

    timed_hold_ms = TEST_TIMED_EINTR_LONG_HOLD_MS;

    if (start_threads(&holder, 1, worker_timed_holder, NULL) == 0) {
        timed_wait_for_holder();

        atomic_store(&helper.fired, 0);

        if (start_threads(&raiser, 1, worker_timed_eintr_raise, args) == 0) {
            start = deadline_after(0);
            deadline = realtime_after(TEST_TIMED_STRETCH_MS);
            stretched = afl_mutex_timedlock(&mutex, &deadline);

            join_threads(&raiser, 1);

            CHECK_EQ("timed mutex: the interrupted waiter of a busy holder times out", stretched, ETIMEDOUT);
            CHECK(
              "timed mutex: the stretch check waited until the deadline",
              elapsed_ms(&start) >= TEST_TIMED_STRETCH_MS - 10, "%u ms", elapsed_ms(&start)
            );
            CHECK(
              "timed mutex: the stretch check did not sleep past the deadline",
              elapsed_ms(&start) < TEST_TIMED_STRETCH_MS + TEST_TIMED_EXPIRY_SLACK_MS, "%u ms", elapsed_ms(&start)
            );
        } else {
            test_fail("timed mutex: an interrupted timed acquire", "could not create the raiser thread");
        }

        join_threads(&holder, 1);
    } else {
        test_fail("timed mutex: an interrupted timed acquire", "could not create the holder thread");
    }

    CHECK_TRUE("timed mutex: the word is free after the interrupted acquires", timed_word() == AFL_UNLOCKED);

    /* Leave no handler and no unblocked signal behind for the tests that follow. */
    sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    sigaction(SIGALRM, &previous, NULL);
}

/*
 * Read/write lock tests.
 *
 * Readers overlap on purpose, so the crit_enter overlap counter of the mutex
 * tests cannot measure this lock. The rwlock tests keep their own counters: a
 * writer that finds any other holder inside while it is inside is an overlap,
 * readers overlapping readers is the contract, and the widest reader set seen
 * is what proves it.
 */
#define TEST_RW_TIMED_MS 50

static afl_rwlock_t rwlock;

static _Atomic long rw_holders;        /* readers currently inside */
static _Atomic long rw_writers;        /* writers currently inside */
static _Atomic long rw_holders_max;    /* widest reader set seen at one time */
static _Atomic long rw_writer_overlap; /* writers that overlapped any holder */
static _Atomic long rw_timed_rc;       /* return value of a timed worker */
static _Atomic long rw_pref_done;      /* the preference writer got through */
static struct timespec rw_timed_deadline;

static uint32_t rw_word(void)
{
    return __atomic_load_n(&rwlock, __ATOMIC_RELAXED);
}

static void rw_state_reset(void)
{
    crit_reset();

    atomic_store(&rw_holders, 0);
    atomic_store(&rw_writers, 0);
    atomic_store(&rw_holders_max, 0);
    atomic_store(&rw_writer_overlap, 0);
    atomic_store(&rw_timed_rc, 0);
}

/* The critical section of a reader: registered as a holder, measured for the
   widest concurrent set, and never an overlap by itself. */
static void rw_read_enter(void)
{
    long holders = atomic_fetch_add_explicit(&rw_holders, 1, memory_order_acq_rel) + 1;

    if (atomic_load_explicit(&rw_writers, memory_order_acquire) != 0)
        atomic_fetch_add_explicit(&rw_writer_overlap, 1, memory_order_relaxed);

    long max = atomic_load_explicit(&rw_holders_max, memory_order_relaxed);

    while (holders > max
           && !atomic_compare_exchange_weak_explicit(
             &rw_holders_max, &max, holders, memory_order_relaxed, memory_order_relaxed
           )) {
    }

    atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);

    for (unsigned i = 0; i < crit_spins; i++)
        __afl_pause;
}

static void rw_read_leave(void)
{
    atomic_fetch_sub_explicit(&rw_holders, 1, memory_order_acq_rel);
}

/*
 * The critical section of a writer: a writer that finds another writer or any
 * reader inside at the same time is an overlap the lock must never allow. The
 * reader side checks the same pair, and because both sides register before
 * they look, a real overlap is always seen by whichever of the two registered
 * second.
 */
static void rw_write_enter(void)
{
    if (
      atomic_fetch_add_explicit(&rw_writers, 1, memory_order_acq_rel) != 0
      || atomic_load_explicit(&rw_holders, memory_order_acquire) != 0
    )
        atomic_fetch_add_explicit(&rw_writer_overlap, 1, memory_order_relaxed);

    atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);

    for (unsigned i = 0; i < crit_spins; i++)
        __afl_pause;
}

static void rw_write_leave(void)
{
    atomic_fetch_sub_explicit(&rw_writers, 1, memory_order_acq_rel);
}

static void *worker_rwlock_readers(void *arg)
{
    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (afl_rwlock_rdlock(&rwlock) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            continue;
        }

        rw_read_enter();
        rw_read_leave();

        afl_rwlock_unlock(&rwlock);
    }

    return NULL;
}

static void *worker_rwlock_writers(void *arg)
{
    (void) arg;

    for (unsigned i = 0; i < test_iterations; i++) {
        if (afl_rwlock_wrlock(&rwlock) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            continue;
        }

        rw_write_enter();
        rw_write_leave();

        afl_rwlock_unlock(&rwlock);
    }

    return NULL;
}

/* The argument picks the role: NULL reads, non NULL writes. */
static void *worker_rwlock_mixed(void *arg)
{
    for (unsigned i = 0; i < test_iterations; i++) {
        if (arg ? afl_rwlock_wrlock(&rwlock) != 0 : afl_rwlock_rdlock(&rwlock) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            continue;
        }

        if (arg) {
            rw_write_enter();
            rw_write_leave();
        } else {
            rw_read_enter();
            rw_read_leave();
        }

        afl_rwlock_unlock(&rwlock);
    }

    return NULL;
}

/* The state after a run: every iteration accounted for, everybody out, no
   writer ever shared the lock, and the word back in the free state. */
static void check_rwlock_result(const char *name, unsigned threads)
{
    long expected = (long) threads * (long) test_iterations;

    CHECK(
      name,
      atomic_load(&counter) == expected && atomic_load(&bad_return) == 0 && atomic_load(&rw_writer_overlap) == 0
        && atomic_load(&rw_holders) == 0 && atomic_load(&rw_writers) == 0 && rw_word() == AFL_UNLOCKED,
      "counter %ld/%ld, bad returns %ld, writer overlaps %ld, holders %ld/%ld, word 0x%x", atomic_load(&counter),
      expected, atomic_load(&bad_return), atomic_load(&rw_writer_overlap), atomic_load(&rw_holders),
      atomic_load(&rw_writers), (unsigned) rw_word()
    );
}

static void check_rwlock_readers(const char *name, unsigned threads)
{
    rw_state_reset();

    if (run_threads(threads, worker_rwlock_readers, NULL) != 0) {
        test_fail(name, "could not create %u threads", threads);
        return;
    }

    check_rwlock_result(name, threads);

    if (threads >= 2)
        CHECK(
          name, atomic_load(&rw_holders_max) >= 2, "the readers never shared the lock, widest set %ld",
          atomic_load(&rw_holders_max)
        );
}

static void check_rwlock_writers(const char *name, unsigned threads)
{
    rw_state_reset();

    if (run_threads(threads, worker_rwlock_writers, NULL) != 0) {
        test_fail(name, "could not create %u threads", threads);
        return;
    }

    check_rwlock_result(name, threads);
}

static void check_rwlock_mixed(const char *name, unsigned readers, unsigned writers)
{
    afl_thread_t thread[TEST_MAX_THREADS];
    void *args[TEST_MAX_THREADS];
    unsigned threads = readers + writers;

    for (unsigned i = 0; i < threads; i++)
        args[i] = i < readers ? NULL : (void *) (uintptr_t) 1;

    rw_state_reset();

    if (start_threads(thread, threads, worker_rwlock_mixed, args) != 0) {
        test_fail(name, "could not create %u threads", threads);
        return;
    }

    join_threads(thread, threads);

    check_rwlock_result(name, threads);
}

/*
 * test_rwlock_state walks the lock word through every mode and every try
 * path on a single thread, so that the states themselves and not just the
 * concurrency are checked.
 */
static void test_rwlock_state(void)
{
    afl_rwlock_t rw = AFL_RWLOCK_INIT;

    CHECK_TRUE("rwlock: the initializer is the free word", rw == AFL_UNLOCKED);
    CHECK_EQ("rwlock: init", afl_rwlock_init(&rw), 0);

    CHECK_EQ("rwlock: rdlock", afl_rwlock_rdlock(&rw), 0);
    CHECK_TRUE("rwlock: the word counts one reader", __atomic_load_n(&rw, __ATOMIC_RELAXED) == 1);
    CHECK_EQ("rwlock: tryrdlock joins the readers", afl_rwlock_tryrdlock(&rw), 0);
    CHECK_TRUE("rwlock: the word counts two readers", __atomic_load_n(&rw, __ATOMIC_RELAXED) == 2);

    afl_rwlock_unlock(&rw);
    afl_rwlock_unlock(&rw);
    CHECK_TRUE(
      "rwlock: the word is free after both reader releases", __atomic_load_n(&rw, __ATOMIC_RELAXED) == AFL_UNLOCKED
    );

    CHECK_EQ("rwlock: wrlock", afl_rwlock_wrlock(&rw), 0);
    CHECK_TRUE("rwlock: the word shows the writer", __atomic_load_n(&rw, __ATOMIC_RELAXED) == AFL_RW_WRITER);
    CHECK_EQ("rwlock: tryrdlock on a held writer", afl_rwlock_tryrdlock(&rw), EBUSY);
    CHECK_EQ("rwlock: trywrlock on a held writer", afl_rwlock_trywrlock(&rw), EBUSY);

    afl_rwlock_unlock(&rw);
    CHECK_TRUE("rwlock: the writer release empties the word", __atomic_load_n(&rw, __ATOMIC_RELAXED) == AFL_UNLOCKED);

    /* A refused try has to leave the word exactly as it found it. */
    CHECK_EQ("rwlock: rdlock before the refused trywrlock", afl_rwlock_rdlock(&rw), 0);
    CHECK_EQ("rwlock: trywrlock with a reader inside", afl_rwlock_trywrlock(&rw), EBUSY);
    CHECK_TRUE("rwlock: the refused trywrlock did not touch the word", __atomic_load_n(&rw, __ATOMIC_RELAXED) == 1);
    afl_rwlock_unlock(&rw);

    CHECK_EQ("rwlock: trywrlock on a free word", afl_rwlock_trywrlock(&rw), 0);
    CHECK_TRUE(
      "rwlock: the word shows the writer after the try", __atomic_load_n(&rw, __ATOMIC_RELAXED) == AFL_RW_WRITER
    );
    afl_rwlock_unlock(&rw);

    CHECK_EQ("rwlock: destroy", afl_rwlock_destroy(&rw), 0);
    CHECK_TRUE("rwlock: the word is free after the destroy", __atomic_load_n(&rw, __ATOMIC_RELAXED) == AFL_UNLOCKED);

    /* Saturation must not carry into the writer-claim bit. */
    struct timespec deadline = deadline_after(1000);
    __atomic_store_n(&rw, AFL_RW_COUNT, __ATOMIC_RELAXED);
    CHECK_EQ("rwlock: saturated tryrdlock reports EAGAIN", afl_rwlock_tryrdlock(&rw), EAGAIN);
    CHECK_EQ("rwlock: saturated rdlock reports EAGAIN", afl_rwlock_rdlock(&rw), EAGAIN);
    CHECK_EQ("rwlock: saturated timedrdlock reports EAGAIN", afl_rwlock_timedrdlock(&rw, &deadline), EAGAIN);
    CHECK_TRUE("rwlock: saturation leaves the count unchanged", rw == AFL_RW_COUNT);
    afl_rwlock_unlock(&rw);
    CHECK_EQ("rwlock: a reader can join after saturation drains", afl_rwlock_tryrdlock(&rw), 0);
    CHECK_TRUE("rwlock: the last reader slot was counted", rw == AFL_RW_COUNT);

    /* A late waiter can announce after the previous writer releases. The
     * next writer must inherit the obligation to wake it. */
    __atomic_store_n(&rw, AFL_HAVE_WAITERS, __ATOMIC_RELAXED);
    CHECK_EQ("rwlock: trywrlock acquires a waiters-only word", afl_rwlock_trywrlock(&rw), 0);
    CHECK_TRUE("rwlock: trywrlock preserves the wake obligation", rw == (AFL_RW_WRITER | AFL_HAVE_WAITERS));
    afl_rwlock_unlock(&rw);
    CHECK_TRUE("rwlock: writer with inherited waiters releases", rw == AFL_UNLOCKED);
}

/* The count prediction belongs to a thread, not a lock. Seed it through an
 * unlock on another lock, then check that stale counts and flags still go
 * through a checked acquire. Synthetic counts cover the saturation boundary. */
static void test_rwlock_read_prediction(void)
{
    static const struct
    {
        const char *name;
        uint32_t previous, current;
        int expected;
    } cases[] = {
      {"rwlock: prediction matches another lock",                4,                    3,                    0     },
      {"rwlock: stale prediction finds a free lock",             4,                    AFL_UNLOCKED,         0     },
      {"rwlock: zero prediction finds readers",                  1,                    4,                    0     },
      {"rwlock: prediction preserves a waiters-only word",       1,                    AFL_HAVE_WAITERS,     0     },
      {"rwlock: matching count preserves waiters",               4,                    AFL_HAVE_WAITERS | 3, 0     },
      {"rwlock: previous waiters do not pollute the prediction", AFL_HAVE_WAITERS | 4, 3,                    0     },
      {"rwlock: prediction takes the final reader slot",         AFL_RW_COUNT,         AFL_RW_COUNT - 1,     0     },
      {"rwlock: prediction cannot overflow a saturated count",   AFL_RW_COUNT,         AFL_RW_COUNT,         EAGAIN},
      {"rwlock: stale prediction detects saturation",            1,                    AFL_RW_COUNT,         EAGAIN},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        afl_rwlock_t previous = cases[i].previous;
        afl_rwlock_t current = cases[i].current;
        afl_rwlock_unlock(&previous);

        int rc = afl_rwlock_rdlock(&current);
        CHECK_EQ(cases[i].name, rc, cases[i].expected);
        CHECK_TRUE(
          "rwlock: predicted acquire changes only the accepted reader count", current == cases[i].current + (rc == 0)
        );
        if (rc == 0)
            afl_rwlock_unlock(&current);
        CHECK_TRUE("rwlock: predicted reader release restores the word", current == cases[i].current);
    }
}

static void test_deadline_extremes(void)
{
#define TEST_TIME_MAX ((time_t) (((uintmax_t) 1 << (sizeof(time_t) * 8 - 1)) - 1))
    static const struct
    {
        const char *name;
        struct timespec now, deadline, relative;
        int expired;
    } cases[] = {
      {"deadline: minimum time_t is expired",  {1, 0},           {-TEST_TIME_MAX - 1, 0}, {0, 1},             1},
      {"deadline: full time_t span saturates",
       {-TEST_TIME_MAX - 1, 0},
       {TEST_TIME_MAX, 0},
       {TEST_TIME_MAX, 999999999L},
       0                                                                                                       },
      {"deadline: maximum interval is exact",  {0, 0},           {TEST_TIME_MAX, 0},      {TEST_TIME_MAX, 0}, 0},
      {"deadline: nanosecond borrow",          {10, 900000000L}, {11, 100000000L},        {0, 200000000L},    0},
      {"deadline: equal times have expired",   {10, 100},        {10, 100},               {0, 1},             1},
      {"deadline: one nanosecond remains",     {10, 100},        {10, 101},               {0, 1},             0},
    };
#undef TEST_TIME_MAX

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct timespec relative;
        int rc = __afl_deadline_relative(&cases[i].deadline, &cases[i].now, &relative);
        CHECK_TRUE(
          cases[i].name, rc == cases[i].expired && relative.tv_sec == cases[i].relative.tv_sec
                           && relative.tv_nsec == cases[i].relative.tv_nsec
        );
    }

    __afl_spin_backoff_t backoff;
    __afl_spin_backoff_init(&backoff);
    for (unsigned i = 0; i < 16; i++)
        __afl_spin_backoff(&backoff);
    CHECK_TRUE("backoff: a non-power-of-two cap is respected", backoff.backoff <= AFL_SPIN_BACKOFF);
}

/* Deny waits on this worker only. This exercises real raw syscall errors,
 * including EPERM (-1) with an unrelated ETIMEDOUT left in libc errno. */
static int futex_error_results[12], futex_filter_error;

static void *worker_futex_errors(void *unused)
{
    (void) unused; /* This worker uses only its local lock words. */
    struct sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_futex, 0, 5),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAIT_PRIVATE, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_LOCK_PI_PRIVATE, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_UNLOCK_PI_PRIVATE, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {sizeof(instructions) / sizeof(instructions[0]), instructions};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) != 0) {
        futex_filter_error = errno;
        return NULL;
    }

    afl_mutex_t m = AFL_LOCKED;
    afl_rwlock_t rw = AFL_RW_WRITER;
    afl_cond_t cond = AFL_COND_INIT;
    struct timespec real, mono = deadline_after(5000);
    int rc = afl_clock_gettime(CLOCK_REALTIME, &real);
    if (rc != 0) {
        futex_error_results[0] = rc;
        return NULL;
    }
    real.tv_sec += 5;
    errno = ETIMEDOUT;
    futex_error_results[0] = afl_mutex_lock(&m);
    futex_error_results[1] = afl_mutex_timedlock(&m, &real);
    m = AFL_TID_MASK;
    futex_error_results[2] = afl_mutex_pi_lock(&m);
    m = __afl_gettid() | AFL_HAVE_WAITERS;
    futex_error_results[3] = afl_mutex_pi_unlock(&m);
    futex_error_results[4] = afl_rwlock_timedrdlock(&rw, &mono);
    rw = 1;
    futex_error_results[5] = afl_rwlock_timedwrlock(&rw, &mono);
    futex_error_results[6] = rw == 1 ? 0 : EINVAL;
    m = AFL_LOCKED;
    futex_error_results[7] = afl_cond_wait(&cond, &m);
    futex_error_results[8] = afl_cond_timedwait(&cond, &m, &mono);
    futex_error_results[9] = m == AFL_LOCKED ? 0 : EINVAL;
    futex_error_results[10] = cond.waiters == 0 ? 0 : EINVAL;
    futex_error_results[11] = afl_mutex_unlock(&m);
    return NULL;
}

static void test_futex_errors(void)
{
    void *args[] = {NULL};
    /* run_threads joins the filtered worker before these results are read. */
    CHECK_EQ("futex errors: create and join worker", run_threads(1, worker_futex_errors, args), 0);
    if (futex_filter_error != 0) {
        test_skip("futex errors: syscall filtering", "filter/setup unavailable: %s", strerror(futex_filter_error));
        return;
    }
    static const struct
    {
        const char *name;
        int expected;
    } cases[] = {
      {"futex errors: mutex propagates EPERM",              EPERM},
      {"futex errors: timed mutex ignores stale errno",     EPERM},
      {"futex errors: PI acquire propagates EPERM",         EPERM},
      {"futex errors: PI release propagates EPERM",         EPERM},
      {"futex errors: timed reader propagates EPERM",       EPERM},
      {"futex errors: timed writer propagates EPERM",       EPERM},
      {"futex errors: failed writer removes its claim",     0    },
      {"futex errors: condition wait propagates EPERM",     EPERM},
      {"futex errors: timed condition ignores stale errno", EPERM},
      {"futex errors: condition wait reacquires mutex",     0    },
      {"futex errors: condition wait unregisters waiter",   0    },
      {"futex errors: release reacquired mutex",            0    },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        CHECK_EQ(cases[i].name, futex_error_results[i], cases[i].expected);
}

static void *worker_rwlock_preference(void *arg)
{
    (void) arg;

    if (afl_rwlock_wrlock(&rwlock) == 0) {
        afl_rwlock_unlock(&rwlock);
        atomic_store_explicit(&rw_pref_done, 1, memory_order_release);
    }

    return NULL;
}

/*
 * The documented preference: a writer that found readers plants its claim
 * before it waits, and every new reader waits behind that claim, even the non
 * blocking one, until the readers currently inside have drained.
 */
static void test_rwlock_preference(void)
{
    afl_thread_t writer;
    int claimed = 0;

    afl_rwlock_init(&rwlock);
    atomic_store(&rw_pref_done, 0);

    CHECK_EQ("rwlock: a reader holds the lock in the preference test", afl_rwlock_rdlock(&rwlock), 0);

    if (start_threads(&writer, 1, worker_rwlock_preference, NULL) != 0) {
        test_fail("rwlock: preference", "could not create the writer thread");
        return;
    }

    for (long i = 0; i < TEST_WAIT_SPINS && !claimed; i++) {
        claimed = (rw_word() & AFL_RW_WCLAIM) != 0;
        __afl_pause;
    }

    CHECK_TRUE("rwlock: the waiting writer planted its claim", claimed == 1);
    CHECK_EQ("rwlock: a new reader waits behind the claim", afl_rwlock_tryrdlock(&rwlock), EBUSY);

    /* The last reader out wakes the claimant and lets it promote. */
    afl_rwlock_unlock(&rwlock);
    join_threads(&writer, 1);

    CHECK_EQ("rwlock: the writer got the lock once the readers drained", atomic_load(&rw_pref_done), 1);
    CHECK_TRUE("rwlock: the word is free after the preference test", rw_word() == AFL_UNLOCKED);
}

static void *worker_rwlock_timed_writer(void *arg)
{
    (void) arg;

    atomic_store_explicit(&rw_timed_rc, afl_rwlock_timedwrlock(&rwlock, &rw_timed_deadline), memory_order_release);

    return NULL;
}

static void *worker_rwlock_timed_holder(void *arg)
{
    struct timespec hold;

    (void) arg;

    if (afl_rwlock_wrlock(&rwlock) != 0)
        return NULL;

    hold.tv_sec = 0;
    hold.tv_nsec = (long) TEST_RW_TIMED_MS * 1000000L;
    nanosleep(&hold, NULL);

    afl_rwlock_unlock(&rwlock);

    return NULL;
}

static void test_rwlock_timed(void)
{
    struct timespec start, deadline, long_deadline;
    afl_thread_t thread[1];

    static const long bad_nsec[] = {1000000000L, 2000000000L, -1L, -1000000000L};

    afl_rwlock_init(&rwlock);

    CHECK_EQ("rwlock: a timed read without an abstime is refused", afl_rwlock_timedrdlock(&rwlock, NULL), EINVAL);
    CHECK_EQ("rwlock: a timed write without an abstime is refused", afl_rwlock_timedwrlock(&rwlock, NULL), EINVAL);

    /* Out of range nanosecond fields are refused before anything is touched. */
    for (unsigned i = 0; i < sizeof(bad_nsec) / sizeof(bad_nsec[0]); i++) {
        deadline = deadline_after(TEST_RW_TIMED_MS);
        deadline.tv_nsec = bad_nsec[i];
        start = deadline_after(0);

        CHECK_EQ(
          "rwlock: a timed read with a bad nanosecond field reports EINVAL", afl_rwlock_timedrdlock(&rwlock, &deadline),
          EINVAL
        );
        CHECK_EQ(
          "rwlock: a timed write with a bad nanosecond field reports EINVAL",
          afl_rwlock_timedwrlock(&rwlock, &deadline), EINVAL
        );
        CHECK_TRUE("rwlock: a refused timed acquire returns at once", elapsed_ms(&start) < 1);
        CHECK_TRUE("rwlock: a refused timed acquire does not touch the word", rw_word() == AFL_UNLOCKED);
    }

    /* A deadline at or behind now is a timeout, without a sleep. */
    start = deadline_after(0);
    deadline = deadline_after(-1);
    CHECK_EQ(
      "rwlock: a timed read with an expired deadline reports ETIMEDOUT", afl_rwlock_timedrdlock(&rwlock, &deadline),
      ETIMEDOUT
    );
    CHECK_EQ(
      "rwlock: a timed write with an expired deadline reports ETIMEDOUT", afl_rwlock_timedwrlock(&rwlock, &deadline),
      ETIMEDOUT
    );
    CHECK_TRUE("rwlock: an expired deadline does not sleep", elapsed_ms(&start) < 1);
    CHECK_TRUE("rwlock: an expired deadline does not touch the word", rw_word() == AFL_UNLOCKED);

    /* Uncontended, a generous deadline is simply an immediate success. */
    deadline = deadline_after(1000);
    CHECK_EQ("rwlock: a timed read on a free lock succeeds", afl_rwlock_timedrdlock(&rwlock, &deadline), 0);
    CHECK_TRUE("rwlock: the timed read counted a reader", rw_word() == 1);
    afl_rwlock_unlock(&rwlock);
    CHECK_EQ("rwlock: a timed write on a free lock succeeds", afl_rwlock_timedwrlock(&rwlock, &deadline), 0);
    CHECK_TRUE("rwlock: the timed write set the writer bit", rw_word() == AFL_RW_WRITER);

    /*
     * Blocked acquires time out and leave the holder exactly as it was. The
     * mask keeps the waiters bit out of the comparison: a timed out reader may
     * leave it set, which costs an extra wake up and can never lose one.
     */
    start = deadline_after(0);
    deadline = deadline_after(TEST_RW_TIMED_MS);
    CHECK_EQ(
      "rwlock: a timed read behind a writer reports ETIMEDOUT", afl_rwlock_timedrdlock(&rwlock, &deadline), ETIMEDOUT
    );
    CHECK_TRUE("rwlock: the timed read waited for its deadline", elapsed_ms(&start) >= TEST_RW_TIMED_MS - 10);
    CHECK_TRUE(
      "rwlock: the timed read did not disturb the writer",
      (rw_word() & (AFL_RW_WRITER | AFL_RW_WCLAIM | AFL_RW_COUNT)) == AFL_RW_WRITER
    );

    start = deadline_after(0);
    deadline = deadline_after(TEST_RW_TIMED_MS);
    CHECK_EQ(
      "rwlock: a timed write behind a writer reports ETIMEDOUT", afl_rwlock_timedwrlock(&rwlock, &deadline), ETIMEDOUT
    );
    CHECK_TRUE("rwlock: the timed write waited for its deadline", elapsed_ms(&start) >= TEST_RW_TIMED_MS - 10);
    CHECK_TRUE(
      "rwlock: the timed write did not disturb the holder",
      (rw_word() & (AFL_RW_WRITER | AFL_RW_WCLAIM | AFL_RW_COUNT)) == AFL_RW_WRITER
    );

    afl_rwlock_unlock(&rwlock);
    CHECK_TRUE("rwlock: the word is free after the holder released", rw_word() == AFL_UNLOCKED);

    /*
     * A timed writer that gives up has to hand its claim back: a claim bit
     * without a waiting writer would keep every new reader out with nobody
     * left to release it. The reader holding the lock never lets the drain
     * finish, so the claim has to be visible and then gone again.
     */
    CHECK_EQ("rwlock: a reader holds the lock for the claim test", afl_rwlock_rdlock(&rwlock), 0);

    rw_timed_deadline = deadline_after(TEST_RW_TIMED_MS);
    atomic_store(&rw_timed_rc, 0);

    if (start_threads(thread, 1, worker_rwlock_timed_writer, NULL) != 0) {
        test_fail("rwlock: claim deregistration", "could not create the timed writer thread");
        afl_rwlock_unlock(&rwlock);
        return;
    }

    for (long i = 0; i < TEST_WAIT_SPINS; i++) {
        if (rw_word() & AFL_RW_WCLAIM)
            break;

        __afl_pause;
    }

    CHECK_TRUE("rwlock: the timed writer planted its claim", (rw_word() & AFL_RW_WCLAIM) != 0);

    join_threads(thread, 1);

    CHECK_EQ("rwlock: the timed writer gave up with ETIMEDOUT", atomic_load(&rw_timed_rc), ETIMEDOUT);
    CHECK_TRUE("rwlock: the given up claim is gone", rw_word() == 1);
    CHECK_EQ("rwlock: a reader can join after the claim was handed back", afl_rwlock_tryrdlock(&rwlock), 0);
    CHECK_TRUE("rwlock: the lock counts both readers", rw_word() == 2);

    afl_rwlock_unlock(&rwlock);
    afl_rwlock_unlock(&rwlock);
    CHECK_TRUE("rwlock: the word is free after the claim test", rw_word() == AFL_UNLOCKED);

    /* A timed waiter that is woken early still acquires, long before its
       deadline. */
    if (start_threads(thread, 1, worker_rwlock_timed_holder, NULL) != 0) {
        test_fail("rwlock: early wake up", "could not create the holder thread");
        return;
    }

    for (long i = 0; i < TEST_WAIT_SPINS; i++) {
        if (rw_word() & AFL_RW_WRITER)
            break;

        __afl_pause;
    }

    CHECK_TRUE("rwlock: the writer holds the lock in the early wake test", (rw_word() & AFL_RW_WRITER) != 0);

    start = deadline_after(0);
    long_deadline = deadline_after(10 * TEST_RW_TIMED_MS);
    CHECK_EQ(
      "rwlock: a timed read taken behind a writer succeeds once it is released",
      afl_rwlock_timedrdlock(&rwlock, &long_deadline), 0
    );
    CHECK(
      "rwlock: the timed read woke with the release, not with the deadline",
      elapsed_ms(&start) >= TEST_RW_TIMED_MS - 10 && elapsed_ms(&start) < 9 * TEST_RW_TIMED_MS, "%u ms",
      elapsed_ms(&start)
    );

    join_threads(thread, 1);

    afl_rwlock_unlock(&rwlock);
    CHECK_TRUE("rwlock: the word is free after the early wake test", rw_word() == AFL_UNLOCKED);
}

/*
 * The adaptive mutex: the state of the packed lock word, the hint transitions
 * and what an uncontended acquire costs. The hint field is addressed through
 * the same macros the header uses.
 */
#define TEST_ADAPTIVE_UNCONTENDED_ITERS 20000u
#define TEST_ADAPTIVE_UNCONTENDED_MS    50u

static uint32_t adaptive_word(void)
{
    return __atomic_load_n(&adaptive_mutex, __ATOMIC_RELAXED);
}

static unsigned adaptive_hint(void)
{
    return (unsigned) __afl_adaptive_hint_of(adaptive_word());
}

static void set_adaptive_hint(unsigned hint)
{
    uint32_t word = __atomic_load_n(&adaptive_mutex, __ATOMIC_RELAXED);

    __atomic_store_n(
      &adaptive_mutex, (word & ~AFL_ADAPTIVE_HINT_MASK) | ((uint32_t) hint << AFL_ADAPTIVE_HINT_SHIFT), __ATOMIC_RELEASE
    );
}

/*
 * The queueing thread of the hand-off check: it blocks behind the mutex the
 * main thread already holds and releases it again. Whether its acquire wins in
 * the spin phase or out of the park does not matter for the assertion, both
 * are observed hand-offs and both raise the hint; the wake chain itself is
 * what the stress and parked runs check.
 */
static void *worker_adaptive_queue(void *arg)
{
    (void) arg;

    if (afl_mutex_adaptive_lock(&adaptive_mutex) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    if (afl_mutex_adaptive_unlock(&adaptive_mutex) != 0)
        atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);

    return NULL;
}

static void test_mutex_adaptive(void)
{
    unsigned cores = (unsigned) sysconf(_SC_NPROCESSORS_ONLN);
    struct timespec start;
    void *args[1];
    afl_thread_t thread;
    int rc;

    CHECK_EQ("adaptive mutex: init", afl_mutex_adaptive_init(&adaptive_mutex), 0);
    CHECK_TRUE("adaptive mutex: the init reset the word", adaptive_hint() == 0);
    CHECK_TRUE(
      "adaptive mutex: the init macro is the free word",
      __atomic_load_n(&(afl_mutex_adaptive_t) {AFL_MUTEX_ADAPTIVE_INIT}, __ATOMIC_RELAXED) == 0
    );
    CHECK_EQ("adaptive mutex: uncontended lock", afl_mutex_adaptive_lock(&adaptive_mutex), 0);
    CHECK_TRUE(
      "adaptive mutex: the uncontended fast path leaves the waiters bit clear",
      (__atomic_load_n(&adaptive_mutex, __ATOMIC_RELAXED) & AFL_HAVE_WAITERS) == 0
    );
    CHECK_TRUE(
      "adaptive mutex: the uncontended fast path marks the holder",
      (__atomic_load_n(&adaptive_mutex, __ATOMIC_RELAXED) & AFL_LOCKED) != 0
    );
    CHECK_EQ(
      "adaptive mutex: trylock behind the holder reports EBUSY", afl_mutex_adaptive_trylock(&adaptive_mutex), EBUSY
    );
    CHECK_EQ("adaptive mutex: unlock", afl_mutex_adaptive_unlock(&adaptive_mutex), 0);
    CHECK_TRUE("adaptive mutex: unlock restores the free word", __atomic_load_n(&adaptive_mutex, __ATOMIC_RELAXED) == 0);
    CHECK_EQ("adaptive mutex: lock again after the unlock", afl_mutex_adaptive_lock(&adaptive_mutex), 0);
    CHECK_EQ("adaptive mutex: unlock again", afl_mutex_adaptive_unlock(&adaptive_mutex), 0);
    CHECK_EQ("adaptive mutex: destroy", afl_mutex_adaptive_destroy(&adaptive_mutex), 0);
    CHECK_TRUE("adaptive mutex: the destroyed mutex is free", __atomic_load_n(&adaptive_mutex, __ATOMIC_RELAXED) == 0);

    /*
     * This variant has no owner tracking, so a different thread is allowed to
     * release it, as in afl_mutex_unlock. Only the owner tracked variants
     * reject that.
     */
    CHECK_EQ("adaptive mutex: lock without owner tracking", afl_mutex_adaptive_lock(&adaptive_mutex), 0);
    CHECK_TRUE(
      "adaptive mutex: a foreign thread may release it (there is no owner tracking)",
      run_foreign_unlock(worker_foreign_adaptive_unlock, &adaptive_mutex) == 0 && atomic_load(&foreign_return) == 0
    );

    /* A trylock on a free mutex takes it, without touching the hint. */
    set_adaptive_hint(2);
    CHECK_EQ("adaptive mutex: trylock of a free mutex succeeds", afl_mutex_adaptive_trylock(&adaptive_mutex), 0);
    CHECK_TRUE("adaptive mutex: a successful trylock keeps the hint", adaptive_hint() == 2);
    CHECK_EQ("adaptive mutex: trylock then unlock returns the word", afl_mutex_adaptive_unlock(&adaptive_mutex), 0);
    CHECK_TRUE("adaptive mutex: the release keeps the hint", adaptive_hint() == 2);
    CHECK_EQ("adaptive mutex: destroy after the hint check", afl_mutex_adaptive_destroy(&adaptive_mutex), 0);

    /*
     * The deterministic transitions: every uncontended acquire of a mutex that
     * still carries a hint takes the decay path and lowers it by one, down to
     * zero, where the pure fast path keeps it. The release without waiters
     * leaves the decayed hint alone.
     */
    CHECK_EQ("adaptive mutex: decay start lock", afl_mutex_adaptive_lock(&adaptive_mutex), 0);
    CHECK_EQ("adaptive mutex: decay start unlock", afl_mutex_adaptive_unlock(&adaptive_mutex), 0);
    CHECK_TRUE("adaptive mutex: the uncontended fast path keeps the hint at zero", adaptive_hint() == 0);

    for (unsigned i = 1; i <= AFL_ADAPTIVE_HINT_MAX; i++) {
        set_adaptive_hint(i);
        CHECK_EQ("adaptive mutex: acquiring a hinted mutex uncontended", afl_mutex_adaptive_lock(&adaptive_mutex), 0);
        CHECK_TRUE("adaptive mutex: an uncontended acquire decays the hint by one", adaptive_hint() == i - 1u);
        CHECK_EQ("adaptive mutex: releasing the decayed mutex", afl_mutex_adaptive_unlock(&adaptive_mutex), 0);
        CHECK_TRUE("adaptive mutex: the release of a decayed hint keeps it", adaptive_hint() == i - 1u);
    }

    /*
     * The zero-syscall claim of the uncontended path, checked by behaviour:
     * a futex park and wake round trip costs hundreds of nanoseconds, a CAS
     * pair costs a handful, so an order of magnitude of margin tells the two
     * shapes apart on any machine the suite runs on.
     */
    CHECK_EQ("adaptive mutex: destroy before the timing check", afl_mutex_adaptive_destroy(&adaptive_mutex), 0);

    crit_reset();
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned i = 0; i < TEST_ADAPTIVE_UNCONTENDED_ITERS; i++) {
        if (afl_mutex_adaptive_lock(&adaptive_mutex) != 0 || afl_mutex_adaptive_unlock(&adaptive_mutex) != 0) {
            atomic_fetch_add_explicit(&bad_return, 1, memory_order_relaxed);
            break;
        }
    }

    CHECK(
      "adaptive mutex: the uncontended loop stays out of the kernel", elapsed_ms(&start) < TEST_ADAPTIVE_UNCONTENDED_MS,
      "%u ms", elapsed_ms(&start)
    );
    CHECK_TRUE("adaptive mutex: the timing loop left no bad return", atomic_load(&bad_return) == 0);

    /* The spin budget is the minimum doubled per hint step, clamped at the maximum. */
    CHECK_TRUE(
      "adaptive mutex: the budget is the minimum at hint zero",
      __afl_adaptive_budget(0) == (unsigned) AFL_ADAPTIVE_SPIN_MIN
    );
    CHECK_TRUE(
      "adaptive mutex: the budget doubles with the hint",
      __afl_adaptive_budget((uint32_t) 1 << AFL_ADAPTIVE_HINT_SHIFT) == (unsigned) AFL_ADAPTIVE_SPIN_MIN * 2u
    );
    CHECK_TRUE(
      "adaptive mutex: the budget of a saturated hint is the maximum",
      __afl_adaptive_budget((uint32_t) AFL_ADAPTIVE_HINT_MAX << AFL_ADAPTIVE_HINT_SHIFT)
        == (unsigned) AFL_ADAPTIVE_SPIN_MAX
    );

    /*
     * The observed hand-off multiplies the hint: a second thread queues behind
     * a holder with a long critical section and its acquire raises the hint,
     * either by winning in the spin phase or by winning out of the park. On a
     * machine that cannot over subscribe itself this is skipped, because the
     * queueing thread would find the mutex already released and take the
     * decay path, passing the check for the wrong reason.
     */
    if (cores < 2) {
        test_skip(
          "adaptive mutex: an observed hand-off raises the hint", "only %u core, the hand off is not guaranteed", cores
        );
        CHECK_EQ("adaptive mutex: final destroy", afl_mutex_adaptive_destroy(&adaptive_mutex), 0);
        return;
    }

    args[0] = NULL;
    rc = afl_mutex_adaptive_lock(&adaptive_mutex);

    if (rc != 0) {
        test_fail("adaptive mutex: hand off", "the main thread could not take the mutex (%d)", rc);
        return;
    }

    if (start_threads(&thread, 1, worker_adaptive_queue, args) != 0) {
        test_fail("adaptive mutex: hand off", "could not create the queueing thread");
        afl_mutex_adaptive_unlock(&adaptive_mutex);
        return;
    }

    /*
     * Hold the mutex long enough for the queue to reach the acquire, so the
     * hand-off below is really observed instead of the queue arriving behind
     * the release. The sleep bounds the race that would otherwise make the
     * check pass or fail by scheduling luck.
     */
    {
        struct timespec hold;

        hold.tv_sec = 0;
        hold.tv_nsec = 5 * 1000000L;
        nanosleep(&hold, NULL);
    }

    /* Releasing hands the mutex over; the winner of that hand-off raised the hint. */
    afl_mutex_adaptive_unlock(&adaptive_mutex);
    join_threads(&thread, 1);

    CHECK_TRUE("adaptive mutex: the queueing thread reported no failure", atomic_load(&bad_return) == 0);
    CHECK_TRUE("adaptive mutex: an observed hand-off raises the hint", adaptive_hint() >= 1);

    CHECK_EQ("adaptive mutex: final destroy", afl_mutex_adaptive_destroy(&adaptive_mutex), 0);
    crit_reset();
}

/*
 * afl_clock_gettime, the timed paths that read their deadlines through it, and
 * the raw scheduling system calls of the priority ceiling borrow (tasks 01 and
 * 02).
 *
 * The libc clock_gettime stays the oracle here on purpose: every check that
 * compares a header read against it proves the vDSO entry and the raw fallback
 * answer with the same clocks the rest of the suite already trusts, and the
 * diff between the two is the point of the pin.
 */
#define TEST_CLOCK_TOLERANCE_NS 50000000LL /* the 50 ms budget of an agreement */
#define TEST_CLOCK_NS_PER_SEC   1000000000L

/* a - b in nanoseconds, as wide as the seconds difference needs. */
static long long test_timespec_delta_ns(const struct timespec *a, const struct timespec *b)
{
    return (long long) (a->tv_sec - b->tv_sec) * TEST_CLOCK_NS_PER_SEC + (a->tv_nsec - b->tv_nsec);
}

/*
 * A reader on a fresh thread: its first afl_clock_gettime call has to resolve
 * the vDSO entry for that thread (the cache of the header lives in thread
 * local storage), its second has to come from that cache, both have to
 * succeed, and the pair has to behave like the main thread's reads. The worker
 * publishes its failure count with an atomic add before returning, which the
 * join makes visible to the caller: joining is both the publication and the
 * reap, a detached reader would leave the result race and the thread open.
 */
#define TEST_CLOCK_WARMUP_THREADS 2

static _Atomic long clock_thread_failed; /* errors the per-thread readers saw */
static _Atomic long clock_thread_done;   /* readers that ran to completion */

static void *worker_clock_warmup(void *arg)
{
    struct timespec first, second, oracle;
    long failures = 0;

    (void) arg;

    if (afl_clock_gettime(CLOCK_MONOTONIC, &first) != 0) // the resolution read of this thread
        failures++;

    if (afl_clock_gettime(CLOCK_MONOTONIC, &second) != 0) // the cached read of this thread
        failures++;

    if (second.tv_nsec < 0 || second.tv_nsec >= TEST_CLOCK_NS_PER_SEC)
        failures++;

    if (test_timespec_delta_ns(&second, &first) < 0) // monotonic within the thread as well
        failures++;

    clock_gettime(CLOCK_MONOTONIC, &oracle);

    if (llabs(test_timespec_delta_ns(&second, &oracle)) > TEST_CLOCK_TOLERANCE_NS)
        failures++;

    atomic_fetch_add_explicit(&clock_thread_failed, failures, memory_order_relaxed);
    atomic_fetch_add_explicit(&clock_thread_done, 1, memory_order_relaxed);

    return NULL;
}

static void check_clock_gettime(void)
{
    /* The clocks the header must read like libc does. */
    static const clockid_t tested_clocks[] = {CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME};
    /*
     * The ids the kernel has to refuse: -1, the first id past the static
     * clocks (16 is MAX_CLOCKS, which the clock id allocator never hands
     * out), and the largest positive a clockid_t holds.
     */
    static const clockid_t refused_clocks[] = {(clockid_t) -1, (clockid_t) 16, (clockid_t) INT32_MAX};
    struct timespec mine, oracle, earlier, later;
    int rc;

    for (unsigned i = 0; i < sizeof(tested_clocks) / sizeof(tested_clocks[0]); i++) {
        rc = afl_clock_gettime(tested_clocks[i], &mine);

        CHECK_EQ("clock: afl_clock_gettime reads the clock", rc, 0);
        CHECK_TRUE(
          "clock: tv_nsec is in range after the read", mine.tv_nsec >= 0 && mine.tv_nsec < TEST_CLOCK_NS_PER_SEC
        );

        rc = clock_gettime(tested_clocks[i], &oracle);
        CHECK_EQ("clock: the libc oracle reads the same clock", rc, 0);
        CHECK_TRUE(
          "clock: the header agrees with the libc oracle within 50 ms",
          llabs(test_timespec_delta_ns(&mine, &oracle)) <= TEST_CLOCK_TOLERANCE_NS
        );
    }

    /* Back-to-back CLOCK_MONOTONIC reads never go backwards. */
    rc = afl_clock_gettime(CLOCK_MONOTONIC, &earlier);
    rc |= afl_clock_gettime(CLOCK_MONOTONIC, &later);
    CHECK_TRUE(
      "clock: back-to-back monotonic reads never go backwards", rc == 0 && test_timespec_delta_ns(&later, &earlier) >= 0
    );

    for (unsigned i = 0; i < sizeof(refused_clocks) / sizeof(refused_clocks[0]); i++) {
        int libc_error;
        int libc_rc;

        /*
         * A failing read is not required to leave the struct alone, so the
         * sentinel is not asserted: the return code is the contract (task-04),
         * and it is pinned against the errno the libc oracle takes from the
         * same kernel.
         */
        mine.tv_sec = (time_t) 0xdeadbeef;
        mine.tv_nsec = 0;

        rc = afl_clock_gettime(refused_clocks[i], &mine);

        errno = 0;
        libc_rc = clock_gettime(refused_clocks[i], &oracle);
        CHECK_TRUE("clock: the libc oracle refuses the invalid clock id", libc_rc != 0);

        libc_error = errno;

        CHECK(
          "clock: an invalid clock id returns the error of the libc oracle", rc != 0 && rc == libc_error,
          "id %d: afl returned %d, libc errno was %d", (int) refused_clocks[i], rc, libc_error
        );
    }

    /*
     * A NULL tp. The vDSO validates the clock id before it touches the
     * struct, so the public call refuses an invalid id with a NULL tp without
     * dereferencing, and on the raw fallback the kernel answers EFAULT for a
     * bad pointer, which the wrapper reports as the positive code: no path
     * pinned here faults in user space. (A valid fast-path id with a NULL tp
     * is written unchecked by the vDSO itself, exactly like the libc fast
     * path, and is outside the contract; it is not exercised.)
     */
    CHECK_TRUE("clock: a NULL tp with an invalid clock id is refused", afl_clock_gettime((clockid_t) -1, NULL) != 0);
    CHECK_EQ(
      "clock: the raw fallback with a NULL tp reports EFAULT", __afl_clock_gettime_syscall(CLOCK_MONOTONIC, NULL),
      EFAULT
    );

    /* The per-thread resolution, from threads that never read a clock before. */
    atomic_store(&clock_thread_failed, 0);
    atomic_store(&clock_thread_done, 0);

    if (run_threads(TEST_CLOCK_WARMUP_THREADS, worker_clock_warmup, NULL) != 0) {
        test_fail("clock: per-thread resolution", "could not create the reader threads");
        return;
    }

    CHECK_EQ("clock: every per-thread reader finished", clock_thread_done, TEST_CLOCK_WARMUP_THREADS);
    CHECK_EQ("clock: the TLS resolution works in every thread", clock_thread_failed, 0);
}

/*
 * check_clock_timedwait_paths pins the timed APIs of the header, which task-01
 * moved onto afl_clock_gettime: an expired CLOCK_MONOTONIC abstime on a
 * condition wait and an expired CLOCK_REALTIME abstime behind a holder on a
 * timed lock still report ETIMEDOUT at once with the state untouched. The
 * deadline helpers of the suite build the past abstimes.
 */
static void check_clock_timedwait_paths(void)
{
    struct timespec start, deadline;
    afl_cond_t pin_cond = AFL_COND_INIT;
    afl_mutex_t pin_cond_mutex = AFL_MUTEX_INIT;
    afl_mutex_t pin_timed_mutex = AFL_MUTEX_INIT;

    CHECK_EQ("timed paths: hold the mutex for the condition pin", afl_mutex_lock(&pin_cond_mutex), 0);

    /* A deadline that is already behind: ETIMEDOUT, no sleep, no state change. */
    start = deadline_after(0);
    deadline = deadline_after(-1);
    CHECK_EQ(
      "timed paths: afl_cond_timedwait with a past deadline reports ETIMEDOUT",
      afl_cond_timedwait(&pin_cond, &pin_cond_mutex, &deadline), ETIMEDOUT
    );
    CHECK_TRUE("timed paths: the past-deadline wait returns at once", elapsed_ms(&start) < 1);
    CHECK_TRUE(
      "timed paths: the past-deadline wait registers no waiter",
      __atomic_load_n(&pin_cond.waiters, __ATOMIC_RELAXED) == 0
    );
    CHECK_TRUE(
      "timed paths: the past-deadline wait leaves the mutex held",
      __atomic_load_n(&pin_cond_mutex, __ATOMIC_RELAXED) == AFL_LOCKED
    );

    CHECK_EQ("timed paths: release the condition pin", afl_mutex_unlock(&pin_cond_mutex), 0);
    CHECK_EQ("timed paths: destroy the condition pin", afl_cond_destroy(&pin_cond), 0);
    CHECK_EQ("timed paths: destroy the condition pin mutex", afl_mutex_destroy(&pin_cond_mutex), 0);

    /* A timed lock behind a holder, with an expired CLOCK_REALTIME abstime. */
    CHECK_EQ("timed paths: hold the mutex for the timed lock pin", afl_mutex_lock(&pin_timed_mutex), 0);

    start = deadline_after(0);
    deadline = realtime_after(-1);
    CHECK_EQ(
      "timed paths: afl_mutex_timedlock with an expired abstime reports ETIMEDOUT",
      afl_mutex_timedlock(&pin_timed_mutex, &deadline), ETIMEDOUT
    );
    CHECK_TRUE("timed paths: the expired timed lock returns at once", elapsed_ms(&start) < 1);
    CHECK_TRUE(
      "timed paths: the refused timed lock left the holder alone",
      (__atomic_load_n(&pin_timed_mutex, __ATOMIC_RELAXED) & (AFL_LOCKED | AFL_TID_MASK)) == AFL_LOCKED
    );

    CHECK_EQ("timed paths: release the timed lock pin", afl_mutex_unlock(&pin_timed_mutex), 0);
    CHECK_EQ("timed paths: destroy the timed lock pin", afl_mutex_destroy(&pin_timed_mutex), 0);
}

/*
 * check_pc_borrow_syscall guards the task-02 borrow path. On an unprivileged
 * run (no CAP_SYS_NICE, the default) every elevation attempt is refused with
 * EPERM and the protocol has to degrade silently: the public afl_mutex_pc_*
 * codes stay 0 and thread_priority(), which asks the kernel on every call,
 * reports the very parameters the thread had before the lock, before and
 * after it. When the setup elevation really succeeds (the probe is the
 * capability answer; geteuid() == 0 without the capability still gets EPERM)
 * the check additionally observes the boost through the raw
 * sched_setscheduler and the exact restore of the saved parameters.
 */
static void check_pc_borrow_syscall(void)
{
    struct sched_param saved_param;
    int min = sched_get_priority_min(SCHED_FIFO);
    int max = sched_get_priority_max(SCHED_FIFO);
    int saved_policy;
    int policy_at_lock;
    int policy_during;
    int policy_after;
    int prio_at_lock;
    int prio_during;
    int prio_after;
    int target;
    int error;
    afl_mutex_pc_t m;

    CHECK_EQ("pc borrow: init with the test ceiling", afl_mutex_pc_init(&m, TEST_PC_CEILING), 0);

    /*
     * Move this thread below the mapped ceiling first, so that a real
     * elevation has something to raise; EPERM here is the unprivileged
     * answer and only degrades what the check observes.
     */
    error = pc_make_sub_ceiling(&saved_policy, &saved_param, TEST_PC_CEILING + 5);

    prio_at_lock = thread_priority(&policy_at_lock);

    if (prio_at_lock < 0 || min < 0 || max < 0) {
        test_skip(
          "pc borrow: the holder is elevated through the raw calls",
          "the scheduling parameters of this thread cannot be read"
        );
        test_skip("pc borrow: the release restores the parameters exactly", "the scheduling parameters cannot be read");
    } else if (error != 0 && error != EPERM && error != EACCES) {
        test_skip(
          "pc borrow: the holder is elevated through the raw calls", "the setup probe failed: %s", strerror(error)
        );
        test_skip("pc borrow: the release restores the parameters exactly", "the setup probe failed");
    } else {
        CHECK_EQ("pc borrow: the lock succeeds whatever the elevation answers", afl_mutex_pc_lock(&m), 0);

        target = min + (max - TEST_PC_CEILING);

        if (error != 0) {
            /* Refused: the borrow must not touch the kernel parameters. */
            prio_during = thread_priority(&policy_during);
            CHECK_TRUE(
              "pc borrow: a refused elevation changes nothing while the mutex is held",
              prio_during == prio_at_lock && policy_during == policy_at_lock
            );
        } else if (prio_at_lock >= target) {
            /* At or above the mapped ceiling already: nothing left to borrow. */
            test_skip(
              "pc borrow: the holder is elevated through the raw calls",
              "this thread is already above the mapped ceiling (priority %d)", prio_at_lock
            );
        } else {
            prio_during = thread_priority(&policy_during);

            CHECK_TRUE(
              "pc borrow: the holder is elevated through the raw calls",
              prio_during >= target && (policy_during == SCHED_FIFO || policy_during == SCHED_RR)
            );
        }

        CHECK_EQ("pc borrow: the unlock succeeds", afl_mutex_pc_unlock(&m), 0);

        prio_after = thread_priority(&policy_after);

        /*
         * The pin that holds in every branch: what the kernel reports after
         * the release is what it reported at the acquire. A refused
         * elevation never changed anything, and a real one restores the
         * parameters the acquire saved exactly.
         */
        CHECK_TRUE(
          "pc borrow: the release restores the parameters exactly",
          prio_after == prio_at_lock && policy_after == policy_at_lock
        );

        if (error == 0)
            __afl_sched_setparam(saved_policy, saved_param.sched_priority);
    }

    CHECK_EQ("pc borrow: destroy", afl_mutex_pc_destroy(&m), 0);
}

#ifdef AFL_DEBUG
/*
 * The AFL_DEBUG build. A misuse of the API has to be reported on stderr instead
 * of being silently ignored, which is the whole point of the flag, so the reports
 * are captured and asserted here rather than merely being printed for a human to
 * notice. Build and run this with: make check-debug
 *
 * stderr is redirected into a pipe for the duration of one capture region and put
 * back afterwards. Only stderr is redirected: the check lines of the suite itself
 * go to stdout, so a failure inside a capture region is still visible. The buffer
 * is fixed because the expected output is a handful of short lines; a capture that
 * fills it is reported as a failure instead of being quietly truncated.
 */
#define TEST_STDERR_CAPTURE 32768

static char stderr_capture[TEST_STDERR_CAPTURE];

/* Runs body with stderr captured into out. Returns the number of bytes captured,
   or -1 if the pipe or a dup could not be set up. */
static long capture_stderr(void (*body)(void), char *out, size_t size)
{
    int fds[2];
    int saved;
    long total = 0;

    if (size == 0)
        return -1;

    out[0] = '\0';

    if (pipe(fds) != 0)
        return -1;

    saved = dup(STDERR_FILENO);

    if (saved < 0 || dup2(fds[1], STDERR_FILENO) < 0) {
        if (saved >= 0)
            close(saved);
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    body();
    fflush(NULL);

    if (dup2(saved, STDERR_FILENO) < 0) {
        /* Without stderr the rest of the run would be writing into a pipe that is
           about to be closed, so this is a hard stop rather than a failed check. */
        fprintf(stderr, "could not restore stderr\n");
        return -1;
    }

    close(saved);
    close(fds[1]);

    /* The write end is gone, so the read ends at EOF once the report is out. */
    for (;;) {
        ssize_t got = read(fds[0], out + total, size - 1 - (size_t) total);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            close(fds[0]);
            return -1;
        }

        if (got == 0)
            break;

        total += got;

        if ((size_t) total >= size - 1)
            break;
    }

    close(fds[0]);
    out[total] = '\0';

    return total;
}

static unsigned count_reports(const char *captured, const char *message)
{
    unsigned count = 0;
    const char *at = captured;

    while ((at = strstr(at, message)) != NULL) {
        count++;
        at += strlen(message);
    }

    return count;
}

/*
 * Every misuse the header reports, each of them also checked for the error code it
 * has to return: a report that comes with a wrong return value, or a right return
 * value that comes without a report, is a bug either way.
 */
static long debug_misuse_return;

static void debug_misuses(void)
{
    afl_mutex_adaptive_t am;
    afl_rwlock_t rw;
    afl_mutex_recursive_t r;
    afl_spinlock_t s;
    afl_mutex_t m;
    afl_cond_t c;

    debug_misuse_return = 0;

    /* Owner tracking spinlock: a recursive acquire, the trylock of the held
       lock (EBUSY, reported by the same owner check), then a release by a
       stranger and a release of a lock that is already free. */
    afl_spin_init(&s, 0);
    debug_misuse_return |= afl_spin_owner_lock(&s) != 0;
    debug_misuse_return |= afl_spin_owner_lock(&s) != EDEADLOCK;
    debug_misuse_return |= afl_spin_owner_trylock(&s) != EBUSY;
    debug_misuse_return |= run_foreign_unlock(worker_foreign_spin_unlock, &s) != 0;
    debug_misuse_return |= atomic_load(&foreign_return) != EPERM;
    debug_misuse_return |= afl_spin_owner_unlock(&s) != 0;
    debug_misuse_return |= afl_spin_owner_unlock(&s) != EPERM;

    /* Plain mutex: a release of a mutex that is not held is reported, but it still
       returns success, because this variant tracks no owner. */
    afl_mutex_destroy(&m);
    debug_misuse_return |= afl_mutex_lock(&m) != 0;
    debug_misuse_return |= afl_mutex_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_unlock(&m) != 0;

    /* Owner tracking mutex: same four misuses as the spinlock. */
    debug_misuse_return |= afl_mutex_owner_lock(&m) != 0;
    debug_misuse_return |= afl_mutex_owner_lock(&m) != EDEADLOCK;
    debug_misuse_return |= afl_mutex_owner_trylock(&m) != EBUSY;
    debug_misuse_return |= run_foreign_unlock(worker_foreign_mutex_unlock, &m) != 0;
    debug_misuse_return |= atomic_load(&foreign_return) != EPERM;
    debug_misuse_return |= afl_mutex_owner_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_owner_unlock(&m) != EPERM;

    /* Priority inheriting mutex: the release of a free word is refused, and the
       refusal is reported. */
    afl_mutex_destroy(&m);
    debug_misuse_return |= afl_mutex_pi_lock(&m) != 0;
    debug_misuse_return |= afl_mutex_pi_lock(&m) != EDEADLOCK;
    debug_misuse_return |= afl_mutex_pi_trylock(&m) != EBUSY;
    debug_misuse_return |= run_foreign_unlock(worker_foreign_pi_unlock, &m) != 0;
    debug_misuse_return |= atomic_load(&foreign_return) != EPERM;
    debug_misuse_return |= afl_mutex_pi_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_pi_unlock(&m) != EPERM;

    /*
     * Recursive mutex: the counter overflow guard and the release of a word whose
     * counter says nothing is nested. Neither is reachable by nesting SIZE_MAX deep
     * in a test, so the counter is put at the boundary directly - single threaded
     * and with the word held, which is exactly the state the guard expects.
     */
    afl_mutex_recursive_init(&r);
    debug_misuse_return |= afl_mutex_recursive_lock(&r) != 0;
    r.count = SIZE_MAX;
    debug_misuse_return |= afl_mutex_recursive_lock(&r) != EAGAIN;
    /* The trylock reaches the same boundary through its recursive re-entry. */
    debug_misuse_return |= afl_mutex_recursive_trylock(&r) != EAGAIN;
    r.count = 0;
    debug_misuse_return |= afl_mutex_recursive_unlock(&r) != 0;
    r.count = 1;
    debug_misuse_return |= afl_mutex_recursive_unlock(&r) != 0;
    debug_misuse_return |= run_foreign_unlock(worker_foreign_recursive_unlock, &r) != 0;
    debug_misuse_return |= atomic_load(&foreign_return) != EPERM;

    /* Condition variable: destroying one while a waiter is registered. The waiter
       count is set directly for the same reason as the counters above. */
    afl_cond_init(&c);
    __atomic_store_n(&c.waiters, 1, __ATOMIC_RELAXED);
    debug_misuse_return |= afl_cond_destroy(&c) != 0;
    debug_misuse_return |= __atomic_load_n(&c.waiters, __ATOMIC_RELAXED) != 0;

    /* Read/write lock: destroying one that is still held, once as a reader and
       once as a writer. The destroy reports the misuse and still resets the
       word, which is what leaves it free for the second case. */
    debug_misuse_return |= afl_rwlock_init(&rw) != 0;
    debug_misuse_return |= afl_rwlock_rdlock(&rw) != 0;
    debug_misuse_return |= afl_rwlock_destroy(&rw) != 0;
    debug_misuse_return |= afl_rwlock_wrlock(&rw) != 0;
    debug_misuse_return |= afl_rwlock_destroy(&rw) != 0;
    debug_misuse_return |= rw != AFL_UNLOCKED;

    /* Adaptive mutex: the release of a mutex that is not held is reported but
       still returns success, there is no owner tracking; destroying one that is
       held is reported too, and the destroy still resets the word. */
    debug_misuse_return |= afl_mutex_adaptive_init(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_lock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_unlock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_unlock(&am) != 0;
    debug_misuse_return |= __atomic_load_n(&am, __ATOMIC_RELAXED) != 0;
    debug_misuse_return |= afl_mutex_adaptive_lock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_destroy(&am) != 0;
    debug_misuse_return |= __atomic_load_n(&am, __ATOMIC_RELAXED) != 0;

    /*
     * Priority ceiling mutex: the same misuses as the PI variant (a recursive
     * acquire, a foreign release, a release of a free mutex), each reported by
     * the owner-tid check of the word, plus the trylock of a held mutex, which
     * returns EBUSY without a report, and a destroy of a held mutex, which the
     * word check of the destroy reports while the release check of the next
     * unlock still sees the reset word. The mutex is the one of the contention
     * runs, initialized again here because the misuse capture must not leave
     * it in a state the parked runs would not recover from.
     */
    debug_misuse_return |= afl_mutex_pc_init(&pc_mutex, TEST_PC_CEILING) != 0;
    debug_misuse_return |= afl_mutex_pc_lock(&pc_mutex) != 0;
    debug_misuse_return |= afl_mutex_pc_lock(&pc_mutex) != EDEADLOCK;
    debug_misuse_return |= afl_mutex_pc_trylock(&pc_mutex) != EBUSY;
    debug_misuse_return |= run_foreign_unlock(worker_foreign_pc_unlock, &pc_mutex) != 0;
    debug_misuse_return |= atomic_load(&foreign_return) != EPERM;
    debug_misuse_return |= afl_mutex_pc_destroy(&pc_mutex) != 0;
    debug_misuse_return |= __atomic_load_n(&pc_mutex.lock, __ATOMIC_RELAXED) != AFL_UNLOCKED;
    debug_misuse_return |= afl_mutex_pc_unlock(&pc_mutex) != EPERM;
    debug_misuse_return |= afl_mutex_pc_destroy(&pc_mutex) != 0;
}

/* A well behaved sequence of every kind of lock, which has to report nothing at
   all: a debug build that cries wolf on correct use is worse than no debug build,
   because the reports stop being read. */
static void debug_clean_sequence(void)
{
    afl_mutex_adaptive_t am;
    afl_rwlock_t rw;
    afl_mutex_recursive_t r;
    afl_spinlock_t s;
    afl_mutex_t m;
    afl_cond_t c;
    int ceiling_read;

    debug_misuse_return = 0;

    afl_spin_init(&s, 0);
    debug_misuse_return |= afl_spin_lock(&s) != 0;
    debug_misuse_return |= afl_spin_unlock(&s) != 0;
    debug_misuse_return |= afl_spin_trylock(&s) != 0;
    debug_misuse_return |= afl_spin_unlock(&s) != 0;
    debug_misuse_return |= afl_spin_owner_lock(&s) != 0;
    debug_misuse_return |= afl_spin_owner_unlock(&s) != 0;
    debug_misuse_return |= afl_spin_owner_trylock(&s) != 0;
    debug_misuse_return |= afl_spin_owner_unlock(&s) != 0;
    debug_misuse_return |= afl_spin_destroy(&s) != 0;

    afl_mutex_destroy(&m);
    debug_misuse_return |= afl_mutex_lock(&m) != 0;
    debug_misuse_return |= afl_mutex_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_trylock(&m) != 0;
    debug_misuse_return |= afl_mutex_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_owner_lock(&m) != 0;
    debug_misuse_return |= afl_mutex_owner_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_owner_trylock(&m) != 0;
    debug_misuse_return |= afl_mutex_owner_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_pi_lock(&m) != 0;
    debug_misuse_return |= afl_mutex_pi_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_pi_trylock(&m) != 0;
    debug_misuse_return |= afl_mutex_pi_unlock(&m) != 0;
    debug_misuse_return |= afl_mutex_destroy(&m) != 0;

    afl_mutex_recursive_init(&r);
    debug_misuse_return |= afl_mutex_recursive_lock(&r) != 0;
    debug_misuse_return |= afl_mutex_recursive_lock(&r) != 0;
    debug_misuse_return |= afl_mutex_recursive_unlock(&r) != 0;
    debug_misuse_return |= afl_mutex_recursive_unlock(&r) != 0;
    debug_misuse_return |= afl_mutex_recursive_trylock(&r) != 0;
    debug_misuse_return |= afl_mutex_recursive_unlock(&r) != 0;
    debug_misuse_return |= afl_mutex_recursive_destroy(&r) != 0;

    afl_cond_init(&c);
    debug_misuse_return |= afl_cond_signal(&c) != 0;
    debug_misuse_return |= afl_cond_broadcast(&c) != 0;
    debug_misuse_return |= afl_cond_destroy(&c) != 0;

    afl_rwlock_init(&rw);
    debug_misuse_return |= afl_rwlock_rdlock(&rw) != 0;
    debug_misuse_return |= afl_rwlock_tryrdlock(&rw) != 0;
    afl_rwlock_unlock(&rw);
    afl_rwlock_unlock(&rw);
    debug_misuse_return |= afl_rwlock_wrlock(&rw) != 0;
    debug_misuse_return |= afl_rwlock_trywrlock(&rw) != EBUSY;
    afl_rwlock_unlock(&rw);
    debug_misuse_return |= afl_rwlock_destroy(&rw) != 0;

    afl_mutex_adaptive_init(&am);
    debug_misuse_return |= afl_mutex_adaptive_lock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_trylock(&am) != EBUSY;
    debug_misuse_return |= afl_mutex_adaptive_unlock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_trylock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_unlock(&am) != 0;
    debug_misuse_return |= afl_mutex_adaptive_destroy(&am) != 0;

    afl_mutex_pc_t pc;

    debug_misuse_return |= afl_mutex_pc_init(&pc, TEST_PC_CEILING) != 0;
    debug_misuse_return |= afl_mutex_pc_lock(&pc) != 0;
    debug_misuse_return |= afl_mutex_pc_unlock(&pc) != 0;
    debug_misuse_return |= afl_mutex_pc_trylock(&pc) != 0;
    debug_misuse_return |= afl_mutex_pc_unlock(&pc) != 0;
    debug_misuse_return |= afl_mutex_pc_setceiling(&pc, 1) != 0;
    debug_misuse_return |= afl_mutex_pc_getceiling(&pc, &ceiling_read) != 0;
    debug_misuse_return |= ceiling_read != 1;
    debug_misuse_return |= afl_mutex_pc_destroy(&pc) != 0;
}

static void test_debug_messages(void)
{
    long misused = capture_stderr(debug_misuses, stderr_capture, sizeof(stderr_capture));

    if (misused < 0) {
        test_fail("debug: capture", "stderr could not be redirected");
        return;
    }

    CHECK_EQ("debug: every misuse reported its documented error code", debug_misuse_return, 0);
    CHECK_TRUE("debug: the capture is not truncated", (size_t) misused + 1 < sizeof(stderr_capture));
    /*
     * Every report is "[ERROR] (file:line) text". The file is __FILE__ where the
     * macro is expanded, that is inside the header, and its spelling follows the
     * include path of the build ("./afl.h" with -I.), so only the parts of the
     * prefix that do not depend on how the header was found are checked here.
     */
    CHECK_TRUE(
      "debug: the reports carry the error prefix",
      strncmp(stderr_capture, "[ERROR] (", sizeof("[ERROR] (") - 1) == 0 && strstr(stderr_capture, "afl.h:") != NULL
    );

    CHECK_EQ(
      "debug: a recursive spinlock acquire is reported",
      count_reports(stderr_capture, "An attempt was made to lock an already owned spinlock."), 2
    );
    CHECK_TRUE(
      "debug: a foreign spinlock release is reported",
      count_reports(stderr_capture, "An attempt was made to unlock a spinlock from a non-owner thread.") >= 2
    );
    CHECK_EQ(
      "debug: a release of a free mutex is reported",
      count_reports(stderr_capture, "An attempt was made to unlock an unlocked mutex."), 1
    );
    CHECK_TRUE(
      "debug: a recursive mutex acquire is reported",
      count_reports(stderr_capture, "An attempt was made to lock an already owned mutex.") >= 2
    );
    CHECK_TRUE(
      "debug: a foreign mutex release is reported",
      count_reports(stderr_capture, "An attempt was made to unlock a mutex from a non-owner thread.") >= 2
    );
    CHECK_EQ(
      "debug: the recursive counter overflow is reported",
      count_reports(stderr_capture, "Recursive mutex counter overflow"), 2
    );
    CHECK_EQ(
      "debug: a release of an unlocked recursive mutex is reported",
      count_reports(stderr_capture, "An attempt was made to unlock an unlocked recursive mutex."), 1
    );
    CHECK_EQ(
      "debug: destroying a condition variable with waiters is reported",
      count_reports(stderr_capture, "A condition variable was destroyed while a thread was waiting on it."), 1
    );
    CHECK_EQ(
      "debug: destroying a held rwlock is reported",
      count_reports(stderr_capture, "An attempt was made to destroy a rwlock that is still held."), 2
    );
    CHECK_EQ(
      "debug: a release of a free adaptive mutex is reported",
      count_reports(stderr_capture, "An attempt was made to unlock an unlocked adaptive mutex."), 1
    );
    CHECK_EQ(
      "debug: destroying a held adaptive mutex is reported",
      count_reports(stderr_capture, "An attempt was made to destroy an adaptive mutex that is still held."), 1
    );
    CHECK_EQ(
      "debug: destroying a held priority ceiling mutex is reported",
      count_reports(stderr_capture, "An attempt was made to destroy a priority ceiling mutex that is still held."), 1
    );
    CHECK_EQ(
      "debug: the priority ceiling relock is reported by the owner check",
      count_reports(stderr_capture, "An attempt was made to lock an already owned mutex."), 5
    );
    /*
     * The five reports above are the re-acquires and held trylocks that share
     * the message: owner mutex (lock, trylock), PI mutex (lock, trylock) and
     * the priority ceiling relock. The spinlock misuses report the spinlock
     * message above, and the recursive trylock of a held mutex re-enters, it
     * is not a misuse. The next message is shared by every owner tracking
     * release: here it comes twice from the owner mutex (foreign, free),
     * twice from the PI mutex (foreign, free), once from the recursive mutex
     * (foreign) and twice from the priority ceiling mutex (foreign, free
     * after the destroy).
     */
    CHECK_EQ(
      "debug: the priority ceiling foreign release is reported",
      count_reports(stderr_capture, "An attempt was made to unlock a mutex from a non-owner thread."), 7
    );
    CHECK_EQ(
      "debug: no system call failure is reported for a misuse", count_reports(stderr_capture, "syscall failed"), 0
    );

    if (capture_stderr(debug_clean_sequence, stderr_capture, sizeof(stderr_capture)) < 0) {
        test_fail("debug: capture", "stderr could not be redirected");
        return;
    }

    CHECK_EQ("debug: every clean call returned success", debug_misuse_return, 0);
    CHECK_EQ("debug: a clean sequence reports nothing", (int) strlen(stderr_capture), 0);
}
#endif /* AFL_DEBUG */

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

/* The kernel and the architecture, for the header line of a run. */
static void print_machine_info(unsigned cores)
{
    struct utsname name;
    long online = sysconf(_SC_NPROCESSORS_ONLN);

    printf("afl.h test suite\n");
    printf("  size: %u threads, %u iterations, %u ms timeout\n", test_threads, test_iterations, test_timeout_ms);
    printf("  machine: %u cores (%ld online)\n", cores, online);

    if (uname(&name) == 0)
        printf("  kernel: %s %s %s\n", name.sysname, name.release, name.machine);
    else
        printf("  kernel: unknown (%s)\n", strerror(errno));

    printf("  compiler: %s\n", TEST_COMPILER);
#ifdef AFL_DEBUG
    printf("  build: AFL_DEBUG\n");
#endif
    printf("  run it under more pressure with: AFL_TEST_THREADS=64 AFL_TEST_ITERATIONS=200000 make check\n\n");
}

/*
 * The suite pins itself to the CPUs the machine performs on: the first four
 * logical CPUs of this laptop are the performance cores and the rest are
 * efficiency cores, so a run spread over all of them measures two different
 * machines at once. AFL_TEST_CPUS overrides the set, spelled like taskset's
 * list ("2,4-5"). A failed pinning is reported and the suite continues on
 * whatever CPUs it can see: refusing to run would turn a reportable condition
 * into no report at all.
 */
#define TEST_CPUS_DEFAULT "0-3"

static unsigned test_cpu_count;

static int parse_cpu_list(const char *list, cpu_set_t *cpus)
{
    const char *p = list;

    CPU_ZERO(cpus);

    while (*p != '\0') {
        char *end;
        long first = strtol(p, &end, 10);
        long last = first;

        if (end == p || first < 0 || first >= CPU_SETSIZE)
            return -1;

        p = end;

        if (*p == '-') {
            p++;
            last = strtol(p, &end, 10);

            if (end == p || last < first || last >= CPU_SETSIZE)
                return -1;

            p = end;
        }

        for (long cpu = first; cpu <= last; cpu++)
            CPU_SET((int) cpu, cpus);

        if (*p == ',')
            p++;
        else if (*p != '\0')
            return -1;
    }

    return CPU_COUNT(cpus);
}

static void test_pin_cpus(void)
{
    const char *list = getenv("AFL_TEST_CPUS");
    cpu_set_t cpus;
    int count;

    if (list == NULL || *list == '\0')
        list = TEST_CPUS_DEFAULT;

    count = parse_cpu_list(list, &cpus);

    if (count <= 0) {
        fprintf(stderr, "afl.h test suite: AFL_TEST_CPUS=\"%s\" is not a CPU list, running unpinned\n", list);
        return;
    }

    if (sched_setaffinity(0, sizeof(cpus), &cpus) != 0) {
        fprintf(stderr, "afl.h test suite: could not pin to \"%s\": %s, running unpinned\n", list, strerror(errno));
        return;
    }

    test_cpu_count = (unsigned) count;
}

int main(void)
{
    afl_thread_t watchdog_id = {0};
    unsigned cores;
    unsigned parked_threads;
    unsigned parked_iterations;
    struct timespec started;

    test_pin_cpus();

    cores = test_cpu_count > 0 ? test_cpu_count : (unsigned) sysconf(_SC_NPROCESSORS_ONLN);

    test_threads = env_unsigned("AFL_TEST_THREADS", TEST_THREADS_DEFAULT);
    test_iterations = env_unsigned("AFL_TEST_ITERATIONS", TEST_ITERATIONS_DEFAULT);
    test_timeout_ms = env_unsigned("AFL_TEST_TIMEOUT_MS", TEST_TIMEOUT_MS_DEFAULT);

    /*
     * A request the suite cannot express is refused here instead of being clamped
     * silently: a clamped run reports the number of checks of the smaller size and
     * looks like a passing run of the bigger one.
     */
    if (test_threads > TEST_MAX_THREADS) {
        fprintf(
          stderr,
          "AFL_TEST_THREADS=%u is more than the suite can hold: recompile with TEST_MAX_THREADS >= %u "
          "(currently %d)\n",
          test_threads, test_threads, TEST_MAX_THREADS
        );
        return EXIT_FAILURE;
    }

    /*
     * More threads than cores, so that the waiters really do get parked. This one
     * is derived from the machine and not from a request, so capping it is a
     * decision the suite makes for itself and says so.
     */
    parked_threads = cores * 3;
    parked_iterations = test_iterations / 10 ? test_iterations / 10 : 1;

    if (parked_threads > TEST_MAX_THREADS)
        parked_threads = TEST_MAX_THREADS;

    print_machine_info(cores);

    clock_gettime(CLOCK_MONOTONIC, &started);
    check_clock_restart();

    if (afl_thread_create(&watchdog_id, watchdog, NULL) != 0) {
        fprintf(stderr, "could not start the watchdog thread\n");
        return EXIT_FAILURE;
    }
    afl_thread_detach(&watchdog_id);

    /* Return values, error codes and the state of the lock words. */
    test_tid_cache();
    test_spinlock();
    test_spinlock_owner();
    test_mutex();
    test_mutex_owner();
    test_mutex_pi();
    test_mutex_pc();
    test_mutex_recursive();
    test_mutex_recursive_depth();
    test_destroy_semantics();

    /* Mutual exclusion while every thread hammers the same lock. */
    afl_spin_init(&spinlock, 0);
    afl_mutex_destroy(&mutex); /* leaves the mutex in the free state */
    afl_mutex_recursive_init(&recursive_mutex);
    afl_mutex_adaptive_init(&adaptive_mutex);
    afl_rwlock_init(&rwlock);

    if (afl_mutex_pc_init(&pc_mutex, TEST_PC_CEILING) != 0)
        fprintf(stderr, "could not initialize the priority ceiling mutex for the contention runs\n");

    check_mutual_exclusion("spinlock: mutual exclusion under contention", worker_spinlock, test_threads);
    check_mutual_exclusion("spinlock owner: mutual exclusion under contention", worker_spinlock_owner, test_threads);
    atomic_store(&spin_mixed_next, 0);
    check_mutual_exclusion(
      "spinlock: plain and owner acquires preserve each other's holders", worker_spinlock_mixed,
      test_threads < 2 ? 2 : test_threads
    );
    check_mutual_exclusion("mutex: mutual exclusion under contention", worker_mutex, test_threads);
    check_mutual_exclusion("mutex owner: mutual exclusion under contention", worker_mutex_owner, test_threads);
    check_mutual_exclusion(
      "priority inheritance mutex: mutual exclusion under contention", worker_mutex_pi, test_threads
    );
    check_mutual_exclusion(
      "recursive mutex: mutual exclusion under contention (nested)", worker_mutex_recursive, test_threads
    );
    check_mutual_exclusion("timed mutex: mutual exclusion under contention", worker_mutex_timed, test_threads);
    check_mutual_exclusion(
      "timed mutex owner: mutual exclusion under contention", worker_mutex_owner_timed, test_threads
    );
    check_mutual_exclusion(
      "recursive timed mutex: mutual exclusion under contention (nested)", worker_mutex_recursive_timed, test_threads
    );
    check_mutual_exclusion("adaptive mutex: mutual exclusion under contention", worker_mutex_adaptive, test_threads);
    check_mutual_exclusion("priority ceiling mutex: mutual exclusion under contention", worker_mutex_pc, test_threads);
    check_mutual_exclusion(
      "priority ceiling mutex: mutual exclusion under contention (trylock)", worker_mutex_pc_try, test_threads
    );
    check_mutual_exclusion("spinlock: mutual exclusion under contention (trylock)", worker_spinlock_try, test_threads);
    check_mutual_exclusion(
      "spinlock owner: mutual exclusion under contention (trylock)", worker_spinlock_owner_try, test_threads
    );
    check_mutual_exclusion("mutex: mutual exclusion under contention (trylock)", worker_mutex_try, test_threads);
    check_mutual_exclusion(
      "mutex owner: mutual exclusion under contention (trylock)", worker_mutex_owner_try, test_threads
    );
    check_mutual_exclusion(
      "priority inheritance mutex: mutual exclusion under contention (trylock)", worker_mutex_pi_try, test_threads
    );
    check_mutual_exclusion(
      "recursive mutex: mutual exclusion under contention (trylock)", worker_mutex_recursive_try, test_threads
    );

    /*
     * Read/write lock contention. Readers overlap by contract, so the widest
     * reader set and the writer overlap counters are checked instead of the
     * plain overlap counter, and every fixed mix of the table runs in addition
     * to the mix derived from the requested thread count.
     */
    check_rwlock_readers("rwlock: readers share the lock under contention", test_threads);
    check_rwlock_writers("rwlock: writers exclude each other under contention", test_threads);

    static const unsigned rw_mix[][2] = {
      {1, 1},
      {2, 6},
      {6, 2},
      {8, 0},
      {0, 8},
      {3, 5}
    };

    for (unsigned i = 0; i < sizeof(rw_mix) / sizeof(rw_mix[0]); i++)
        check_rwlock_mixed("rwlock: mixed readers and writers under contention", rw_mix[i][0], rw_mix[i][1]);

    check_rwlock_mixed(
      "rwlock: half readers, half writers under contention", test_threads / 2, test_threads - test_threads / 2
    );

    /*
     * Parked hand off: more threads than cores and a critical section that is
     * longer than the spin phase of the locks, so the waiters block on the futex
     * and the wake up chain is what is being tested. A lost wake up does not
     * return a wrong value, it hangs, which the watchdog reports as a failure.
     *
     * A single core machine cannot over subscribe itself, so the hand off is not
     * what the test claims to be there. It is skipped with a warning rather than
     * run, because a run of it would pass for the wrong reason.
     */
    if (cores < 2) {
        test_skip(
          "mutex: mutual exclusion with parked waiters", "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "mutex owner: mutual exclusion with parked waiters", "only %u core, the waiters are never over subscribed",
          cores
        );
        test_skip(
          "recursive mutex: mutual exclusion with parked waiters",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "rwlock: readers share the lock with parked waiters", "only %u core, the waiters are never over subscribed",
          cores
        );
        test_skip(
          "rwlock: writers exclude each other with parked waiters",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "rwlock: mixed readers and writers with parked waiters",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "timed mutex: mutual exclusion with parked waiters", "only %u core, the waiters are never over subscribed",
          cores
        );
        test_skip(
          "timed mutex owner: mutual exclusion with parked waiters",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "recursive timed mutex: mutual exclusion with parked waiters",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "adaptive mutex: mutual exclusion with parked waiters", "only %u core, the waiters are never over subscribed",
          cores
        );
        test_skip(
          "priority ceiling mutex: mutual exclusion with parked waiters",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "priority ceiling mutex: mutual exclusion with parked waiters (trylock)",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "mutex: mutual exclusion with parked waiters (trylock)",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "mutex owner: mutual exclusion with parked waiters (trylock)",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "priority inheritance mutex: mutual exclusion with parked waiters (trylock)",
          "only %u core, the waiters are never over subscribed", cores
        );
        test_skip(
          "recursive mutex: mutual exclusion with parked waiters (trylock)",
          "only %u core, the waiters are never over subscribed", cores
        );
    } else {
        crit_spins = TEST_CRIT_SPINS_LONG;
        test_iterations = parked_iterations;

        check_mutual_exclusion("mutex: mutual exclusion with parked waiters", worker_mutex, parked_threads);
        check_mutual_exclusion("mutex owner: mutual exclusion with parked waiters", worker_mutex_owner, parked_threads);
        check_mutual_exclusion(
          "priority inheritance mutex: mutual exclusion with parked waiters", worker_mutex_pi, parked_threads
        );
        check_mutual_exclusion(
          "recursive mutex: mutual exclusion with parked waiters", worker_mutex_recursive, parked_threads
        );
        check_mutual_exclusion("timed mutex: mutual exclusion with parked waiters", worker_mutex_timed, parked_threads);
        check_mutual_exclusion(
          "timed mutex owner: mutual exclusion with parked waiters", worker_mutex_owner_timed, parked_threads
        );
        check_mutual_exclusion(
          "recursive timed mutex: mutual exclusion with parked waiters", worker_mutex_recursive_timed, parked_threads
        );
        check_mutual_exclusion(
          "adaptive mutex: mutual exclusion with parked waiters", worker_mutex_adaptive, parked_threads
        );
        check_mutual_exclusion(
          "priority ceiling mutex: mutual exclusion with parked waiters", worker_mutex_pc, parked_threads
        );
        check_mutual_exclusion(
          "priority ceiling mutex: mutual exclusion with parked waiters (trylock)", worker_mutex_pc_try, parked_threads
        );
        check_mutual_exclusion(
          "mutex: mutual exclusion with parked waiters (trylock)", worker_mutex_try, parked_threads
        );
        check_mutual_exclusion(
          "mutex owner: mutual exclusion with parked waiters (trylock)", worker_mutex_owner_try, parked_threads
        );
        check_mutual_exclusion(
          "priority inheritance mutex: mutual exclusion with parked waiters (trylock)", worker_mutex_pi_try,
          parked_threads
        );
        check_mutual_exclusion(
          "recursive mutex: mutual exclusion with parked waiters (trylock)", worker_mutex_recursive_try, parked_threads
        );

        check_rwlock_readers("rwlock: readers share the lock with parked waiters", parked_threads);
        check_rwlock_writers("rwlock: writers exclude each other with parked waiters", parked_threads);

        if (parked_threads >= 4)
            check_rwlock_mixed(
              "rwlock: mixed readers and writers with parked waiters", parked_threads / 2,
              parked_threads - parked_threads / 2
            );
    }

    crit_spins = TEST_CRIT_SPINS_DEFAULT;

    /* One shot initialization. */
    test_once();

    /* Condition variables: the hand off of a wake up. */
    test_cond_state();
    test_cond_broadcast();
    test_cond_signal();
    test_cond_relock();
    test_cond_timedwait();
    test_cond_timedwait_eintr();

    /* Read/write lock: the states, the writer preference and the timed paths. */
    test_rwlock_state();
    test_rwlock_read_prediction();
    test_rwlock_preference();
    test_rwlock_timed();
    test_deadline_extremes();
    test_futex_errors();

    /* Timed mutex acquires: the deadline paths and the interrupted acquire. */
    test_mutex_timed();
    test_mutex_timed_eintr();

    /* Adaptive mutex: the lock word, the hint transitions and the spin budget. */
    test_mutex_adaptive();

    /* afl_clock_gettime against the libc oracle, the timed paths that read their
       deadlines through it, and the raw scheduling calls of the ceiling borrow. */
    check_clock_gettime();
    check_clock_timedwait_paths();
    check_pc_borrow_syscall();

#ifdef AFL_DEBUG
    /* The misuse reports of the debug build, asserted rather than just printed. */
    test_debug_messages();
#endif

    printf("\n  %u passed, %u failed", tests_passed, tests_failed);

    if (tests_skipped != 0)
        printf(", %u skipped", tests_skipped);

    printf(", %u checks total, %.1f s\n", tests_passed + tests_failed, elapsed_seconds(&started));
    printf("  %s\n\n", tests_failed ? "\033[0;31mFAIL\033[0m" : "\033[0;32mPASS\033[0m");

    return tests_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
