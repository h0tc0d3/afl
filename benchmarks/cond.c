/*
 * Condition variables.
 *
 * A condition variable has no uncontended case that is worth measuring: a
 * signal that nobody waits for is a no-op in both implementations and a wait
 * only costs anything once another thread wakes it. The hand-off of a wake up
 * from one thread to another is therefore the workload, and it needs a second
 * thread to be the receiver.
 *
 * Every OpenMP worker thread owns a mutex, a condition variable and a partner
 * thread, and the two ping-pong through them: the worker hands the turn to the
 * partner with a signal and blocks in a wait, the partner wakes up, hands the
 * turn straight back the same way and parks again. One iteration is therefore
 * two full signal/wait round trips through one condition variable, and both
 * columns execute exactly the same hand-off. The partner is created the first
 * time a worker runs the benchmark and stays parked until the process exits,
 * which keeps the setup out of the measured region.
 *
 * The measured region is the whole ping-pong, not a single signal or wait, so
 * the split of the lock and unlock times would be misleading and stays unused,
 * the way it does for the recursive mutex benchmark.
 */
#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT 10000
#define RUN_ITERATIONS 8
#include "benchmark.h"

typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_t partner;
    int turn; /* 1 while the turn is with the partner */
} pthread_handoff_t;

typedef struct
{
    afl_mutex_t mutex;
    afl_cond_t cond;
    pthread_t partner;
    int turn; /* 1 while the turn is with the partner */
} afl_handoff_t;

/*
 * The state is heap allocated and referenced from thread local storage, so that
 * a partner thread that outlives the worker it serves only touches memory that
 * stays valid: a parked partner cannot be left behind with a dangling pointer
 * to the thread local storage of a worker that the OpenMP runtime has recycled.
 *
 * The allocation is aligned to a cache line because that is how the afl types
 * are declared, see afl.h.
 */
#define HANDOFF_ALIGNMENT 64

static __thread pthread_handoff_t *pthread_handoff;
static __thread afl_handoff_t *afl_handoff;

static void *handoff_alloc(size_t size)
{
    void *memory = NULL;

    if (posix_memalign(&memory, HANDOFF_ALIGNMENT, size) != 0)
        return NULL;

    memset(memory, 0, size);

    return memory;
}

/*
 * The partner wakes up with the turn, gives it back and parks again. It never
 * returns: it is detached and the process exit is what ends it.
 */
static void *pthread_handoff_partner(void *arg)
{
    pthread_handoff_t *handoff = arg;

    pthread_mutex_lock(&handoff->mutex);

    for (;;) {
        /* Tolerate a spurious wake up: only a set turn is a real one. */
        while (!handoff->turn)
            pthread_cond_wait(&handoff->cond, &handoff->mutex);

        handoff->turn = 0;
        pthread_cond_signal(&handoff->cond);
    }
}

static void *afl_handoff_partner(void *arg)
{
    afl_handoff_t *handoff = arg;

    afl_mutex_lock(&handoff->mutex);

    for (;;) {
        while (!handoff->turn)
            afl_cond_wait(&handoff->cond, &handoff->mutex);

        handoff->turn = 0;
        afl_cond_signal(&handoff->cond);
    }
}

static pthread_handoff_t *pthread_handoff_get(void)
{
    pthread_handoff_t *handoff = pthread_handoff;

    if (handoff != NULL)
        return handoff;

    handoff = handoff_alloc(sizeof(*handoff));

    if (handoff == NULL)
        return NULL;

    pthread_mutex_init(&handoff->mutex, NULL);
    pthread_cond_init(&handoff->cond, NULL);
    pthread_create(&handoff->partner, NULL, pthread_handoff_partner, handoff);
    pthread_detach(handoff->partner);

    pthread_handoff = handoff;

    return handoff;
}

static afl_handoff_t *afl_handoff_get(void)
{
    afl_handoff_t *handoff = afl_handoff;

    if (handoff != NULL)
        return handoff;

    handoff = handoff_alloc(sizeof(*handoff));

    if (handoff == NULL)
        return NULL;

    /* The zeroed allocation is already AFL_MUTEX_INIT and AFL_COND_INIT. */
    pthread_create(&handoff->partner, NULL, afl_handoff_partner, handoff);
    pthread_detach(handoff->partner);

    afl_handoff = handoff;

    return handoff;
}

static timing_t benchmark_pthread_cond(size_t iters, benchmark_split *split)
{
    pthread_handoff_t *handoff = pthread_handoff_get();
    timing_t start, stop, duration;

    (void) split;

    if (handoff == NULL)
        return 0;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        pthread_mutex_lock(&handoff->mutex);

        handoff->turn = 1;
        pthread_cond_signal(&handoff->cond);

        while (handoff->turn)
            pthread_cond_wait(&handoff->cond, &handoff->mutex);

        pthread_mutex_unlock(&handoff->mutex);
    }
    TIMING_NOW(stop);

    TIMING_DIFF(duration, start, stop);

    return duration;
}

static timing_t benchmark_afl_cond(size_t iters, benchmark_split *split)
{
    afl_handoff_t *handoff = afl_handoff_get();
    timing_t start, stop, duration;

    (void) split;

    if (handoff == NULL)
        return 0;

    TIMING_NOW(start);
    for (size_t i = 0; i < iters; i++) {
        afl_mutex_lock(&handoff->mutex);

        handoff->turn = 1;
        afl_cond_signal(&handoff->cond);

        while (handoff->turn)
            afl_cond_wait(&handoff->cond, &handoff->mutex);

        afl_mutex_unlock(&handoff->mutex);
    }
    TIMING_NOW(stop);

    TIMING_DIFF(duration, start, stop);

    return duration;
}

int main(void)
{
    benchmark_info pthread_cond = {.name = "pthread", .func = benchmark_pthread_cond};
    benchmark_info afl_cond     = {.name = "afl", .func = benchmark_afl_cond};

    do_bench(&pthread_cond);
    do_bench(&afl_cond);

    print_benchmark(afl_cond, pthread_cond);

    return 0;
}
