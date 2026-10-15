/*
 * Read/write lock benchmark.
 *
 * Three workloads against pthread_rwlock_t with the identical loop, payload and
 * sampling of the other lock benchmarks: every thread takes the read side, every
 * thread takes the write side, and the mixed run splits the harness threads by
 * parity, half readers and half writers. The mixed run is where a reader/writer
 * lock earns its keep, and also where a waiting writer can cost the readers, so
 * all three are reported side by side.
 */
#include <pthread.h>

#include "afl.h"

#define RUNS_COUNT     100000
#define RUN_ITERATIONS 8
#include "benchmark.h"

static afl_rwlock_t ar = AFL_RWLOCK_INIT;

static pthread_rwlock_t pr = PTHREAD_RWLOCK_INITIALIZER;

static timing_t benchmark_pthread_rwlock_readers(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_rwlock_rdlock(&pr), pthread_rwlock_unlock(&pr), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_rwlock_readers(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_rwlock_rdlock(&ar), (afl_rwlock_unlock(&ar), 0), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_pthread_rwlock_writers(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, pthread_rwlock_wrlock(&pr), pthread_rwlock_unlock(&pr), split);

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_rwlock_writers(size_t iters, benchmark_split *split)
{
    BENCH_LOCK_UNLOCK(iters, afl_rwlock_wrlock(&ar), (afl_rwlock_unlock(&ar), 0), split);

    return split->lock + split->unlock;
}

/*
 * The mixed runs take their role from the worker number, so the very same
 * split of readers and writers goes through both implementations. The acquire is
 * one conditional call and the release does not need the mode, so the macro can
 * keep the loop identical.
 */
static timing_t benchmark_pthread_rwlock_mixed(size_t iters, benchmark_split *split)
{
    const int writer = bench_worker_index % 2;

    BENCH_LOCK_UNLOCK(
      iters, (writer ? pthread_rwlock_wrlock(&pr) : pthread_rwlock_rdlock(&pr)), pthread_rwlock_unlock(&pr), split
    );

    return split->lock + split->unlock;
}

static timing_t benchmark_afl_rwlock_mixed(size_t iters, benchmark_split *split)
{
    const int writer = bench_worker_index % 2;

    BENCH_LOCK_UNLOCK(
      iters, (writer ? afl_rwlock_wrlock(&ar) : afl_rwlock_rdlock(&ar)), (afl_rwlock_unlock(&ar), 0), split
    );

    return split->lock + split->unlock;
}

int main(void)
{
    benchmark_info afl_readers = {.name = "afl rwlock readers", .func = benchmark_afl_rwlock_readers};
    benchmark_info pthread_readers = {.name = "pthread_rwlock readers", .func = benchmark_pthread_rwlock_readers};
    benchmark_info afl_writers = {.name = "afl rwlock writers", .func = benchmark_afl_rwlock_writers};
    benchmark_info pthread_writers = {.name = "pthread_rwlock writers", .func = benchmark_pthread_rwlock_writers};
    benchmark_info afl_mixed = {.name = "afl rwlock mixed", .func = benchmark_afl_rwlock_mixed};
    benchmark_info pthread_mixed = {.name = "pthread_rwlock mixed", .func = benchmark_pthread_rwlock_mixed};

    print_benchmark_note("every thread takes the read side: shared acquire, shared release");
    do_bench(&pthread_readers);
    do_bench(&afl_readers);
    print_benchmark(afl_readers, pthread_readers);

    print_benchmark_note("every thread takes the write side: the lock is used as a mutex");
    do_bench(&pthread_writers);
    do_bench(&afl_writers);
    print_benchmark(afl_writers, pthread_writers);

    print_benchmark_note("half the threads read, half write: the writer preference is in play");
    do_bench(&pthread_mixed);
    do_bench(&afl_mixed);
    print_benchmark(afl_mixed, pthread_mixed);

    return 0;
}
