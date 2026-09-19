#ifndef __AFL_BENCHMARK_H
#define __AFL_BENCHMARK_H

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

typedef uint64_t timing_t;

#ifdef USE_CLOCK_GETTIME
/* The clock_gettime (CLOCK_MONOTONIC) has unspecified starting time,
   nano-second accuracy, and for some architectues is implemented as
   vDSO symbol.  */
#define TIMING_NOW(var)                                          \
    ({                                                           \
        struct timespec tv;                                      \
        clock_gettime(CLOCK_MONOTONIC, &tv);                     \
        (var) = (tv.tv_nsec + UINT64_C(1000000000) * tv.tv_sec); \
    })

#else

#ifdef USE_RDTSCP
/* RDTSCP waits until all previous instructions have executed and all
   previous loads are globally visible before reading the counter.
   RDTSC doesn't wait until all previous instructions have been executed
   before reading the counter.  */
#define TIMING_NOW(var)                        \
    (__extension__({                           \
        unsigned int __aux;                    \
        (var) = __builtin_ia32_rdtscp(&__aux); \
    }))
#else
#define TIMING_NOW(var) ((var) = __builtin_ia32_rdtsc())
#endif

#endif

#define TIMING_DIFF(diff, start, end) ((diff) = (end) - (start))
#define TIMING_ADD_DIFF(total, start, end) ((total) += (end) - (start))

#ifndef RUNS_COUNT
#error "RUNS_COUNT not defined!"
#endif

#ifndef RUN_ITERATIONS
#error "RUN_ITERATIONS not defined!"
#endif

/*
 * Amount of work a benchmark executes while it holds the lock.
 *
 * The critical section must not be empty: an empty one reduces the benchmark to
 * an uncontended hand-off and lets the optimizer delete the whole loop body.
 * It has to be identical for both implementations that are compared, and it has
 * to stay constant for the whole run, otherwise the threads keep measuring a
 * workload that keeps changing.
 *
 * bench_work is volatile, so the optimizer cannot constant fold the payload and
 * the acquire of the lock cannot be moved in front of it; bench_sink is a
 * thread local volatile, so the accumulators of the benchmark threads do not
 * share a cache line. Override the size with -DBENCH_WORK=<n>.
 */
#ifndef BENCH_WORK
#define BENCH_WORK 1000
#endif

/* Keeps the payload of the benchmark inside the critical section. */
#define BENCH_BARRIER __asm__ __volatile__("" ::: "memory")

static volatile size_t bench_work __attribute__((unused)) = BENCH_WORK;
static __thread volatile size_t bench_sink __attribute__((unused));

static inline size_t fibonacci(size_t n)
{
    if (n <= 1)
        return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

static inline void bench_payload(void)
{
    size_t work = bench_work;

    for (size_t i = 0; i < work; i++)
        bench_sink += i;

    BENCH_BARRIER;
}

/*
 * Time spent inside the lock and inside the unlock call of a benchmark. Both are
 * measured separately, so that the cost of a hand-off can be attributed to the
 * side where it happens: waiting for the current owner is charged to the lock,
 * the wake up system call to the unlock.
 */
typedef struct
{
    timing_t lock;
    timing_t unlock;
} benchmark_split;

typedef timing_t (*benchmark_function_t)(size_t, benchmark_split *);

/*
 * Measure `iters` lock/unlock pairs with the very same loop for every lock that
 * is being compared. LOCK and UNLOCK are the statements that take and release
 * the lock, split receives the time that was spent in each of them.
 */
#define BENCH_LOCK_UNLOCK(iters, LOCK, UNLOCK, split)                      \
    do {                                                                   \
        timing_t __bench_start, __bench_stop;                              \
        for (size_t __bench_i = 0; __bench_i < (iters); __bench_i++) {     \
            TIMING_NOW(__bench_start);                                     \
            LOCK;                                                          \
            TIMING_NOW(__bench_stop);                                      \
            TIMING_ADD_DIFF((split)->lock, __bench_start, __bench_stop);   \
            bench_payload();                                               \
            BENCH_BARRIER;                                                 \
            TIMING_NOW(__bench_start);                                     \
            UNLOCK;                                                        \
            TIMING_NOW(__bench_stop);                                      \
            TIMING_ADD_DIFF((split)->unlock, __bench_start, __bench_stop); \
        }                                                                  \
    } while (0)

typedef struct
{
    char name[128];
    benchmark_function_t func;
    double duration;
    double mean, stdev, min, max, median;
    double lock_mean, unlock_mean;
} benchmark_info;

static int compare_timing(const void *a, const void *b)
{
    timing_t ta = *(const timing_t *) a;
    timing_t tb = *(const timing_t *) b;

    return (ta > tb) - (ta < tb);
}

static int do_bench(benchmark_info *benchmark)
{
    timing_t duration = 0;
    timing_t durations[RUNS_COUNT];
    benchmark_split splits[RUNS_COUNT];
    size_t warmup_runs = RUNS_COUNT / 16 ? RUNS_COUNT / 16 : 1;
    double mean = 0.0, stdev = 0.0, lock_mean = 0.0, unlock_mean = 0.0;
    double min = INFINITY, max = 0.0, median = 0.0;

    memset(durations, 0, sizeof(durations));
    memset(splits, 0, sizeof(splits));

    /*
     * Warm up first and keep the result out of the statistics: the initial
     * samples contain the startup of the OpenMP thread pool, the first lookup of
     * the thread id of every thread and the first touch of the lock.
     */
#pragma omp parallel for proc_bind(spread)
    for (size_t i = 0; i < warmup_runs; i++) {
        benchmark_split warmup = {0, 0};

        benchmark->func(RUN_ITERATIONS, &warmup);
    }

#pragma omp parallel for proc_bind(spread)
    for (size_t i = 0; i < RUNS_COUNT; i++) {
        durations[i] = benchmark->func(RUN_ITERATIONS, &splits[i]);
    }

    for (size_t i = 0; i < RUNS_COUNT; i++) {
        double v = (double) durations[i];

        mean += v;
        duration += durations[i];
        lock_mean += (double) splits[i].lock;
        unlock_mean += (double) splits[i].unlock;
        if (v > max)
            max = v;
        if (v < min)
            min = v;
    }
    mean /= RUNS_COUNT;
    lock_mean /= RUNS_COUNT;
    unlock_mean /= RUNS_COUNT;

    for (size_t i = 0; i < RUNS_COUNT; i++) {
        double s = (double) durations[i] - mean;

        stdev += s * s;
    }
    stdev = sqrt(stdev / (RUNS_COUNT - 1));

    qsort(durations, RUNS_COUNT, sizeof(timing_t), compare_timing);
    median = (double) durations[RUNS_COUNT / 2];

    /* Everything is reported per lock/unlock pair, just like the iterations. */
    benchmark->duration    = (double) duration / RUN_ITERATIONS;
    benchmark->min         = min / RUN_ITERATIONS;
    benchmark->max         = max / RUN_ITERATIONS;
    benchmark->stdev       = stdev / RUN_ITERATIONS;
    benchmark->mean        = mean / RUN_ITERATIONS;
    benchmark->median      = median / RUN_ITERATIONS;
    benchmark->lock_mean   = lock_mean / RUN_ITERATIONS;
    benchmark->unlock_mean = unlock_mean / RUN_ITERATIONS;

    return 0;
}

/*
 * Layout of the table, shared by the header and by every data row so that the
 * two value columns cannot drift apart. The marker carries ANSI escapes, so it
 * is printed verbatim; the label is right aligned in a 12 column field (the
 * width of the longest label, `unlock time:`) and both numbers are right
 * aligned in 15 column fields. A row is therefore 1 + 3 + 1 + 12 + 2 + 15 + 2 +
 * 15 = 51 columns wide, which is what the rule below spans. The header reuses
 * the same fields with empty marker and label, so the names sit over the
 * numbers.
 */
#define BENCHMARK_HEADER_FORMAT "\t %3s %12s  %15s  %15s\n"
#define BENCHMARK_ROW_FORMAT "\t %s %12s  %15.2f  %15.2f\n"
#define BENCHMARK_RULE "\t---------------------------------------------------\n"

static void print_benchmark_row(const char *marker, const char *label, double left, double right)
{
    printf(BENCHMARK_ROW_FORMAT, marker, label, left, right);
}

static int print_benchmark(benchmark_info b1, benchmark_info b2)
{
    const char *plus  = "\033[0;32m[+]\033[0m";
    const char *minus = "\033[0;31m[-]\033[0m";

    printf("\n\n");
    printf(BENCHMARK_HEADER_FORMAT, "", "", b1.name, b2.name);
    printf("%s", BENCHMARK_RULE);
    print_benchmark_row(b1.duration < b2.duration ? plus : minus, "duration:", b1.duration, b2.duration);
    print_benchmark_row(b1.mean < b2.mean ? plus : minus, "mean:", b1.mean, b2.mean);
    print_benchmark_row(b1.median < b2.median ? plus : minus, "median:", b1.median, b2.median);
    print_benchmark_row(b1.stdev < b2.stdev ? plus : minus, "stdev:", b1.stdev, b2.stdev);
    print_benchmark_row(b1.min < b2.min ? plus : minus, "min:", b1.min, b2.min);
    print_benchmark_row(b1.max < b2.max ? plus : minus, "max:", b1.max, b2.max);

    /*
     * A benchmark of a lock/unlock pair reports both halves. One that measures a
     * bigger workload (the recursive mutex recurses while it holds the lock)
     * leaves them at zero and only has the total.
     */
    if (b1.lock_mean > 0.0 || b2.lock_mean > 0.0) {
        printf("%s", BENCHMARK_RULE);
        print_benchmark_row(b1.lock_mean < b2.lock_mean ? plus : minus, "lock time:", b1.lock_mean, b2.lock_mean);
        print_benchmark_row(
          b1.unlock_mean < b2.unlock_mean ? plus : minus, "unlock time:", b1.unlock_mean, b2.unlock_mean
        );
    }

    printf("%s", BENCHMARK_RULE);
    printf("\t %s/%s mean ratio: %.3f\n", b1.name, b2.name, b2.mean > 0.0 ? b1.mean / b2.mean : 0.0);
    printf("\t iterations: %d\n", RUNS_COUNT * RUN_ITERATIONS);
    printf("\n\n");

    return 0;
}

#endif /* benchmark.h */
