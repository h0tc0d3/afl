#ifndef __AFL_BENCHMARK_H
#define __AFL_BENCHMARK_H

#include <math.h>
#include <stdio.h>
#include <stdint.h>
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

static inline size_t fibonacci(size_t n)
{
    if (n <= 1)
        return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

typedef timing_t (*benchmark_function_t)(size_t);

typedef struct
{
    char name[128];
    benchmark_function_t func;
    double duration;
    double mean, stdev, min, max;
} benchmark_info;

static int do_bench(benchmark_info *benchmark)
{
    timing_t duration = 0;
    timing_t durations[RUNS_COUNT];
    double mean = 0.0, stdev = 0.0, min = 0.0, max = 0.0;

#pragma omp parallel for proc_bind(spread)
    for (size_t i = 0; i < RUNS_COUNT; i++) {
        durations[i] = benchmark->func(RUN_ITERATIONS);
    }

    for (size_t i = 0; i < RUNS_COUNT; i++) {
        mean += (double) durations[i];
        duration += durations[i];
        if (durations[i] > max)
            max = durations[i];
        else if (durations[i] < max)
            min = durations[i];
    }
    mean /= RUNS_COUNT;

    for (size_t i = 0; i < RUNS_COUNT; i++) {
        double s = (double) durations[i] - mean;
        stdev += s * s;
    }
    stdev               = sqrt(stdev / (RUNS_COUNT - 1));

    benchmark->duration = (double) duration / RUN_ITERATIONS;
    benchmark->min      = min / RUN_ITERATIONS;
    benchmark->max      = max / RUN_ITERATIONS;
    benchmark->stdev    = stdev / RUN_ITERATIONS;
    benchmark->mean     = mean / RUN_ITERATIONS;

    return 0;
}

static int print_benchmark(benchmark_info b1, benchmark_info b2)
{
    const char *plus  = "\033[0;32m[+]\033[0m";
    const char *minus = "\033[0;31m[-]\033[0m";

    printf("\n\n");
    printf("\t\t\t       %s \t\t      %s\n", b1.name, b2.name);
    printf("\t---------------------------------------------------------------\n");
    printf("\t %s  duration:\t %15.2f\t %15.2f\n", b1.duration < b2.duration ? plus : minus, b1.duration, b2.duration);
    printf("\t %s      mean:\t %15.2f\t %15.2f\n", b1.mean < b2.mean ? plus : minus, b1.mean, b2.mean);
    printf("\t %s     stdev:\t %15.2f\t %15.2f\n", b1.stdev < b2.stdev ? plus : minus, b1.stdev, b2.stdev);
    printf("\t %s       min:\t %15.2f\t %15.2f\n", b1.min < b2.min ? plus : minus, b1.min, b2.min);
    printf("\t %s       max:\t %15.2f\t %15.2f\n", b1.max < b2.max ? plus : minus, b1.max, b2.max);
    printf("\t---------------------------------------------------------------\n");
    printf("\t iterations: %d\n", RUNS_COUNT * RUN_ITERATIONS);
    printf("\n\n");

    return 0;
}

#endif /* benchmark.h */
