/*
 * End-to-end throughput with real pthread workers and no timer in the lock
 * loop. Both implementations use the same payload, affinity and start gate.
 * Usage: throughput [threads [iterations-per-thread [work [rounds]]]]
 * Pin the process with taskset to choose the cores (or to oversubscribe them).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "afl.h"

#define MAX_THREADS 256
#define MAX_ROUNDS  31

static afl_mutex_t am = AFL_MUTEX_INIT;
static afl_spinlock_t as;
static afl_rwlock_t ar = AFL_RWLOCK_INIT;
static pthread_mutex_t pm __attribute__((aligned(64))) = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t ps __attribute__((aligned(64)));
static pthread_rwlock_t pr __attribute__((aligned(64))) = PTHREAD_RWLOCK_INITIALIZER;
static uint64_t counter __attribute__((aligned(64)));
static unsigned ready, start, done;
static size_t iterations = 1000000;
static unsigned work, threads = 4;
static int cpus[CPU_SETSIZE], cpu_count;

static void check(int error)
{
    if (error != 0) {
        fprintf(stderr, "throughput: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }
}

/* Gates sleep so the coordinator does not compete with the timed workers.
 * Release stores publish readiness/completion; acquire loads consume them. */
static void wake(unsigned *word, int count)
{
    long rc = __afl_syscall(__NR_futex, (intptr_t) word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, count, 0);
    if (rc < 0)
        check((int) -rc);
}

static void wait_for_count(unsigned *word, unsigned count)
{
    unsigned value;
    while ((value = __atomic_load_n(word, __ATOMIC_ACQUIRE)) != count) {
        long rc = __afl_syscall(__NR_futex, (intptr_t) word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, value, 0);
        if (rc < 0 && rc != -EINTR && rc != -EAGAIN)
            check((int) -rc);
    }
}

static uint64_t nanoseconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void enter(size_t worker)
{
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpus[worker % cpu_count], &affinity);
    check(pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity));
    if (__atomic_add_fetch(&ready, 1, __ATOMIC_RELEASE) == threads)
        wake(&ready, 1);
    wait_for_count(&start, 1);
}

/* The counter verifies exclusive workloads; readers only load it. */
#define WORKER(name, lock, unlock, writing)                            \
    static void *name(void *arg)                                       \
    {                                                                  \
        enter((size_t) arg);                                           \
        for (size_t i = 0; i < iterations; i++) {                      \
            check(lock);                                               \
            if (writing)                                               \
                counter++;                                             \
            uint64_t value = counter;                                  \
            for (unsigned j = 0; j < work; j++)                        \
                value = value * 1664525 + 1013904223;                  \
            asm volatile("" : "+r"(value) : : "memory");               \
            check(unlock);                                             \
        }                                                              \
        if (__atomic_add_fetch(&done, 1, __ATOMIC_RELEASE) == threads) \
            wake(&done, 1);                                            \
        return NULL;                                                   \
    }

WORKER(afl_mutex_worker, afl_mutex_lock(&am), afl_mutex_unlock(&am), 1)
WORKER(pthread_mutex_worker, pthread_mutex_lock(&pm), pthread_mutex_unlock(&pm), 1)
WORKER(afl_spin_worker, afl_spin_lock(&as), afl_spin_unlock(&as), 1)
WORKER(pthread_spin_worker, pthread_spin_lock(&ps), pthread_spin_unlock(&ps), 1)
WORKER(afl_reader_worker, afl_rwlock_rdlock(&ar), (afl_rwlock_unlock(&ar), 0), 0)
WORKER(pthread_reader_worker, pthread_rwlock_rdlock(&pr), pthread_rwlock_unlock(&pr), 0)
WORKER(afl_writer_worker, afl_rwlock_wrlock(&ar), (afl_rwlock_unlock(&ar), 0), 1)
WORKER(pthread_writer_worker, pthread_rwlock_wrlock(&pr), pthread_rwlock_unlock(&pr), 1)
WORKER(
  afl_mixed_worker, (i % 8 == 0 ? afl_rwlock_wrlock(&ar) : afl_rwlock_rdlock(&ar)), (afl_rwlock_unlock(&ar), 0),
  i % 8 == 0
)
WORKER(
  pthread_mixed_worker, (i % 8 == 0 ? pthread_rwlock_wrlock(&pr) : pthread_rwlock_rdlock(&pr)),
  pthread_rwlock_unlock(&pr), i % 8 == 0
)

typedef void *(*worker_fn)(void *);

static double measure(worker_fn worker, unsigned writes_every)
{
    pthread_t handles[MAX_THREADS];
    ready = start = done = 0;
    counter = 0;
    for (size_t i = 0; i < threads; i++)
        check(pthread_create(&handles[i], NULL, worker, (void *) i));
    wait_for_count(&ready, threads);
    uint64_t begin = nanoseconds();
    __atomic_store_n(&start, 1, __ATOMIC_RELEASE);
    wake(&start, (int) threads);
    wait_for_count(&done, threads);
    uint64_t elapsed = nanoseconds() - begin;
    /* Join every worker before resetting the gates and protected counter. */
    for (unsigned i = 0; i < threads; i++)
        check(pthread_join(handles[i], NULL));
    uint64_t expected = writes_every ? (uint64_t) threads * ((iterations + writes_every - 1) / writes_every) : 0;
    if (counter != expected) {
        fprintf(stderr, "throughput: incorrect protected counter\n");
        exit(EXIT_FAILURE);
    }
    return (double) elapsed / ((double) threads * iterations);
}

static int compare(const void *a, const void *b)
{
    double x = *(const double *) a, y = *(const double *) b;
    return (x > y) - (x < y);
}

static unsigned long number(const char *text, unsigned long max)
{
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || end == text || *end || *text == '-' || value > max) {
        fprintf(stderr, "throughput: invalid argument: %s\n", text);
        exit(EXIT_FAILURE);
    }
    return value;
}

int main(int argc, char **argv)
{
    unsigned rounds = 5;
    cpu_set_t affinity;
    if (argc > 5) {
        fprintf(stderr, "usage: %s [threads [iterations [work [odd-rounds]]]]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc > 1)
        threads = number(argv[1], MAX_THREADS);
    if (argc > 2)
        iterations = number(argv[2], 1000000000);
    if (argc > 3)
        work = number(argv[3], 1000000);
    if (argc > 4)
        rounds = number(argv[4], MAX_ROUNDS);
    if (!threads || !iterations || !rounds || !(rounds & 1)) {
        fprintf(stderr, "throughput: positive threads/iterations and odd rounds required\n");
        return EXIT_FAILURE;
    }
    if (sched_getaffinity(0, sizeof(affinity), &affinity) != 0) {
        perror("sched_getaffinity");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, &affinity))
            cpus[cpu_count++] = i;
    check(pthread_spin_init(&ps, PTHREAD_PROCESS_PRIVATE));
    static const struct
    {
        const char *name;
        worker_fn afl, pthread;
        int writing;
    } cases[] = {
      {"mutex",    afl_mutex_worker,  pthread_mutex_worker,  1},
      {"spin",     afl_spin_worker,   pthread_spin_worker,   1},
      {"rw-read",  afl_reader_worker, pthread_reader_worker, 0},
      {"rw-write", afl_writer_worker, pthread_writer_worker, 1},
      {"rw-mixed", afl_mixed_worker,  pthread_mixed_worker,  8},
    };
    printf("threads=%u iterations=%zu work=%u rounds=%u cpus=%d\n", threads, iterations, work, rounds, cpu_count);
    puts("lock,afl_ns_per_pair,pthread_ns_per_pair,pthread_over_afl");
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        double a[MAX_ROUNDS], p[MAX_ROUNDS];
        /* Warm both implementations (discard timing), then alternate order. */
        (void) measure(cases[c].afl, cases[c].writing);
        (void) measure(cases[c].pthread, cases[c].writing);
        for (unsigned r = 0; r < rounds; r++) {
            if (r & 1) {
                p[r] = measure(cases[c].pthread, cases[c].writing);
                a[r] = measure(cases[c].afl, cases[c].writing);
            } else {
                a[r] = measure(cases[c].afl, cases[c].writing);
                p[r] = measure(cases[c].pthread, cases[c].writing);
            }
        }
        qsort(a, rounds, sizeof(double), compare);
        qsort(p, rounds, sizeof(double), compare);
        printf("%s,%.2f,%.2f,%.3f\n", cases[c].name, a[rounds / 2], p[rounds / 2], p[rounds / 2] / a[rounds / 2]);
        fflush(stdout);
    }
    check(pthread_spin_destroy(&ps));
    check(pthread_mutex_destroy(&pm));
    check(pthread_rwlock_destroy(&pr));
    return EXIT_SUCCESS;
}
