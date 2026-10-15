#ifndef __AFL_BENCHMARK_H
#define __AFL_BENCHMARK_H

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
/*
 * sched.h is here for sched_getaffinity, sched_setaffinity, cpu_set_t and the
 * CPU_ZERO / CPU_ISSET / CPU_SET / CPU_COUNT macros, which glibc exposes only
 * under _GNU_SOURCE. afl.h does not define that macro and this header must not
 * define it either: a #define _GNU_SOURCE only takes effect before the first
 * libc include, so by the time a header that is included after <stdio.h> gets to
 * it the decision is already made. It has to come from the command line, which
 * is what the Makefile's BENCH_CFLAGS does with -D_GNU_SOURCE= (spelled with an
 * empty value so that it is an identical, and therefore benign, redefinition of
 * the "#define _GNU_SOURCE" that benchmark.c and mutex_pi.c carry in source).
 *
 * afl_thread.h is the thread layer the regions run on: raw clone and futex, with
 * no thread runtime to link. A region of one worker runs inline on the calling
 * thread, and a wider region creates one worker per thread.
 */
#include <sched.h>
#include <sys/param.h>
#include "afl_thread.h"
/*
 * __get_cpuid_count, the only way to ask the processor itself for the crystal
 * frequency and the ratio it derives the time stamp counter from. Both compilers
 * of this project ship the header, and only on x86, which is exactly where the
 * counter timer that needs calibrating exists.
 */
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#include "afl.h"

typedef uint64_t timing_t;

#if defined(USE_CLOCK_GETTIME)
/*
 * TIMING_START and TIMING_STOP sample the clock with
 * afl_clock_gettime(CLOCK_MONOTONIC_RAW): nanosecond accuracy, an unspecified
 * starting time, and no libc call (the header resolves the vDSO entry once per
 * thread and falls back to the raw clock_gettime system call). Active when the
 * Makefile is given CLOCK=1, which is also the default on every architecture
 * that is not x86, where the counter read below does not exist.
 *
 * Neither end of the interval needs a fence here: the clock read is a function
 * call, through the vDSO entry or as a system call, and a call is already a
 * compiler and execution barrier. The clock is synchronized across CPUs, so a
 * sample survives moving between cores; the x86 timestamps are per-CPU
 * oscillators instead. For the same reason the migration check has nothing to
 * reject here, and bench_add_half compiles it out on this path instead of
 * leaving a comparison that always matches to be evaluated at run time.
 * TIMING_STOP still stores the constant 0 into bench_timing_cpu, so the slot
 * holds the processor id bench_timing_cpu_id answers on this path.
 */
#define TIMING_START(var)                                        \
    ({                                                           \
        struct timespec tv;                                      \
        afl_clock_gettime(CLOCK_MONOTONIC_RAW, &tv);             \
        (var) = (tv.tv_nsec + UINT64_C(1000000000) * tv.tv_sec); \
    })

#define TIMING_STOP(var)                                         \
    ({                                                           \
        struct timespec tv;                                      \
        afl_clock_gettime(CLOCK_MONOTONIC_RAW, &tv);             \
        (var) = (tv.tv_nsec + UINT64_C(1000000000) * tv.tv_sec); \
        bench_timing_cpu = 0;                                    \
    })

#elif defined(__x86_64__) || defined(__i386__)
/*
 * bench_tsc_read reads the time stamp counter with RDTSCP, returns it and
 * stores the identifier of the processor that served the read in *aux. It
 * holds no fence, so each of TIMING_START and TIMING_STOP below places the one
 * its own position needs; keeping the read apart from the ordering is also what
 * lets the harness take the processor id out of *aux and reject the sample of a
 * thread that migrated between CPUs, without touching the fence placement.
 *
 * The counter is per-CPU and unsynchronized, and the host has to report the
 * rdtscp, constant_tsc and nonstop_tsc CPUID features for its samples to be
 * comparable at all. The unit of a sample is a TSC tick and not a nanosecond;
 * the tick-to-nanosecond conversion belongs to the harness, not to this timer.
 */
static inline uint64_t bench_tsc_read(unsigned *aux)
{
#if defined(__has_builtin) && __has_builtin(__builtin_ia32_rdtscp)
    return __builtin_ia32_rdtscp(aux);
#else
    /* The same read as one inline asm, for a compiler without that builtin. */
    uint32_t lo, hi;
    unsigned int id;

    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(id)::"memory");
    *aux = id;

    return ((uint64_t) hi << 32) | lo;
#endif
}

/*
 * TIMING_START takes the opening sample of a measured region: RDTSCP, then
 * LFENCE. RDTSCP is ordered on one side only, and the opening read is the end
 * whose ordering it does not provide: nothing in the region may be executed
 * speculatively before the timestamp is taken, and only a fence after the read
 * enforces that. The fence carries a "memory" clobber, so the optimizer is
 * bound by it as well as the processor. A leading LFENCE is not a substitute:
 * it orders the read against what came before, which RDTSCP already does, and
 * leaves the region free to hoist above the timestamp.
 *
 * Active on x86_64 and i386, where this is the default timer; the Makefile
 * knob RDTSCP=1 spells that default out and is not required.
 */
#define TIMING_START(var)                            \
    (__extension__({                                 \
        unsigned int __aux;                          \
        uint64_t __tsc = bench_tsc_read(&__aux);     \
        __asm__ __volatile__("lfence" ::: "memory"); \
        (var) = __tsc;                               \
    }))

/*
 * TIMING_STOP takes the closing sample of a measured region: a bare RDTSCP.
 * RDTSCP waits until all earlier instructions have executed and all earlier
 * loads are globally visible before it reads the counter, so at this end it is
 * already the complete barrier and the work of the region cannot retire after
 * it; a fence here would order nothing and only cost cycles.
 *
 * The read also stores the processor id RDTSCP reports into bench_timing_cpu,
 * the per-thread slot the migration check of BENCH_LOCK_UNLOCK reads. The
 * store sits after the closing read, outside the measured interval, and the
 * opening read captures nothing: capturing both ends was measured at +5.7 to
 * +8.2 percent of an uncontended spinlock bracket, which is material against
 * the tens of nanoseconds this harness reports, while the
 * closing capture alone stayed inside the run-to-run noise (the measurement is
 * recorded in .pipeline/solutions/solution-03.md). Comparing the closing id
 * against the CPU this thread is pinned to is just as strong while the pin
 * holds, which bench_pin_this_thread makes the normal case.
 */
#define TIMING_STOP(var)                \
    (__extension__({                    \
        unsigned int __aux;             \
        (var) = bench_tsc_read(&__aux); \
        bench_timing_cpu = __aux;       \
    }))

#else
#error "benchmark.h: no timer for this target; it needs x86 (fenced RDTSCP) or USE_CLOCK_GETTIME (Makefile CLOCK=1)"
#endif

#define TIMING_DIFF(diff, start, end)      ((diff) = (end) - (start))
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

/*
 * Samples taken before the measured ones and kept out of the statistics: they
 * contain the startup of the region's threads, the first lookup of the thread
 * id of every thread and the first touch of the lock. The default is an eighth
 * of the sample count and never less than one. Override with -DBENCH_WARMUP=<n>,
 * or set it to 0 to measure the cold path as well.
 */
#ifndef BENCH_WARMUP
#define BENCH_WARMUP (RUNS_COUNT / 8)
#endif

/*
 * How many threads a measured region runs, the calling thread included.
 *
 * The default is the number of CPUs in the mask this process inherited: when
 * the runner starts a binary it pins the child to its --cpus / AFL_BENCH_CPUS
 * list first, 0-3 by default, so the harness spreads that many workers over the
 * four performance cores and a binary started directly spreads over every
 * online CPU. AFL_BENCH_THREADS overrides the default, and a benchmark that
 * measures splits of its own calls bench_set_threads before do_bench. The value
 * is per process: the harness is one translation unit per binary, so the setting
 * belongs to the binary alone.
 */
#define BENCH_THREADS_ENV "AFL_BENCH_THREADS"

static int bench_threads __attribute__((unused));

/*
 * The CPU mask this process inherited, read once before any thread narrows its
 * own, and the pool every worker of every region is mapped against.
 *
 * The snapshot has to be taken before the first pin because a pin narrows
 * permanently: bench_region_run pins worker 0, which is the calling thread, so
 * a second read of the mask reports the single processor that thread now sits
 * on. A region that read the mask per thread would then map all of its workers
 * onto that one processor, and every region but the first of a run would share
 * a single CPU. bench_parallel fills the pool before it creates anything and
 * bench_cpu_count fills it from the calling thread of do_bench, so the flag is
 * only ever touched by one thread at a time and needs no synchronization.
 */
static cpu_set_t bench_cpu_pool __attribute__((unused));
static int bench_cpu_pool_ready __attribute__((unused));

/*
 * bench_cpu_pool_once fills the pool on its first call and answers how many
 * processors it holds, 0 when the mask could not be read.
 */
static inline int bench_cpu_pool_once(void)
{
    if (bench_cpu_pool_ready != 0)
        return CPU_COUNT(&bench_cpu_pool);

    if (sched_getaffinity(0, sizeof(bench_cpu_pool), &bench_cpu_pool) != 0)
        CPU_ZERO(&bench_cpu_pool);

    bench_cpu_pool_ready = 1;

    return CPU_COUNT(&bench_cpu_pool);
}

/*
 * bench_cpu_count answers the number of CPUs in the inherited affinity mask, or
 * a single CPU when the mask cannot be read, which keeps the default sane
 * everywhere.
 */
static inline int bench_cpu_count(void)
{
    int count = bench_cpu_pool_once();

    return count > 0 ? count : 1;
}

/*
 * bench_thread_count answers the number of threads every region runs, reading
 * the default once. AFL_BENCH_THREADS, when it holds a positive number, wins
 * over the CPU count; anything else is ignored rather than reported, because
 * the count is a convenience and a malformed one has a sane default.
 */
static inline int bench_thread_count(void)
{
    const char *setting;

    if (bench_threads > 0)
        return bench_threads;

    setting = getenv(BENCH_THREADS_ENV);

    if (setting != NULL && *setting != '\0') {
        long value = strtol(setting, NULL, 10);

        if (value > 0 && value < 1000000) {
            bench_threads = (int) value;

            return bench_threads;
        }
    }

    bench_threads = bench_cpu_count();

    return bench_threads;
}

/*
 * bench_set_threads fixes the number of threads for the rest of the process, so
 * that a benchmark with splits of its own can size each of them. A request of
 * one or less is a single thread, never none.
 */
static inline void bench_set_threads(int threads)
{
    bench_threads = threads > 0 ? threads : 1;
}

static volatile size_t bench_work __attribute__((unused)) = BENCH_WORK;
static __thread volatile size_t bench_sink __attribute__((unused));

static inline void bench_payload(void)
{
    size_t work = bench_work;

    for (size_t i = 0; i < work; i++)
        bench_sink += i;

    BENCH_BARRIER;
}

/*
 * The processor that served the closing counter read of the bracket that is
 * currently being accumulated. TIMING_STOP writes it, BENCH_LOCK_UNLOCK reads
 * it right after the bracket to decide whether the sample is trustworthy. It is
 * thread local, so the threads of a parallel region never share it, and it
 * lives outside the bracketed interval, so storing it costs the measurement
 * nothing.
 */
static __thread unsigned bench_timing_cpu __attribute__((unused));

/*
 * The processor this thread pinned itself to, and whether that pinning holds.
 * bench_pin_this_thread writes both once per thread per parallel region, before
 * the first sample; the migration check compares bench_timing_cpu against them.
 * A thread whose pinning failed stays marked unpinned and is never rejected:
 * without a pin there is no expected processor to compare against, and dropping
 * a sample that nothing proves to be bad would be worse than keeping it.
 */
static __thread unsigned bench_thread_cpu __attribute__((unused));
static __thread int bench_thread_pinned __attribute__((unused));

/*
 * Per-thread tally of the bracketed halves this thread measured and of the ones
 * it dropped because the two counter reads came from different processors.
 * do_bench folds both across the measured parallel region and says so once in
 * the output when anything was dropped.
 */
static __thread uint64_t bench_timing_brackets __attribute__((unused));
static __thread uint64_t bench_timing_rejected __attribute__((unused));

/*
 * bench_add_half folds one bracketed half of a lock/unlock pair into `total`,
 * or drops it and counts the drop. `brackets` and `rejected` are the caller's
 * tally, not the thread-local one; BENCH_LOCK_UNLOCK keeps that tally in two
 * locals for the length of its loop and folds them into bench_timing_brackets
 * and bench_timing_rejected once, after it.
 *
 * The counter is per CPU and the two reads of a half are only comparable while
 * both came from the same one, so a half whose closing read reports a processor
 * other than the one this thread is pinned to measured the gap between two
 * unsynchronized oscillators and is not a measurement. It is dropped, and the
 * tally records that, rather than the half landing in the statistics as a
 * number nobody can interpret.
 *
 * A thread that is not pinned has no expected processor to compare against, so
 * its halves are all kept: bench_pin_this_thread already said out loud that the
 * pinning failed, and dropping samples that nothing proves to be bad on top of
 * that would hide the run's real content.
 *
 * On the clock_gettime timer the test is compiled out. That clock is
 * synchronized across CPUs, so a half survives a migration and there is nothing
 * to reject; leaving the comparison in would only evaluate a constant at run
 * time. Compiling it out is also what keeps the loop body of BENCH_LOCK_UNLOCK
 * free of thread-local reads on that path, which matters for code generation:
 * see the comment above that macro.
 *
 * The test sits outside the bracketed interval, between the closing read and
 * the next opening one, so it costs the measurement nothing either way.
 */
static inline void
  bench_add_half(uint64_t *brackets, uint64_t *rejected, timing_t *total, timing_t start, timing_t stop)
{
    (*brackets)++;

#if !defined(USE_CLOCK_GETTIME)
    if (bench_thread_pinned && bench_timing_cpu != bench_thread_cpu) {
        (*rejected)++;
        return;
    }
#endif

    TIMING_ADD_DIFF(*total, start, stop);
}

/*
 * print_benchmark_note is defined below, next to the table it annotates, but the
 * pinning and the calibration report through it from here. The declaration
 * carries the same format attribute as the definition, so the calls below are
 * format checked exactly as the ones after it are.
 */
__attribute__((format(printf, 1, 2))) static inline void print_benchmark_note(const char *format, ...);

/*
 * The processor the counter read reports for this thread, which is what
 * bench_pin_this_thread records as the expected one.
 *
 * On x86 that is the RDTSCP processor id, the same value TIMING_STOP captures,
 * so the two are directly comparable; the counter itself is discarded here
 * because only the processor id is wanted. On the clock_gettime timer there is
 * no processor id to read: that clock is synchronized across CPUs, so a sample
 * survives a migration and there is nothing to reject. It answers the constant
 * that its TIMING_STOP stores, which makes the comparison below match always,
 * and every sample is kept.
 */
static inline unsigned bench_timing_cpu_id(void)
{
#if defined(USE_CLOCK_GETTIME)
    return 0;
#else
    unsigned aux;

    /* The counter is not wanted here, only the processor id it comes with. */
    (void) bench_tsc_read(&aux);

    return aux;
#endif
}

/*
 * Report a pinning failure once per process and mark this thread unpinned. The
 * note names the call that failed and why, so a run whose threads could not be
 * pinned is visible as such instead of quietly measuring across CPUs; the
 * measurement then continues, because a benchmark that cannot pin is still a
 * benchmark, and giving up would turn a reportable condition into no report at
 * all. The exchange is what makes the note print exactly once when several
 * threads fail at the same time.
 */
static int bench_pin_note_printed __attribute__((unused));

static inline int bench_pin_failed(const char *call)
{
    int error = errno;

    bench_thread_cpu = 0;
    bench_thread_pinned = 0;

    if (__atomic_exchange_n(&bench_pin_note_printed, 1, __ATOMIC_ACQ_REL) == 0)
        print_benchmark_note("could not pin the benchmark threads, %s: %s", call, strerror(error));

    errno = error;

    return -1;
}

/*
 * bench_pin_this_thread pins the calling thread to one processor of the pool
 * the process inherited, and answers 0 when that worked or -1 with errno set
 * when it did not. Call it from inside a parallel region, before the first
 * sample.
 *
 * The inherited mask is the contract: when the runner started this binary it
 * pinned the child with sched_setaffinity first, so the pool is the runner's
 * --cpus / AFL_BENCH_CPUS list, and `make bench` is the pinned path. A binary
 * started directly inherits no restriction, its pool is every online CPU, and
 * the same policy then spreads the threads over all of them; that is the spread
 * path. Either way a thread is only ever pinned to a member of the pool, never
 * outside it, so a run cannot end up measuring on CPUs the caller excluded.
 *
 * Which member a thread takes is its worker number modulo the size of the pool,
 * so the threads of one region land on distinct processors until there are more
 * of them than the pool has room for, and two runs with the same thread count
 * pin the same way and stay comparable. Every region maps against the same
 * snapshot, including the regions whose threads were created after worker 0
 * narrowed the calling thread: they inherit that narrow mask and widen it back
 * to the processor the pool assigns them.
 *
 * Pinning is what makes the migration check below meaningful: the time stamp
 * counter is per CPU, so a bracket whose two reads came from different
 * processors compares two unsynchronized oscillators and is not a measurement.
 * With every thread on one known processor, the id captured by the closing read
 * either matches that processor or the thread moved, and the sample is dropped.
 */
static inline int bench_pin_this_thread(unsigned worker)
{
    const cpu_set_t *pool = &bench_cpu_pool;
    cpu_set_t fallback;
    cpu_set_t single;
    int available = bench_cpu_pool_once();
    int wanted;
    int cpu = -1;

    /*
     * A pool that could not be read leaves the calling thread's own mask as the
     * only description available, so fall back to it rather than giving up on
     * pinning altogether.
     */
    if (available <= 0) {
        if (sched_getaffinity(0, sizeof(fallback), &fallback) != 0)
            return bench_pin_failed("sched_getaffinity");

        pool = &fallback;
        available = CPU_COUNT(&fallback);

        if (available <= 0) {
            errno = EINVAL;

            return bench_pin_failed("sched_getaffinity");
        }
    }

    wanted = (int) (worker % (unsigned) available);

    for (int candidate = 0; candidate < CPU_SETSIZE && cpu < 0; candidate++) {
        if (!CPU_ISSET(candidate, pool))
            continue;

        if (wanted-- == 0)
            cpu = candidate;
    }

    if (cpu < 0) {
        errno = EINVAL;

        return bench_pin_failed("sched_getaffinity");
    }

    CPU_ZERO(&single);
    CPU_SET(cpu, &single);

    if (sched_setaffinity(0, sizeof(single), &single) != 0)
        return bench_pin_failed("sched_setaffinity");

    /*
     * Record the processor the counter read reports rather than the one that was
     * asked for: on the x86 timer that is the very value TIMING_STOP captures,
     * so the comparison needs no translation, and on the clock_gettime timer it
     * is the constant that timer stores, so it always matches.
     */
    bench_thread_cpu = bench_timing_cpu_id();
    bench_thread_pinned = 1;

    return 0;
}

/*
 * Nanoseconds per time stamp counter tick. The clock_gettime timer already
 * samples nanoseconds, so it leaves this at 1.0 and every number passes through
 * unchanged; the x86 timer samples ticks and bench_timer_init replaces the 1.0
 * with the measured ratio.
 *
 * Nothing inside a measured loop ever touches this: the accumulators, the
 * TIMING_DIFF and TIMING_ADD_DIFF arithmetic and the sort all stay in raw
 * integer ticks, and the multiplication happens once per statistic, where
 * do_bench turns the accumulated ticks into the doubles it reports. That keeps
 * floating point out of the measured interval and keeps the reported unit the
 * nanosecond the harness has always printed.
 */
static double bench_ns_per_tick = 1.0;

/*
 * bench_ticks_to_ns converts one accumulated tick count into nanoseconds. It
 * takes the double the statistics already turned the tick count into, so the
 * conversion is the one multiplication at the reporting boundary and nothing
 * else; on the clock_gettime timer the ratio is 1.0 and the value passes
 * through unchanged.
 */
static inline double bench_ticks_to_ns(double ticks)
{
    return ticks * bench_ns_per_tick;
}

#if !defined(USE_CLOCK_GETTIME)

/* 8 trials of 2 ms each: about 16 ms of calibration, and enough trials that one
   disturbed by an interrupt does not decide the ratio. */
#define BENCH_CALIBRATION_TRIALS 8
#define BENCH_CALIBRATION_NS     UINT64_C(2000000)

/* The firmware's own answer, when the host exposes one, in hertz. */
#define BENCH_TSC_FREQ_SYSFS "/sys/devices/system/cpu/cpu0/tsc_freq_khz"

/*
 * bench_measure_ticks_per_ns calibrates the counter against
 * CLOCK_MONOTONIC_RAW: bracket a bounded interval with a paired RDTSCP and
 * clock read, and divide. Several trials run and the smallest ticks-per-
 * nanosecond ratio is kept, because every disturbance of a trial - an
 * interrupt, a migration, the clock read taking the slow syscall path - can
 * only add time or ticks to the interval and so can only push the ratio up.
 * The least disturbed trial is therefore the smallest one. Answers 0.0 when the
 * clock cannot be read at all.
 */
static inline double bench_measure_ticks_per_ns(void)
{
    double best = 0.0;

    for (int trial = 0; trial < BENCH_CALIBRATION_TRIALS; trial++) {
        struct timespec start, stop;
        uint64_t ticks_start, ticks_stop;
        int64_t elapsed_seconds;
        int64_t elapsed;
        double ratio;
        unsigned aux;

        if (afl_clock_gettime(CLOCK_MONOTONIC_RAW, &start) != 0)
            return best;

        ticks_start = bench_tsc_read(&aux);

        do {
            if (afl_clock_gettime(CLOCK_MONOTONIC_RAW, &stop) != 0)
                return best;

            elapsed_seconds = (int64_t) (stop.tv_sec - start.tv_sec) * INT64_C(1000000000);
            elapsed = elapsed_seconds + (int64_t) (stop.tv_nsec - start.tv_nsec);
        } while (elapsed < (int64_t) BENCH_CALIBRATION_NS);

        ticks_stop = bench_tsc_read(&aux);

        if (elapsed <= 0)
            continue;

        ratio = (double) (ticks_stop - ticks_start) / (double) elapsed;

        if (best == 0.0 || ratio < best)
            best = ratio;
    }

    return best;
}

/*
 * bench_cpuid_tsc_hz asks the processor for its time stamp counter frequency
 * through CPUID leaf 0x15: eax is the crystal clock ratio, ebx the counter
 * ratio and ecx the crystal frequency in hertz, so the counter runs at
 * ecx * ebx / eax. Answers 0.0 when the leaf does not exist or reports a zero
 * field, which is what an older or a virtualized host does.
 *
 * The highest supported leaf is checked first because __get_cpuid_count answers
 * success unconditionally on some compilers and would otherwise hand back
 * whatever the unsupported leaf left in the registers.
 */
static inline double bench_cpuid_tsc_hz(void)
{
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;

    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx))
        return 0.0;

    if (eax < 0x15)
        return 0.0;

    eax = ebx = ecx = edx = 0;

    if (!__get_cpuid_count(0x15, 0, &eax, &ebx, &ecx, &edx))
        return 0.0;

    if (eax == 0 || ebx == 0 || ecx == 0)
        return 0.0;

    return (double) ecx * ((double) ebx / (double) eax);
}

/*
 * bench_sysfs_tsc_hz reads the counter frequency the kernel published for this
 * host, in kilohertz, and answers it in hertz, or 0.0 when the attribute does
 * not exist or does not hold a positive number. It is the second firmware
 * source, for a host that exposes it but not CPUID leaf 0x15.
 */
static inline double bench_sysfs_tsc_hz(void)
{
    char buffer[32];
    ssize_t bytes;
    double khz;
    int descriptor;

    descriptor = open(BENCH_TSC_FREQ_SYSFS, O_RDONLY | O_CLOEXEC);

    if (descriptor < 0)
        return 0.0;

    bytes = read(descriptor, buffer, sizeof(buffer) - 1);

    /*
     * A read-only sysfs attribute has nothing to flush, so close() cannot lose
     * data here; a failure still means the descriptor was not released cleanly,
     * and the value is then treated as unavailable rather than half trusted.
     */
    if (close(descriptor) != 0)
        return 0.0;

    if (bytes <= 0)
        return 0.0;

    buffer[bytes] = '\0';
    khz = strtod(buffer, NULL);

    return khz > 0.0 ? khz * 1000.0 : 0.0;
}

/*
 * The single shot body of bench_timer_init: pick the ratio, then cross-check it.
 *
 * A firmware value is preferred over the measured one when the host exposes
 * either source, because it is exact by construction where the measurement is
 * only as good as its least disturbed trial. The measurement is what decides
 * whether that preference is safe: the two are compared, and when they disagree
 * by more than two percent one note says which value is in use and why, so a
 * host whose firmware lies reports the lie instead of silently converting every
 * number by it.
 *
 * Nothing here ever fails the run. With no firmware value the measurement is
 * used, and with neither the ratio stays at 1.0 and the tables report raw ticks
 * under a note that says so, because a number labelled with the wrong unit is
 * worse than a number the reader was warned about.
 */
__attribute__((unused)) static void bench_timer_init_once(void)
{
    const char *source = "the measured ratio";
    double measured = bench_measure_ticks_per_ns();
    double reported = bench_cpuid_tsc_hz();
    double ticks_per_ns;

    if (reported > 0.0) {
        source = "CPUID leaf 0x15";
    } else {
        reported = bench_sysfs_tsc_hz();

        if (reported > 0.0)
            source = BENCH_TSC_FREQ_SYSFS;
    }

    if (reported > 0.0)
        ticks_per_ns = reported / 1000000000.0;
    else if (measured > 0.0)
        ticks_per_ns = measured;
    else
        ticks_per_ns = 0.0;

    if (ticks_per_ns <= 0.0) {
        print_benchmark_note(
          "the time stamp counter could not be calibrated and no firmware frequency was reported, "
          "so the tables below are raw ticks and not nanoseconds"
        );

        return;
    }

    bench_ns_per_tick = 1.0 / ticks_per_ns;

    if (reported > 0.0 && measured > 0.0) {
        double deviation = fabs(measured * 1000000000.0 - reported) / reported * 100.0;

        if (deviation > 2.0)
            print_benchmark_note(
              "the time stamp counter was calibrated at %.0f Hz, %.2f%% away from the %s Hz that %s "
              "reports; %s is used, because a firmware frequency is exact where a measurement is only "
              "as good as its least disturbed trial, and a gap that wide means one of the two is wrong "
              "about this host",
              measured * 1000000000.0, deviation, source, source, source
            );
    }
}

#endif /* !USE_CLOCK_GETTIME */

/*
 * bench_timer_init establishes the tick-to-nanosecond ratio, once per process.
 * do_bench calls it before its first parallel region, so on the ordinary path
 * it is the main thread that calibrates and no worker ever races for it; the
 * afl_once guard is there for a caller that reaches it from several threads at
 * once, and it makes the call idempotent as well, which is what lets every one
 * of a binary's several do_bench calls make it without repeating the work.
 *
 * On the clock_gettime timer there is nothing to establish: that timer already
 * samples nanoseconds and bench_ns_per_tick keeps its initial 1.0.
 */
static inline void bench_timer_init(void)
{
#if !defined(USE_CLOCK_GETTIME)
    static afl_once_t once = AFL_ONCE_INIT;

    /*
     * afl_once answers 0 on every path: it either runs the initializer or waits
     * for the thread that does, and it has no failure mode to propagate. The
     * result is discarded, and the calibration itself never fails the run
     * either.
     */
    (void) afl_once(&once, bench_timer_init_once);
#endif
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
 *
 * Both statements are cast to void. That is deliberate and it is the only place
 * in the harness that swallows a return: five call sites pass a comma
 * expression as UNLOCK so that the release keeps the shape of an expression
 * (`(afl_mutex_unlock(&am), 0)` in mutex.c and rwlock.c), and the right operand
 * of a comma expression has no effect, which gcc reports as -Wunused-value and
 * -Werror turns into a build failure. The cast consumes the value of the whole
 * expression, so the call still happens exactly where it did and the interval
 * still brackets exactly the same work; nothing is measured differently and
 * nothing is printed differently. The parentheses around the parameter are what
 * make the cast apply to the comma expression as a whole instead of to its left
 * operand alone.
 *
 * Each half is folded into split by bench_add_half rather than accumulated
 * directly, so that a half whose two counter reads came from different
 * processors is counted and dropped instead of reported as a measurement.
 *
 * The tally lives in two locals for the length of the loop and reaches the
 * thread-local counters of do_bench only after it. That is not a micro
 * optimisation of the increment, it is what keeps the loop body free of
 * thread-local storage, and the layout of the loop body decides how the
 * compiler emits the subtraction of the two counter reads. With the tally in
 * thread-local storage, clang 22 at -O2 with -march=arrowlake vectorises the two
 * 8-byte fields of the clock_gettime timespec into one XMM subtract and stages
 * the pair through a 16-byte aligned slot, which cost the reported median of the
 * pthread baseline of benchmarks/uncontended about 8 ns per pair; with the tally
 * in locals the same build emits two scalar subtractions and the median comes
 * back. gcc does not vectorise the loop either way, and the default RDTSCP build
 * reads no timespec inside the loop at all, so neither is sensitive to the
 * choice. The migration test of bench_add_half is compiled out on the
 * clock_gettime timer for the same reason: it reads thread-local storage too,
 * and on that timer it can only ever evaluate to false.
 */
#define BENCH_LOCK_UNLOCK(iters, LOCK, UNLOCK, split)                                                            \
    do {                                                                                                         \
        timing_t __bench_start, __bench_stop;                                                                    \
        uint64_t __bench_brackets = 0, __bench_rejected = 0;                                                     \
        for (size_t __bench_i = 0; __bench_i < (iters); __bench_i++) {                                           \
            TIMING_START(__bench_start);                                                                         \
            (void) (LOCK);                                                                                       \
            TIMING_STOP(__bench_stop);                                                                           \
            bench_add_half(&__bench_brackets, &__bench_rejected, &(split)->lock, __bench_start, __bench_stop);   \
            bench_payload();                                                                                     \
            BENCH_BARRIER;                                                                                       \
            TIMING_START(__bench_start);                                                                         \
            (void) (UNLOCK);                                                                                     \
            TIMING_STOP(__bench_stop);                                                                           \
            bench_add_half(&__bench_brackets, &__bench_rejected, &(split)->unlock, __bench_start, __bench_stop); \
        }                                                                                                        \
        bench_timing_brackets += __bench_brackets;                                                               \
        bench_timing_rejected += __bench_rejected;                                                               \
    } while (0)

typedef struct
{
    char name[128];
    benchmark_function_t func;
    double duration;
    double mean, stdev, min, max, median;
    double p95, p99;
    double lock_mean, unlock_mean;
} benchmark_info;

/* Everything below is defined in a header that every benchmark includes, so it
   is `static inline`: no external symbol, no duplicate definition, and no
   -Wunused-function in a translation unit that happens not to call it. */

static inline int compare_timing(const void *a, const void *b)
{
    timing_t ta = *(const timing_t *) a;
    timing_t tb = *(const timing_t *) b;

    return (ta > tb) - (ta < tb);
}

/*
 * Nearest rank percentile of a sorted sample: the smallest observation that at
 * least `percent` of the samples do not exceed. The rank is computed in integers
 * so that no floating point rounding can move it to the next sample.
 */
static inline double bench_percentile(const timing_t *sorted, size_t count, unsigned percent)
{
    size_t rank = ((size_t) percent * count + 99) / 100;

    if (rank == 0)
        rank = 1;

    if (rank > count)
        rank = count;

    return (double) sorted[rank - 1];
}

/*
 * The worker number of the calling thread inside the region it runs, 0 for the
 * thread that called do_bench. do_bench sets it before a worker enters the
 * measured function, and a benchmark that splits its threads by role (the mixed
 * rwlock run) reads it there.
 */
static __thread unsigned bench_worker_index __attribute__((unused));

/*
 * The threads of one region can be at most this many. The number is a guard,
 * not a limit anyone should reach: the default is the size of an affinity mask
 * and a realistic override is a multiple of the core count. A request beyond it
 * is refused loudly rather than silently clamped into a different measurement.
 */
#define BENCH_MAX_THREADS 256

/*
 * One region of do_bench: what to run, where the samples go, and the per-region
 * tallies. `durations` and `splits` are NULL for a warm-up, whose samples are
 * thrown away. The tallies are atomic because every worker folds its own into
 * them once, after its loop.
 */
typedef struct
{
    benchmark_info *benchmark;
    timing_t *durations;
    benchmark_split *splits;
    size_t runs;
    unsigned threads;
    uint64_t brackets;
    uint64_t rejected;
} bench_region_t;

/*
 * bench_region_run is one worker of a region: pin itself to one CPU of the
 * inherited mask by its worker number, take the block of samples a static
 * schedule gives it, run them and fold its tallies into the region. The pinning
 * failure is reported by the call itself, and the measurement continues either
 * way, so the result drives no control flow. A worker whose block is empty
 * still pins itself and zeroes its tallies, the way an idle thread of a static
 * schedule does.
 */
static inline void bench_region_run(unsigned worker, bench_region_t *region)
{
    size_t chunk = (region->runs + region->threads - 1u) / region->threads;
    size_t start = (size_t) worker * chunk;
    size_t end = start + chunk;
    size_t i;

    if (end > region->runs)
        end = region->runs;

    bench_worker_index = worker;

    (void) bench_pin_this_thread(worker);

    bench_timing_brackets = 0;
    bench_timing_rejected = 0;

    if (region->durations == NULL) {
        for (i = start; i < end; i++) {
            benchmark_split warmup = {0, 0};

            region->benchmark->func(RUN_ITERATIONS, &warmup);
        }
    } else {
        for (i = start; i < end; i++)
            region->durations[i] = region->benchmark->func(RUN_ITERATIONS, &region->splits[i]);
    }

    __atomic_fetch_add(&region->brackets, bench_timing_brackets, __ATOMIC_RELAXED);
    __atomic_fetch_add(&region->rejected, bench_timing_rejected, __ATOMIC_RELAXED);
}

/*
 * The argument one created worker carries: its number, the body and the region.
 * It lives on the creating thread's stack, which stays valid for as long as the
 * thread does, because the creating thread runs and joins the whole region
 * before it returns.
 */
typedef struct
{
    unsigned worker;
    void (*body)(unsigned, void *);
    void *context;
} bench_thread_arg_t;

static inline void bench_thread_entry(void *argument)
{
    bench_thread_arg_t *arg = argument;

    arg->body(arg->worker, arg->context);
}

/*
 * bench_region_trampoline adapts the typed body of a region to the void pointer
 * the thread layer carries.
 */
static inline void bench_region_trampoline(unsigned worker, void *context)
{
    bench_region_run(worker, context);
}

/*
 * bench_parallel runs body(worker, context) on `threads` workers and answers 0,
 * or the error of a creation that failed. Worker 0 runs on the calling thread;
 * the others get a thread of their own. A region of one worker therefore creates
 * no thread at all, which is what the uncontended benchmark depends on: that
 * benchmark measures the libc while the process still looks single-threaded, and
 * a thread of the region's own would make the libc's fast paths stand down before
 * the measurement.
 */
static inline int bench_parallel(unsigned threads, void (*body)(unsigned, void *), void *context)
{
    bench_thread_arg_t arguments[BENCH_MAX_THREADS];
    afl_thread_t handles[BENCH_MAX_THREADS];
    unsigned created = 0;
    unsigned i;
    int result = 0;

    /*
     * Read the pool here, on the thread that goes on to create the region, so
     * that the snapshot exists before any worker of any region can ask for it
     * and no two threads ever fill it at the same time.
     */
    (void) bench_cpu_pool_once();

    if (threads <= 1) {
        body(0, context);

        return 0;
    }

    if (threads > BENCH_MAX_THREADS) {
        print_benchmark_note("a region of %u threads is more than the harness holds (%d)", threads, BENCH_MAX_THREADS);

        return EINVAL;
    }

    for (i = 1; i < threads; i++) {
        int error;

        arguments[i - 1].worker = i;
        arguments[i - 1].body = body;
        arguments[i - 1].context = context;

        error = afl_thread_create(&handles[i - 1], bench_thread_entry, &arguments[i - 1]);

        if (error != 0) {
            result = error;
            break;
        }

        created++;
    }

    body(0, context);

    for (i = 0; i < created; i++) {
        int error = afl_thread_join(&handles[i]);

        if (error != 0 && result == 0)
            result = error;
    }

    return result;
}

static inline int do_bench(benchmark_info *benchmark)
{
    timing_t duration = 0;
    timing_t durations[RUNS_COUNT];
    benchmark_split splits[RUNS_COUNT];
    size_t warmup_runs = BENCH_WARMUP > 0 ? (size_t) BENCH_WARMUP : 1;
    unsigned threads = (unsigned) bench_thread_count();
    double mean = 0.0, stdev = 0.0, lock_mean = 0.0, unlock_mean = 0.0;
    double min = INFINITY, max = 0.0, median = 0.0;
    uint64_t brackets = 0, rejected = 0;

    memset(durations, 0, sizeof(durations));
    memset(splits, 0, sizeof(splits));

    /*
     * Establish the tick-to-nanosecond ratio before the first sample is taken:
     * on the x86 timer everything below accumulates raw counter ticks, and the
     * reporting boundary at the end of this function converts them. The call is
     * idempotent, so the second and every later do_bench of one binary pay the
     * calibration once between them and never again.
     */
    bench_timer_init();

    /*
     * Warm up first and keep the result out of the statistics: the initial
     * samples contain the startup of the region's threads, the first lookup of
     * the thread id of every worker and the first touch of the lock. Every
     * worker pins itself to one processor of the inherited mask before it takes
     * its first sample, here and in the measured region below, so that no
     * bracket straddles two of the unsynchronized per-CPU counters.
     *
     * The pinning failure is reported once by bench_pin_this_thread itself, and
     * the region keeps measuring either way; only a failed thread creation is
     * reported here, because it is the harness and not the measurement that
     * failed.
     */
    {
        bench_region_t warmup_region = {benchmark, NULL, NULL, warmup_runs, threads, 0, 0};
        int error = bench_parallel(threads, bench_region_trampoline, &warmup_region);

        if (error != 0)
            print_benchmark_note("could not run the warm-up region on %u threads: %s", threads, strerror(error));
    }

    /*
     * The measured region. Its tallies collect across the workers: how many
     * bracketed halves were measured, and how many of them were dropped because
     * the closing counter read came from a processor other than the one the
     * worker is pinned to. Each worker zeroes its own counters before its loop,
     * so the halves of the warm-up above stay out of this tally.
     */
    {
        bench_region_t measured = {benchmark, durations, splits, RUNS_COUNT, threads, 0, 0};
        int error = bench_parallel(threads, bench_region_trampoline, &measured);

        if (error != 0)
            print_benchmark_note("could not run the measured region on %u threads: %s", threads, strerror(error));

        brackets = __atomic_load_n(&measured.brackets, __ATOMIC_RELAXED);
        rejected = __atomic_load_n(&measured.rejected, __ATOMIC_RELAXED);
    }

    /*
     * A dropped half contributes 0 to the split accumulators, so a sample all
     * of whose halves were dropped enters the statistics as 0 instead of being
     * removed from them: RUNS_COUNT samples are still reported per iteration
     * and the median is still the median of RUNS_COUNT values. That can pull
     * the statistics down, so it must not happen silently - this note says how
     * much of the run was dropped and why. Zero rejections prints nothing.
     */
    if (rejected != 0)
        print_benchmark_note(
          "dropped %llu of %llu bracketed halves: the thread had migrated between the two counter "
          "reads, so those halves spanned two unsynchronized per-CPU counters; they contribute 0 to "
          "the statistics below",
          (unsigned long long) rejected, (unsigned long long) brackets
        );

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

    /*
     * The median of an even sample is the mean of its two middle observations:
     * durations[RUNS_COUNT / 2] on its own is the upper of the two and sits half
     * a gap too high. Every benchmark here uses an even RUNS_COUNT, so the branch
     * that averages is the one that runs.
     */
    if (RUNS_COUNT % 2 == 0)
        median = ((double) durations[RUNS_COUNT / 2 - 1] + (double) durations[RUNS_COUNT / 2]) / 2.0;
    else
        median = (double) durations[RUNS_COUNT / 2];

    /*
     * The reporting boundary, and the only place where ticks become
     * nanoseconds: every statistic above accumulated raw counter ticks in
     * integer arithmetic - no floating point inside the measured loop and no
     * change to the statistics formulas - and each of the ten reported doubles
     * is scaled by the calibrated ratio exactly once, here. A positive scale
     * commutes with the mean, the standard deviation, the median and the
     * integer-rank percentiles, so converting at the boundary reports the same
     * numbers that converting every sample up front would, at none of the
     * cost. On the clock_gettime timer the ratio is 1.0 and every value passes
     * through unchanged, exactly as before the counter timer existed.
     * Everything is reported per lock/unlock pair, just like the iterations.
     */
    benchmark->duration = bench_ticks_to_ns((double) duration) / RUN_ITERATIONS;
    benchmark->min = bench_ticks_to_ns(min) / RUN_ITERATIONS;
    benchmark->max = bench_ticks_to_ns(max) / RUN_ITERATIONS;
    benchmark->stdev = bench_ticks_to_ns(stdev) / RUN_ITERATIONS;
    benchmark->mean = bench_ticks_to_ns(mean) / RUN_ITERATIONS;
    benchmark->median = bench_ticks_to_ns(median) / RUN_ITERATIONS;
    benchmark->p95 = bench_ticks_to_ns(bench_percentile(durations, RUNS_COUNT, 95)) / RUN_ITERATIONS;
    benchmark->p99 = bench_ticks_to_ns(bench_percentile(durations, RUNS_COUNT, 99)) / RUN_ITERATIONS;
    benchmark->lock_mean = bench_ticks_to_ns(lock_mean) / RUN_ITERATIONS;
    benchmark->unlock_mean = bench_ticks_to_ns(unlock_mean) / RUN_ITERATIONS;

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
#define BENCHMARK_ROW_FORMAT    "\t %s %12s  %15.2f  %15.2f\n"
#define BENCHMARK_RULE          "\t---------------------------------------------------\n"

/*
 * The runner prints the title of a benchmark and no newline, and leaves the
 * blank line that separates the title from the output to whatever the binary
 * prints first. print_benchmark() has always done that with the two newlines it
 * starts with; a note that comes before it has to do the same, or it lands on
 * the title line. The flag is what makes the two agree on who is first.
 */
static int benchmark_started_output;

/*
 * A line of prose about what a table does and does not measure, indented like
 * the table so that it reads as part of it. Two benchmarks cannot compare like
 * with like without an explanation: the uncontended one, because the libc has two
 * code paths for an uncontended pair, and the priority inheritance one, because
 * the protocol may be unavailable. Both say so out loud instead of leaving the
 * reader to guess which path a number came from.
 */
__attribute__((format(printf, 1, 2))) static inline void print_benchmark_note(const char *format, ...)
{
    va_list arguments;

    if (!benchmark_started_output) {
        benchmark_started_output = 1;
        fputs("\n\n", stdout);
    }

    fputs("\t ", stdout);
    va_start(arguments, format);
    vprintf(format, arguments);
    va_end(arguments);
    fputc('\n', stdout);
}

static inline void print_benchmark_row(const char *marker, const char *label, double left, double right)
{
    printf(BENCHMARK_ROW_FORMAT, marker, label, left, right);
}

static inline int print_benchmark(benchmark_info b1, benchmark_info b2)
{
    const char *plus = "\033[0;32m[+]\033[0m";
    const char *minus = "\033[0;31m[-]\033[0m";

    benchmark_started_output = 1;

    printf("\n\n");
    printf(BENCHMARK_HEADER_FORMAT, "", "", b1.name, b2.name);
    printf("%s", BENCHMARK_RULE);
    print_benchmark_row(b1.duration < b2.duration ? plus : minus, "duration:", b1.duration, b2.duration);
    print_benchmark_row(b1.mean < b2.mean ? plus : minus, "mean:", b1.mean, b2.mean);
    print_benchmark_row(b1.median < b2.median ? plus : minus, "median:", b1.median, b2.median);
    print_benchmark_row(b1.p95 < b2.p95 ? plus : minus, "p95:", b1.p95, b2.p95);
    print_benchmark_row(b1.p99 < b2.p99 ? plus : minus, "p99:", b1.p99, b2.p99);
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
