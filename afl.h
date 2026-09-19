#ifndef __AFL_H
#define __AFL_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/futex.h>

/*
 * Small, futex based locks for user space: a single header, no library.
 *
 * Every lock is one 32 bit word that holds the owner of the lock plus a bit that
 * tells the releasing thread whether somebody is waiting for it:
 *
 *   bit    31          30 .. 0
 *          waiters bit  owner (a thread id, 0 when the lock is free)
 *
 * The owner tracking variants store the thread id of the owner in the low bits,
 * so that they can detect a recursive acquisition and refuse to be released by
 * any other thread. The plain variants use the word as a counter with three
 * states: free, locked and locked with waiters.
 *
 * A contended acquire makes a bounded number of attempts at the lock
 * (AFL_SPIN_LIMIT), spaced by a backoff of doubling PAUSE iterations
 * (AFL_SPIN_BACKOFF), and then blocks on the futex. Spinning pays off because the
 * critical section of a lock like this is usually shorter than the round trip
 * through the kernel; a thread that is about to block sets the waiters bit first,
 * so that the releasing thread knows that it has to issue a FUTEX_WAKE.
 *
 * The lock types are aligned to 64 bytes, i.e. every lock occupies a cache line
 * of its own, which keeps false sharing out of the measurements.
 *
 * Linux only: the blocking path is the raw futex system call.
 */

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Hints for the branch predictor and for the code layout: __afl_likely marks the
 * path that the lock takes when it succeeds, __afl_unlikely the error paths and
 * the slow paths, which the compiler then lays out of line.
 *
 * Example, the fast path of a lock word:
 *
 *     uint32_t lock;
 *
 *     __atomic_load(val, &lock, __ATOMIC_RELAXED);
 *
 *     if (__afl_likely(lock == 1))
 *         goto success;
 *
 *     asm volatile("movq $100, %%rcx;rep nop;" ::: "rcx", "memory");
 *
 * success:
 *     return 0;
 *
 * With __afl_likely the test falls through and the reparation loop is moved out
 * of line:
 *
 *     movl    (%rdi), %eax
 *     cmpl    $1, %eax
 *     jne     .not_success
 *     xorl    %eax, %eax
 *     retq
 *
 * .not_success:
 *     movq    $100, %rcx
 *     rep     nop
 *     xorl    %eax, %eax
 *     retq
 *
 * With __afl_unlikely the same test becomes a jump over the hot path:
 *
 *     movl    (%rdi), %eax
 *     cmpl    $1, %eax
 *     je      .success
 *     movq    $100, %rcx
 *     rep     nop
 *
 * .success:
 *     xorl    %eax, %eax
 *     retq
 *
 */
#define __afl_unlikely(condition) __builtin_expect((condition), 0)
#define __afl_likely(condition) __builtin_expect((condition), 1)

/*
 * Debug Atomic Fast Locks
 *
 * Enabled with -DAFL_DEBUG: a misuse of the API, for example releasing a lock
 * from a thread that does not own it, is reported on stderr instead of being
 * silently ignored.
 */
#ifdef AFL_DEBUG
#define __afl_debug(condition, text)                                       \
    if (__afl_unlikely(condition)) {                                       \
        fprintf(stderr, "[ERROR] (%s:%d) %s\n", __FILE__, __LINE__, text); \
    }

#define __afl_syscall_check_errors(ret)                                                            \
    if (__afl_unlikely((ret) < 0 && (ret) >= -4095)) {                                             \
        fprintf(stderr, "[ERROR] (%s:%d) syscall error: %ld\n", __FILE__, __LINE__, (long) (ret)); \
    }
#else
#define __afl_debug(condition, text)
#define __afl_syscall_check_errors(ret)
#endif

/*
 * Pause Thread
 *
 * PAUSE improves the performance of a spin-wait loop: it tells the processor that
 * the code sequence is a spin loop, which keeps it from suffering the memory
 * order violation penalty when the loop exits. Placing a PAUSE in every spin-wait
 * loop is recommended. It also stops the core from burning power while it waits.
 * The more or less equivalent instruction on aarch64 is YIELD.
 */
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) \
  || defined(__i686__)
#define __afl_pause asm volatile("pause" ::: "memory")
#elif defined(__aarch64__)
#define __afl_pause asm volatile("yield" ::: "memory")
#else
#include <sched.h>
#define __afl_pause sched_yield()
#endif

#define AFL_TID_MASK 0x3FFFFFFF // Thread ID bit mask

/*
 * Thread-local storage (TLS) - Thread Pointer
 */
#if (defined(__clang__) && __clang_major__ >= 14) \
  || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ > 11 || (__GNUC__ == 11 && __GNUC_MINOR__ >= 1)))
#define __afl_thread_pointer(tp) tp = (uintptr_t) __builtin_thread_pointer()
#elif defined(__x86_64__) || defined(__amd64__)
#define __afl_thread_pointer(tp) asm volatile("movq %%fs:0, %0" : "=r"(tp))
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
#define __afl_thread_pointer(tp) asm volatile("movl %%gs:0, %0" : "=r"(tp))
#elif defined(__aarch64__)
#define __afl_thread_pointer(tp) asm volatile("mrs %0, tpidr_el0" : "=r"(tp))
#else
#error "Compiler or platform not supported for TLS"
#endif

/*
 * Create Memory Barrier
 */
#define __afl_memory_barrier asm volatile("" ::: "memory")

/*
 * Direct system calls: the futex operations of the slow paths are issued without
 * the libc wrapper, which saves a few cycles per call and keeps the header
 * independent of the C library.
 */
#if defined(__x86_64__) || defined(__amd64__)
static inline long __afl_syscall(long number, long p1, long p2, long p3, long p4)
{
    long ret;
    register long r8 __asm__("r8")   = 0;
    register long r9 __asm__("r9")   = 0;
    register long r10 __asm__("r10") = p4;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"(p1), "S"(p2), "d"(p3), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    __afl_syscall_check_errors(ret);
    return ret;
}
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
static inline long __afl_syscall(long number, long p1, long p2, long p3, long p4)
{
    long ret;
#if !defined(__PIC__)
    asm volatile("call *%%gs:16" : "=a"(ret) : "a"(number), "b"(p1), "c"(p2), "d"(p3), "S"(p4) : "memory");
#else
    asm volatile("xchg %%ebx, %%edi;\n"
                 "call *%%gs:16;\n"
                 "xchg %%ebx, %%edi;\n"
                 : "=a"(ret)
                 : "a"(number), "D"(p1), "c"(p2), "d"(p3), "S"(p4)
                 : "memory");
#endif
    __afl_syscall_check_errors(ret);
    return ret;
}
#elif defined(__aarch64__)
static inline long __afl_syscall(long number, long p1, long p2, long p3, long p4)
{
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = p1;
    register long x1 __asm__("x1") = p2;
    register long x2 __asm__("x2") = p3;
    register long x3 __asm__("x3") = p4;
    register long x4 __asm__("x4") = 0;
    register long x5 __asm__("x5") = 0;
    asm volatile("svc 0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "cc", "memory");
    __afl_syscall_check_errors(x0);
    return x0;
}
#else
#define __afl_syscall(number, p1, p2, p3, p4) syscall(number, p1, p2, p3, p4)
#endif

/*
 * Caches the thread id in thread local storage, so that a lock pays for the gettid
 * system call once per thread instead of once per acquisition.
 */
static inline uint32_t __afl_gettid(void)
{
    static __thread uint32_t tid = 0;

    if (__afl_likely(tid))
        return tid;

    tid = (uint32_t) (__afl_syscall(__NR_gettid, 0, 0, 0, 0) & AFL_TID_MASK);

    return tid;
}

enum __afl_state
{
    AFL_UNLOCKED = 0, // The lock is free
    AFL_LOCKED   = 1  // The lock is taken, without an owner in the lock word
};

#define AFL_HAVE_WAITERS 0x80000000 // Somebody is blocked on this lock

#define __AFL_ALIGN __attribute__((aligned(64))) // Most processors have a cache line size of 64 bytes

/*
 * Number of attempts that a contended mutex acquire makes before it falls back to
 * a blocking futex wait. Define it to 0 to disable spinning. The spinlocks do not
 * use this limit, they spin until they win the lock.
 *
 * The attempts are spaced by the backoff that AFL_SPIN_BACKOFF configures, so the
 * limit counts attempts and not PAUSE iterations: a large part of the wait is
 * spent inside the backoff (up to AFL_SPIN_BACKOFF PAUSE iterations per attempt)
 * instead of being spent probing the lock word. That is what makes the spin phase
 * pay off. A tight loop of the same length gives up and parks while the holder is
 * still about to release the lock, see the comment on AFL_SPIN_BACKOFF for what
 * the measured difference looks like.
 *
 * The default sits between two measured losses, because the limit is an upper end
 * as well as a lower one. Above it, a longer spin buys nothing where the lock is
 * acquired and released in a tight loop: the three benchmarks of that shape are 1
 * to 5% slower at 32 attempts than at 128. What it costs is the benchmark that
 * hands the lock over again and again, thousands of times per measured iteration:
 * benchmarks/mutex_recursive is level with its baseline at 32 attempts, within
 * about 1% at five, fifteen and twenty eight threads, and slower at 128 by 43%,
 * 52% and 76% at those three counts. Below it, the waiters park in the middle of
 * a hand-off: at 8 attempts those three tight loop benchmarks become 2.7 to 8
 * times slower than their baseline.
 *
 * The default trades latency for CPU time: spinning avoids the two system calls
 * of a futex round trip when the lock is released quickly, which is the common
 * case, but a waiter that spins while the holder is descheduled burns a core that
 * somebody else could use. Raise it (-DAFL_SPIN_LIMIT=<n>) when the critical
 * sections are short and the threads do not oversubscribe the cores, lower it
 * when they do. The measured effect of the limit is in the README.
 */
#ifndef AFL_SPIN_LIMIT
#define AFL_SPIN_LIMIT 32
#endif

/*
 * Announce to the thread that holds the lock that the calling thread is about to
 * block on it: the waiters bit has to be set before the thread sleeps, otherwise
 * the releasing thread would not know that it has to issue a FUTEX_WAKE. The
 * compare exchange fails when the lock was released in the meantime, in which case
 * the up to date value of the lock is returned instead.
 */
static inline uint32_t __afl_futex_announce(uint32_t *lock, uint32_t value)
{
    uint32_t expected = value;

    if (
      __afl_unlikely(
        !__atomic_compare_exchange_n(lock, &expected, value | AFL_HAVE_WAITERS, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)
      )
    )
        return expected;

    return value | AFL_HAVE_WAITERS;
}

/*
 * Spinlock
 */
typedef uint32_t afl_spinlock_t __AFL_ALIGN;

static inline int afl_spin_init(afl_spinlock_t *spinlock, int shared)
{
    (void) shared;
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/*
 * Longest gap, in PAUSE iterations, between two attempts on a contended lock. The
 * gap grows as 1, 2, 4, ... and stays at AFL_SPIN_BACKOFF once it has been
 * reached. Both the spinlocks and the spin phase of the mutexes use it.
 *
 * A small cap looks like the obvious choice: a waiter that polls closely notices
 * a release as soon as it happens. Measured, it is a loss. With the cap at 4 the
 * waiters win the race for the cache line on most releases, so most acquires
 * become a cross core hand-off instead of a re-acquire of the thread that just
 * released the lock, out of the cache line it still owns. On this machine, at
 * five threads, the median acquire of benchmarks/spinlock_owner is 32 ns with
 * the cap at 1024, against 600 to 850 ns with the cap at 4 or 16, and the median
 * of benchmarks/spinlock moves from 27 ns to 30 ns. The default matches the
 * behaviour of the lock before the cap became a knob.
 *
 * The state is local to one acquire: a wait that ends before the ramp has
 * reached the cap never backs off longer than the ramp of that wait.
 *
 * In the bounded spin phase of a mutex (see AFL_SPIN_LIMIT) the spacing is what
 * separates spinning from parking. A tight loop of 128 PAUSE iterations, which is
 * what the limit used to be, parks most acquires and costs 840 to 1080 ns for
 * afl_mutex_lock, afl_mutex_owner_lock and afl_mutex_recursive_lock at five
 * threads, while the same three benchmarks report 35 to 46 ns when the 128
 * attempts are spaced by the backoff, at five and at fifteen threads on this
 * machine. The loss of a tight loop is not false sharing with the holder: the
 * recursion counter of afl_mutex_recursive_t does share the cache line of its lock
 * word, but moving that word to a line of its own with __AFL_ALIGN moves
 * benchmarks/mutex_recursive by at most 6%, against the 43 to 76% that the length
 * of the spin phase moves it by, see AFL_SPIN_LIMIT. afl_mutex_pi_lock does not
 * take part in this, it has no spin phase, it goes straight to FUTEX_LOCK_PI.
 */
#ifndef AFL_SPIN_BACKOFF
#define AFL_SPIN_BACKOFF 1024
#endif

typedef struct
{
    int backoff;
} __afl_spin_backoff_t;

static inline void __afl_spin_backoff_init(__afl_spin_backoff_t *backoff)
{
    backoff->backoff = 1;
}

static inline void __afl_spin_backoff(__afl_spin_backoff_t *backoff)
{
    int pauses = backoff->backoff;

    if (pauses < 1)
        pauses = 1;

    for (int i = 0; i < pauses; i++)
        __afl_pause;

    if (pauses < AFL_SPIN_BACKOFF)
        backoff->backoff = pauses << 1;
}

static inline int afl_spin_lock(afl_spinlock_t *spinlock)
{
    uint32_t lock             = AFL_UNLOCKED;
    __afl_spin_backoff_t backoff;

    /*
     * Fast path: one compare exchange from the free value, without a separate
     * test load. An uncontended acquire is therefore a single atomic instruction,
     * and a failed attempt does not write the lock word, so it does not steal the
     * cache line from the thread that holds the lock.
     */
    if (__afl_likely(__atomic_compare_exchange_n(spinlock, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    __afl_spin_backoff_init(&backoff);

    for (;;) {
        /*
         * Contended: test-and-test-and-set. Only issue the expensive atomic
         * exchange once the lock looks free. Spinning on a plain load keeps the
         * cache line shared, while a blind exchange would steal it from the other
         * spinners on every iteration.
         */
        lock = __atomic_load_n(spinlock, __ATOMIC_RELAXED);
        if (
          __afl_likely(lock == AFL_UNLOCKED)
          && __afl_likely(__atomic_exchange_n(spinlock, AFL_LOCKED, __ATOMIC_ACQUIRE) == AFL_UNLOCKED)
        )
            return 0;

        __afl_spin_backoff(&backoff);
    }
}

static inline int afl_spin_unlock(afl_spinlock_t *spinlock)
{
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

static inline int afl_spin_owner_lock(afl_spinlock_t *spinlock)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid  = __afl_gettid();
    __afl_spin_backoff_t backoff;

    /*
     * Fast path: one compare exchange from the free value, without a separate
     * test load. The expected value is pinned to the free value, never the value
     * that was just observed: the latter also matches a lock that is still owned
     * by another thread, the exchange then succeeds and hands out the same
     * spinlock twice. An uncontended acquire is a single atomic instruction, and
     * a failed, uncontended attempt only reads the lock word.
     */
    if (__afl_likely(__atomic_compare_exchange_n(spinlock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    /* Only this thread may own it, a stale read or a recursive call. */
    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned spinlock.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    __afl_spin_backoff_init(&backoff);

    for (;;) {
        /*
         * Contended: test-and-test-and-set, see afl_spin_lock: the test load
         * keeps the cache line shared while the lock is held by somebody else.
         *
         * There is no owner check in this loop. This thread cannot have written
         * its own tid (it has not acquired the lock), and no other live thread
         * carries the same tid, so the value read back here can never match; the
         * recursive case was already rejected above, where the failed fast path
         * left the current owner in lock.
         */
        lock = __atomic_load_n(spinlock, __ATOMIC_RELAXED);

        if (
          __afl_likely(
            lock == AFL_UNLOCKED
            && __atomic_compare_exchange_n(spinlock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
          )
        )
            return 0;

        __afl_spin_backoff(&backoff);
    }
}

static inline int afl_spin_owner_unlock(afl_spinlock_t *spinlock)
{
    uint32_t lock = 0;
    uint32_t tid  = __afl_gettid();

    __atomic_load(spinlock, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a spinlock from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);

    return 0;
}

static inline int afl_spin_destroy(afl_spinlock_t *spinlock)
{
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/*
 * Mutex
 */
typedef uint32_t afl_mutex_t __AFL_ALIGN;

#define AFL_MUTEX_INIT 0

static inline int afl_mutex_lock(afl_mutex_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;
    __afl_spin_backoff_t backoff;

    /*
     * Fast path: one compare exchange from the free value, without a separate
     * test load, so an uncontended acquire is a single atomic instruction, the
     * same shape as afl_spin_lock. Because the value that is written does not
     * carry the waiters bit, this also clears a waiters bit that a previous,
     * longer hand-off left behind, so a lock that is never contended does not
     * perform any system call. On failure the compare exchange leaves the
     * observed value in lock, which is what the spin loop below needs.
     */
    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    /*
     * Contended: spin for up to AFL_SPIN_LIMIT attempts, spaced by the backoff,
     * the critical section might be tiny. See the comment on AFL_SPIN_LIMIT for
     * why the attempts are not a tight loop.
     */
    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (
          lock == AFL_UNLOCKED
          && __atomic_compare_exchange_n(mutex, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
        )
            return 0;

        __afl_spin_backoff(&backoff);
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }

    for (;;) {
        if (lock == AFL_UNLOCKED) {
            /*
             * Contended path: keep the waiters bit set. This thread has to wake
             * the next waiter when it releases the lock, otherwise a wake up that
             * is addressed to a single waiter would end the chain.
             */
            if (
              __atomic_compare_exchange_n(
                mutex, &lock, AFL_LOCKED | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED
              )
            )
                return 0;
            continue;
        }

        if (!(lock & AFL_HAVE_WAITERS)) {
            lock = __afl_futex_announce(mutex, lock);
            continue;
        }

        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, lock, 0);
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }
}

static inline int afl_mutex_unlock(afl_mutex_t *mutex)
{
    uint32_t lock = __atomic_exchange_n(mutex, AFL_UNLOCKED, __ATOMIC_RELEASE);

    __afl_debug(lock == AFL_UNLOCKED, "An attempt was made to unlock an unlocked mutex.");

    if (__afl_unlikely(lock & AFL_HAVE_WAITERS))
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

static inline int afl_mutex_owner_lock(afl_mutex_t *mutex)
{
    uint32_t tid  = __afl_gettid();
    uint32_t lock = AFL_UNLOCKED;
    __afl_spin_backoff_t backoff;

    /*
     * Fast path: one compare exchange from the free value, without a separate
     * test load, see afl_mutex_lock and afl_spin_owner_lock. The recursive check
     * can only fire on the failed path, where the compare exchange leaves the
     * current owner in lock, so it is moved below the acquire and does not cost
     * the uncontended path anything.
     */
    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    /*
     * Contended: spin for up to AFL_SPIN_LIMIT attempts, spaced by the backoff,
     * the critical section might be tiny. See the comment on AFL_SPIN_LIMIT.
     */
    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (lock == AFL_UNLOCKED && __atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return 0;

        __afl_spin_backoff(&backoff);
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }

    for (;;) {
        if (lock == AFL_UNLOCKED) {
            /* Contended path: keep the waiters bit set, see afl_mutex_lock. */
            if (__atomic_compare_exchange_n(mutex, &lock, tid | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return 0;
            continue;
        }

        if (!(lock & AFL_HAVE_WAITERS)) {
            lock = __afl_futex_announce(mutex, lock);
            continue;
        }

        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, lock, 0);
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }
}

static inline int afl_mutex_owner_unlock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    if (__atomic_exchange_n(mutex, AFL_UNLOCKED, __ATOMIC_RELEASE) & AFL_HAVE_WAITERS)
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

static inline int afl_mutex_pi_lock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    if (lock || (!lock && !__atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

    return 0;
}

static inline int afl_mutex_pi_unlock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    if (!__atomic_compare_exchange_n(mutex, &tid, AFL_UNLOCKED, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

    return 0;
}

static inline int afl_mutex_destroy(afl_mutex_t *mutex)
{
    __atomic_store_n(mutex, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/*
 * Recursive Mutex
 */
typedef struct
{
    uint32_t lock;
    size_t count;
} afl_mutex_recursive_t __AFL_ALIGN;

static inline int afl_mutex_recursive_init(afl_mutex_recursive_t *mutex)
{
    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    mutex->count = 0;

    return 0;
}

static inline int afl_mutex_recursive_lock(afl_mutex_recursive_t *mutex)
{
    uint32_t tid  = __afl_gettid();
    uint32_t lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);
    __afl_spin_backoff_t backoff;

    /*
     * Recursive acquisition: the calling thread already owns the mutex. This is
     * the common case for a recursive mutex, a lock that is taken at every level
     * of a recursive walk re-acquires it on the way down, so it is answered from
     * the plain load alone and costs no atomic operation at all. A compare
     * exchange seeded from the free value cannot answer it on its own: it fails
     * first and only then leaves the owner in lock, which would turn every nested
     * acquisition into a failed atomic operation.
     */
    if (__afl_likely(tid == (lock & AFL_TID_MASK))) {
        __afl_debug(
          mutex->count + 1 == 0,
          "Recursive mutex counter overflow. "
          "This is not an error, but please check that the EAGAIN return value is being processed correctly."
        );
        if (__afl_unlikely(mutex->count + 1 == 0))
            return EAGAIN;
        mutex->count++;
        return 0;
    }

    /*
     * Fast path: the mutex is free, and the test load above already showed that
     * this thread is not the owner, so only the compare exchange is left. An
     * uncontended first acquisition is that single atomic instruction. The
     * expected value is pinned to the free value rather than taken from the load:
     * the two are the same here, but a pinned one keeps a failed attempt from
     * writing, so a contended attempt does not steal the cache line. On failure
     * the compare exchange leaves the observed value in lock, which is what the
     * spin loop below needs, and that loop repeats the test load anyway.
     */
    if (__afl_likely(lock == AFL_UNLOCKED)) {
        if (__afl_likely(__atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))) {
            mutex->count = 1;
            return 0;
        }
    }

    /*
     * Contended: spin for up to AFL_SPIN_LIMIT attempts, spaced by the backoff,
     * the critical section might be tiny. See the comment on AFL_SPIN_LIMIT.
     */
    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (
          lock == AFL_UNLOCKED
          && __atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
        ) {
            mutex->count = 1;
            return 0;
        }

        __afl_spin_backoff(&backoff);
        lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);
    }

    for (;;) {
        if (lock == AFL_UNLOCKED) {
            /* Contended path: keep the waiters bit set, see afl_mutex_lock. */
            if (
              __atomic_compare_exchange_n(
                &mutex->lock, &lock, tid | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED
              )
            ) {
                mutex->count = 1;
                return 0;
            }
            continue;
        }

        if (!(lock & AFL_HAVE_WAITERS)) {
            lock = __afl_futex_announce(&mutex->lock, lock);
            continue;
        }

        __afl_syscall(__NR_futex, (intptr_t) &mutex->lock, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, lock, 0);
        lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);
    }
}

static inline int afl_mutex_recursive_unlock(afl_mutex_recursive_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();

    __atomic_load(&mutex->lock, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    __afl_debug(mutex->count == 0, "An attempt was made to unlock an unlocked recursive mutex.");

    if (--mutex->count == 0 && (__atomic_exchange_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE) & AFL_HAVE_WAITERS))
        __afl_syscall(__NR_futex, (intptr_t) &mutex->lock, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

static inline int afl_mutex_recursive_destroy(afl_mutex_recursive_t *mutex)
{
    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    mutex->count = 0;

    return 0;
}

/*
 * Condition Variable
 *
 * A condition variable only hands out wake ups, so its futex word is a sequence
 * number instead of a lock word: every signal and every broadcast bumps it, and a
 * waiter sleeps as long as the word still holds the value it read. A signal that
 * lands between the read and the FUTEX_WAIT is therefore not lost, the wait sees
 * the changed value and returns instead of sleeping.
 *
 * The second word counts the threads that are inside afl_cond_wait(). It lets a
 * signal that nobody can receive return without a system call, which is the
 * common case when the predicate is already true. A waiter registers before it
 * releases the mutex, so a signal that arrives after the release cannot miss it.
 *
 * Like a pthread condition variable this has spurious wake ups, so the caller has
 * to re-check its predicate in a loop:
 *
 *     afl_mutex_lock(&mutex);
 *     while (!ready)
 *         afl_cond_wait(&cond, &mutex);
 *     afl_mutex_unlock(&mutex);
 *
 * A wait only pairs with the plain afl_mutex_lock()/afl_mutex_unlock() pair, the
 * same way pthread_cond_wait() only pairs with the mutex type it was initialized
 * for.
 */
typedef struct
{
    uint32_t sequence; // Futex word: bumped by every signal and every broadcast
    uint32_t waiters;  // Threads that are currently inside afl_cond_wait()
} afl_cond_t __AFL_ALIGN;

#define AFL_COND_INIT {0, 0}

static inline int afl_cond_init(afl_cond_t *cond)
{
    cond->sequence = 0;
    cond->waiters  = 0;

    return 0;
}

static inline int afl_cond_destroy(afl_cond_t *cond)
{
    __afl_debug(
      __atomic_load_n(&cond->waiters, __ATOMIC_RELAXED) != 0,
      "A condition variable was destroyed while a thread was waiting on it."
    );

    return afl_cond_init(cond);
}

/*
 * Wake up to `wake` waiters. The sequence number is bumped before the wake, so a
 * waiter that is still on its way into FUTEX_WAIT returns from the system call
 * without sleeping instead of missing the wake up. A signal that nobody can
 * receive is a no-op, which keeps the "the predicate is already true" path out of
 * the kernel the same way the uncontended lock paths are.
 */
static inline int __afl_cond_wake(afl_cond_t *cond, int wake)
{
    if (__atomic_load_n(&cond->waiters, __ATOMIC_RELAXED) == 0)
        return 0;

    __atomic_fetch_add(&cond->sequence, 1, __ATOMIC_RELEASE);
    __afl_syscall(__NR_futex, (intptr_t) &cond->sequence, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, wake, 0);

    return 0;
}

static inline int afl_cond_signal(afl_cond_t *cond)
{
    return __afl_cond_wake(cond, 1);
}

static inline int afl_cond_broadcast(afl_cond_t *cond)
{
    return __afl_cond_wake(cond, INT32_MAX);
}

static inline int afl_cond_wait(afl_cond_t *cond, afl_mutex_t *mutex)
{
    uint32_t sequence = __atomic_load_n(&cond->sequence, __ATOMIC_RELAXED);

    /*
     * Register before the mutex is released, so that a signal which arrives right
     * after the release sees this waiter. The system call that follows is a full
     * barrier, so the registration is visible to the signaller before this thread
     * can be asleep.
     */
    __atomic_fetch_add(&cond->waiters, 1, __ATOMIC_SEQ_CST);

    afl_mutex_unlock(mutex);

    __afl_syscall(__NR_futex, (intptr_t) &cond->sequence, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, sequence, 0);

    __atomic_fetch_sub(&cond->waiters, 1, __ATOMIC_RELAXED);

    return afl_mutex_lock(mutex);
}

static inline int afl_cond_timedwait(afl_cond_t *cond, afl_mutex_t *mutex, const struct timespec *abstime)
{
    struct timespec now, relative;
    uint32_t sequence = __atomic_load_n(&cond->sequence, __ATOMIC_RELAXED);
    long ret;
    int rc;

    /*
     * FUTEX_WAIT wants a relative timeout while pthread_cond_timedwait() wants an
     * absolute deadline, so the deadline is measured against CLOCK_MONOTONIC and
     * converted here.
     */
    clock_gettime(CLOCK_MONOTONIC, &now);

    relative.tv_sec  = abstime->tv_sec - now.tv_sec;
    relative.tv_nsec = abstime->tv_nsec - now.tv_nsec;

    if (relative.tv_nsec < 0) {
        relative.tv_nsec += 1000000000L;
        relative.tv_sec--;
    }

    /* The deadline is already behind: report the timeout, the mutex stays held. */
    if (relative.tv_sec < 0)
        return ETIMEDOUT;

    __atomic_fetch_add(&cond->waiters, 1, __ATOMIC_SEQ_CST);

    afl_mutex_unlock(mutex);

    ret = __afl_syscall(
      __NR_futex, (intptr_t) &cond->sequence, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, sequence, (long) (intptr_t) &relative
    );

    __atomic_fetch_sub(&cond->waiters, 1, __ATOMIC_RELAXED);

    rc = afl_mutex_lock(mutex);

    if (rc != 0)
        return rc;

    /*
     * The direct system call stubs return the negated errno, the generic fallback
     * returns -1 and sets errno; both mean a timeout here.
     */
    if (ret == -ETIMEDOUT || (ret == -1 && errno == ETIMEDOUT))
        return ETIMEDOUT;

    return 0;
}

/*
 * Once
 *
 * The same three states as the plain mutex plus a flag that says that the
 * initialization is done: once that flag is set nobody ever takes the lock again,
 * every further call just reads AFL_SUCCESS and returns.
 */
typedef uint32_t afl_once_t __AFL_ALIGN;

#define AFL_SUCCESS 0x40000000 // Initialization finished, return immediately

#define AFL_ONCE_INIT 0

static inline int afl_once(afl_once_t *once, void (*init)(void))
{
    uint32_t lock = __atomic_load_n(once, __ATOMIC_ACQUIRE);

    if (__afl_likely(lock & AFL_SUCCESS))
        return 0;

    /* Try to become the thread that runs the initialization routine. */
    if (lock == AFL_UNLOCKED) {
        uint32_t expected = AFL_UNLOCKED;

        if (__atomic_compare_exchange_n(once, &expected, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            init();

            if (__atomic_exchange_n(once, AFL_SUCCESS, __ATOMIC_RELEASE) & AFL_HAVE_WAITERS)
                __afl_syscall(__NR_futex, (intptr_t) once, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, INT32_MAX, 0);

            return 0;
        }

        lock = expected;
    }

    for (;;) {
        if (lock & AFL_SUCCESS)
            return 0;

        /*
         * Announce that this thread is going to block. The bit has to be set by
         * one waiter before it sleeps; the others fall through to the futex wait
         * as well instead of busy-spinning until init() returns.
         */
        if (lock == AFL_LOCKED)
            lock = __afl_futex_announce(once, lock);

        if (lock == (AFL_LOCKED | AFL_HAVE_WAITERS))
            __afl_syscall(
              __NR_futex, (intptr_t) once, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, AFL_LOCKED | AFL_HAVE_WAITERS, 0
            );

        lock = __atomic_load_n(once, __ATOMIC_ACQUIRE);
    }
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __AFL_H */
