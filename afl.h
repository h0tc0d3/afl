#ifndef __AFL_H
#define __AFL_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Allow the compiler to optimize for the case where paths of execution including that statement
 * are more or less likely than any alternative path of execution that does not include such a statement.
 *
 * Example:
 *
 * int f1(uint32_t *val) {
 *
 *     uint32_t lock;
 *
 *     __atomic_load(val, &lock, __ATOMIC_RELAXED);
 *
 *     if(__likely(lock == 1))
 *         goto success;
 *
 *     asm volatile("movq $100, %%rcx;rep nop;" ::: "rcx", "memory");
 *
 * success:
 *     return 0;
 * }
 *
 * -------------------------
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
 * -------------------------
 *
 * int f2(uint32_t *val) {
 *
 *     uint32_t lock;
 *
 *     __atomic_load(val, &lock, __ATOMIC_RELAXED);
 *
 *     if(__unlikely(lock == 1))
 *         goto success;
 *
 *     asm volatile("movq $100, %%rcx;rep nop;" ::: "rcx", "memory");
 *
 * success:
 *     return 0;
 * }
 *
 * -------------------------
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
 */
#ifdef AFL_DEBUG
#define __afl_debug(condition, text)                                       \
    if (__afl_unlikely(condition)) {                                       \
        fprintf(stderr, "[ERROR] (%s:%d) %s\n", __FILE__, __LINE__, text); \
    }
#define __afl_syscall_check_errors(ret)                                                  \
    if (__afl_unlikely(ret <= -4095)) {                                                  \
        fprintf(stderr, "[ERROR] (%s:%d) syscall error: %d\n", __FILE__, __LINE__, ret); \
    }
#else
#define __afl_debug(condition, text)
#define __afl_syscall_check_errors(ret)
#endif

/*
 * Pause Thread
 *
 * Improves the performance of spin-wait loops. When executing a "spin-wait loop",
 * processors will suffer a severe performance penalty when exiting the loop because it detects a possible memory order violation.
 * The PAUSE instruction provides a hint to the processor that the code sequence is a spin-wait loop.
 * The processor uses this hint to avoid the memory order violation in most situations,
 * which greatly improves processor performance. For this reason,
 * it is recommended that a PAUSE instruction be placed in all spin-wait loops.
 *
 * An additional function of the PAUSE instruction is to reduce the power consumed by a processor while executing a spin loop.
 * A processor can execute a spin-wait loop extremely quickly,
 * causing the processor to consume a lot of power while it waits for the resource it is spinning on to become available.
 * Inserting a pause instruction in a spin-wait loop greatly reduces the processor`s power consumption.
 */
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) \
  || defined(__i686__)
#define __afl_pause asm volatile("pause" ::: "memory")
#elif defined(__aarch64__)
#define __afl_pause asm volatile("yield" ::: "memory")
else
#include <sched.h>
#define __afl_pause sched_yield()
#endif

#define AFL_TID_MASK 0x3FFFFFFF // Thread ID bit mask

/*
 * Thread-local storage (TLS) - Thread Pointer
 */
#if (__GNUC__ > 11) || (__clang_major__ >= 14) || (__GNUC__ == 11 && __GNUC_MINOR__ >= 1)
#define __afl_thread_pointer(tp) tp = (uintptr_t) __builtin_thread_pointer()
#elif defined(__x86_64__) || defined(__amd64__)
#define __afl_thread_pointer(tp) asm volatile("movl %%fs:0, %0" : "=r"(tp))
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
#define __afl_thread_pointer(tp) asm volatile("movl %%gs:0, %0" : "=r"(tp))
#elif defined(__aarch64__)
#define __afl_thread_pointer(tp) asm volatile("mrs %0, tpidr_el0" : "=r"(tp))
#else
#error Compiler or platform not support TLS
#endif

static inline uint32_t __afl_thread_pointer_tid(void)
{
    uint32_t ret;
    __afl_thread_pointer(ret);
    return ret & AFL_TID_MASK;
}

/*
 * Create Memory Barrier
 */
#define __afl_memory_barrier asm volatile("" ::: "memory")

/*
 * Call system calls directly. This helps to save some CPU cycles.
 */
#if defined(__x86_64__) || defined(__amd64__)
static inline int32_t __afl_syscall(int64_t number, int64_t p1, int64_t p2, int64_t p3, int64_t p4)
{
    int32_t ret;
    register int64_t r8 __asm__("r8")   = 0;
    register int64_t r9 __asm__("r9")   = 0;
    register int64_t r10 __asm__("r10") = p4;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"(p1), "S"(p2), "d"(p3), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    __afl_syscall_check_errors(ret);
    return ret;
}
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
static inline int32_t __afl_syscall(int32_t number, int32_t p1, int32_t p2, int32_t p3, int32_t p4)
{
    int32_t ret;
#if !defined(__PIC__)
    asm volatile("call *%%gs:16" : "=a"(ret) : "a"(number), "b"(p1), "c"(p2), "d"(p3), "S"(p4) : "memory");
#else
    asm volatile("xchg %%ebx, %%edi;\n"
                 "call *%%gs:16;\n"
                 "xchg %%ebx,%%edi;\n"
                 : "=a"(ret)
                 : "a"(number), "D"(p1), "c"(p2), "d"(p3), "S"(p4)
                 : "memory");
#endif
    __afl_syscall_check_errors(ret);
    return ret;
}
#elif defined(__aarch64__)
static inline int64_t __afl_syscall(int64_t number, int64_t p1, int64_t p2, int64_t p3, int64_t p4)
{
    register int64_t x8 __asm__("x8") = number;
    register int64_t x0 __asm__("x0") = p1;
    register int64_t x1 __asm__("x1") = p2;
    register int64_t x2 __asm__("x2") = p3;
    register int64_t x3 __asm__("x3") = p4;
    register int64_t x4 __asm__("x4") = 0;
    register int64_t x5 __asm__("x5") = 0;
    asm volatile("svc 0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "cc", "memory");
    __afl_syscall_check_errors(x0);
    return x0;
}
#else
#define __afl_syscall(number, p1, p2, p3, p4) syscall(number, p1, p2, p3, p4)
#endif

/*
 * Caches the syscall gettid and stores Thread ID in TLS.
 * This improves performance and reduces the number of system calls.
 */
static inline uint32_t __afl_gettid(void)
{
    static __thread uint32_t tid;

    if (__afl_likely(tid))
        return tid;

    tid = __afl_syscall(__NR_gettid, 0, 0, 0, 0) & AFL_TID_MASK;

    return tid;
}

enum __afl_state
{
    AFL_UNLOCKED = 0, // Unlocked
    AFL_LOCKED   = 1  // Locked
};

#define AFL_HAVE_WAITERS 0x80000000 // Lock have waiters bit mask

#define __AFL_ALIGN __attribute__((aligned(64))) // Most processors have a cache line size of 64 bytes

/*
 * Spinlock
 */
typedef __AFL_ALIGN uint32_t afl_spinlock_t;

static inline int afl_spin_init(afl_spinlock_t *spinlock, int shared)
{
    (void) shared;
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

static inline int afl_spin_lock(afl_spinlock_t *spinlock)
{
    uint32_t lock;

    if (__afl_likely(!__atomic_exchange_n(spinlock, AFL_LOCKED, __ATOMIC_ACQUIRE)))
        return 0;

loop:
    __afl_pause;
    lock = __atomic_exchange_n(spinlock, AFL_LOCKED, __ATOMIC_ACQUIRE);
    if (lock != AFL_UNLOCKED)
        goto loop;

    return 0;
}

static inline int afl_spin_unlock(afl_spinlock_t *spinlock)
{
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

static inline int afl_spin_owner_lock(afl_spinlock_t *spinlock)
{
    uint32_t lock;
    uint32_t tid = __afl_thread_pointer_tid();

    __atomic_load(spinlock, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock already owned spinlock.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

loop:
    lock = AFL_UNLOCKED;
    if (__atomic_compare_exchange_n(spinlock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;
    __afl_pause;
    goto loop;

    return 0;
}

static inline int afl_spin_owner_unlock(afl_spinlock_t *spinlock)
{
    uint32_t lock = 0;
    uint32_t tid  = __afl_thread_pointer_tid();

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
typedef __AFL_ALIGN uint32_t afl_mutex_t;

#define AFL_MUTEX_INIT 0

static inline int afl_mutex_lock(afl_mutex_t *mutex)
{
    uint32_t lock;

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    if (lock & AFL_HAVE_WAITERS)
        goto futex;

    lock = AFL_UNLOCKED;
    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    if (!(lock & AFL_HAVE_WAITERS))
        __atomic_compare_exchange_n(mutex, &lock, AFL_LOCKED | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);

    while (lock != AFL_UNLOCKED) {
    futex:
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, AFL_LOCKED | AFL_HAVE_WAITERS, 0);
        lock = __atomic_exchange_n(mutex, AFL_LOCKED | AFL_HAVE_WAITERS, __ATOMIC_ACQUIRE);
    }

    return 0;
}

static inline int afl_mutex_unlock(afl_mutex_t *mutex)
{
    uint32_t lock;

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(lock == AFL_UNLOCKED, "An attempt was made to unlock an unlocked mutex.");

    if (__atomic_exchange_n(mutex, AFL_UNLOCKED, __ATOMIC_ACQUIRE) & AFL_HAVE_WAITERS)
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

static inline int afl_mutex_owner_lock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_thread_pointer_tid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock already owned mutex.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    if (__afl_likely(!lock && __atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

try_lock:
    if (!(lock & AFL_HAVE_WAITERS)) {
        lock = __atomic_or_fetch(mutex, AFL_HAVE_WAITERS, __ATOMIC_ACQUIRE);
        if (lock == AFL_HAVE_WAITERS
            && __atomic_compare_exchange_n(mutex, &lock, tid | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return 0;
    }

    __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, lock, 0);
    lock = AFL_UNLOCKED;
    if (!__atomic_compare_exchange_n(mutex, &lock, tid | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        goto try_lock;

    return 0;
}

static inline int afl_mutex_owner_unlock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_thread_pointer_tid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    if (__atomic_exchange_n(mutex, AFL_UNLOCKED, __ATOMIC_ACQUIRE) & AFL_HAVE_WAITERS)
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

static inline int afl_mutex_pi_lock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock already owned mutex.");

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

    if (!__atomic_compare_exchange_n(mutex, &tid, AFL_UNLOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
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
    __attribute__((aligned(8))) uint32_t lock;
    size_t count;
} __AFL_ALIGN afl_mutex_recursive_t;

static inline int afl_mutex_recursive_init(afl_mutex_recursive_t *mutex)
{
    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    mutex->count = 0;

    return 0;
}

static inline int afl_mutex_recursive_lock(afl_mutex_recursive_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_thread_pointer_tid();

    __atomic_load(&mutex->lock, &lock, __ATOMIC_RELAXED);

    if (__afl_likely(
          !lock && __atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
        ))
        goto success;

    if (__afl_likely(tid == (lock & AFL_TID_MASK))) {
        __afl_debug(
          mutex->count + 1 == 0,
          "Recusive mutex counter overflow. "
          "This is not an error, but please check that the EAGAIN return value is being processed correctly."
        );
        if (__afl_unlikely(mutex->count + 1 == 0))
            return EAGAIN;
        mutex->count++;
        return 0;
    }

try_lock:
    if (!(lock & AFL_HAVE_WAITERS)) {
        lock = __atomic_or_fetch(&mutex->lock, AFL_HAVE_WAITERS, __ATOMIC_ACQUIRE);
        if (lock == AFL_HAVE_WAITERS
            && __atomic_compare_exchange_n(
              &mutex->lock, &lock, tid | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED
            ))
            goto success;
    }

    __afl_syscall(__NR_futex, (intptr_t) &mutex->lock, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, lock, 0);
    lock = AFL_UNLOCKED;
    if (!__atomic_compare_exchange_n(&mutex->lock, &lock, tid | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        goto try_lock;

success:
    mutex->count = 1;

    return 0;
}

static inline int afl_mutex_recursive_unlock(afl_mutex_recursive_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_thread_pointer_tid();

    __atomic_load(&mutex->lock, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    __afl_debug(mutex->count == 0, "An attempt was made to unlock an unlocked recursive mutex.");

    if (--mutex->count == 0 && (__atomic_exchange_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_ACQUIRE) & AFL_HAVE_WAITERS))
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
 * Once
 */
typedef __AFL_ALIGN uint32_t afl_once_t;

#define AFL_SUCCESS 0x40000000 // Once init success, just return

#define AFL_ONCE_INIT 0

static inline int afl_once(afl_once_t *once, void (*init)(void))
{
    uint32_t lock;

    __atomic_load(once, &lock, __ATOMIC_RELAXED);

    if (__afl_likely(lock & AFL_SUCCESS))
        return 0;

try_lock:
    lock = AFL_UNLOCKED;
    if (__atomic_compare_exchange_n(once, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        init();

        if (__atomic_exchange_n(once, AFL_SUCCESS, __ATOMIC_ACQUIRE) & AFL_HAVE_WAITERS)
            __afl_syscall(__NR_futex, (intptr_t) once, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, INT32_MAX, 0);

        return 0;
    }

    if (lock & AFL_SUCCESS)
        return 0;

    lock = AFL_LOCKED;
    if (__atomic_compare_exchange_n(once, &lock, AFL_LOCKED | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        __afl_syscall(__NR_futex, (intptr_t) once, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, AFL_LOCKED | AFL_HAVE_WAITERS, 0);

    if (!(lock & AFL_SUCCESS))
        goto try_lock;

    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __AFL_H */
