# afl — Atomic Fast Locks

`afl.h` is a header-only collection of locks for Linux user space. It provides
spinlocks, mutexes, reader/writer locks, condition variables and once-only
initialization. Blocking paths use the futex system call; no separate lock
library is required.

## Requirements

- GCC or Clang with GNU C17 support. The header uses compiler atomic builtins,
  inline assembly and alignment attributes.
- Linux on x86-64, i386 or AArch64 for the system call stubs in `afl.h`.
- `make` to build the repository's tests and benchmarks. Sanitizer targets need
  the matching compiler runtime.

The tests and latency benchmarks use `afl_thread.h`, an internal thread layer
with raw `clone` and futex calls. Its TLS setup supports x86-64 and AArch64 and
relies on libc details. ThreadSanitizer builds use pthreads to track thread
creation. The elapsed-time benchmark also uses pthread workers.

## Quick start

Copy `afl.h` into your project. A complete `main.c`:

```c
#include <stdio.h>

#include "afl.h"

static afl_mutex_t mutex = AFL_MUTEX_INIT;
static unsigned counter;

int main(void)
{
    int error = afl_mutex_lock(&mutex);
    if (error != 0)
        return error;

    unsigned value = ++counter;
    error = afl_mutex_unlock(&mutex);
    if (error != 0)
        return error;

    return printf("%u\n", value) < 0 ? 1 : 0;
}
```

```sh
clang -O2 -std=gnu17 -Wall -Werror main.c -o app
```

Protect every access to shared state with the same lock. Use matching acquire
and release functions for the chosen family.

## API

Lock functions return `0` on success or a positive `errno` value on failure.
`afl_rwlock_unlock` returns `void`. The clock helper `afl_clock_gettime` follows
`clock_gettime`: `0` on success, `-1` with `errno` set on failure.

### Types and initialization

| Family | Type | Initialization |
| --- | --- | --- |
| Plain or owner-tracking spinlock | `afl_spinlock_t` | `afl_spin_init(&lock, 0)` |
| Plain, owner-tracking or priority-inheritance mutex | `afl_mutex_t` | `AFL_MUTEX_INIT` |
| Recursive mutex | `afl_mutex_recursive_t` | `{0}` or `afl_mutex_recursive_init(&lock)` |
| Adaptive mutex | `afl_mutex_adaptive_t` | `AFL_MUTEX_ADAPTIVE_INIT` or `afl_mutex_adaptive_init(&lock)` |
| Priority-ceiling mutex | `afl_mutex_pc_t` | `AFL_MUTEX_PC_INIT` or `afl_mutex_pc_init(&lock, ceiling)` |
| Reader/writer lock | `afl_rwlock_t` | `AFL_RWLOCK_INIT` or `afl_rwlock_init(&lock)` |
| Condition variable | `afl_cond_t` | `AFL_COND_INIT` or `afl_cond_init(&cond)` |
| Once-only initializer | `afl_once_t` | `AFL_ONCE_INIT` |

Types require 64-byte alignment. The scalar lock words are 32 bits; recursive
and priority-ceiling mutexes carry additional bookkeeping. Preserve the
alignment in allocated storage. For arrays of aligned scalar types, wrap each
lock in a struct so the element size meets the alignment requirement.

The `shared` argument to `afl_spin_init` is accepted for API compatibility and
ignored. Locks in this header are for threads within one process.

### Lock operations

| Family | Acquire | Try acquire | Release |
| --- | --- | --- | --- |
| Spinlock | `afl_spin_lock` | `afl_spin_trylock` | `afl_spin_unlock` |
| Owner-tracking spinlock | `afl_spin_owner_lock` | `afl_spin_owner_trylock` | `afl_spin_owner_unlock` |
| Mutex | `afl_mutex_lock` | `afl_mutex_trylock` | `afl_mutex_unlock` |
| Owner-tracking mutex | `afl_mutex_owner_lock` | `afl_mutex_owner_trylock` | `afl_mutex_owner_unlock` |
| Priority-inheritance mutex | `afl_mutex_pi_lock` | `afl_mutex_pi_trylock` | `afl_mutex_pi_unlock` |
| Recursive mutex | `afl_mutex_recursive_lock` | `afl_mutex_recursive_trylock` | `afl_mutex_recursive_unlock` |
| Adaptive mutex | `afl_mutex_adaptive_lock` | `afl_mutex_adaptive_trylock` | `afl_mutex_adaptive_unlock` |
| Priority-ceiling mutex | `afl_mutex_pc_lock` | `afl_mutex_pc_trylock` | `afl_mutex_pc_unlock` |
| Reader | `afl_rwlock_rdlock` | `afl_rwlock_tryrdlock` | `afl_rwlock_unlock` |
| Writer | `afl_rwlock_wrlock` | `afl_rwlock_trywrlock` | `afl_rwlock_unlock` |

Trylocks do not wait for the lock. A failed attempt leaves the lock word
unchanged. Owner-ID initialization and priority-ceiling bookkeeping may still
require system calls. A trylock on a lock the caller holds returns `EBUSY`,
except that a recursive mutex permits another level of acquisition.

The recursive mutex must be released once per successful acquisition. Owner
tracking detects a recursive acquire of a nonrecursive lock and rejects foreign
releases. Plain locks perform no ownership checks.

Each family has a destroy function: `afl_spin_destroy`, `afl_mutex_destroy`,
`afl_mutex_recursive_destroy`, `afl_mutex_adaptive_destroy`,
`afl_mutex_pc_destroy` and `afl_rwlock_destroy`. Destroy resets the state and
requires that no thread holds or waits for the lock.

`afl_mutex_pc_getceiling` reads a priority ceiling; `afl_mutex_pc_setceiling`
changes it while the mutex is free. Smaller ceiling values request higher
priorities. `AFL_MUTEX_PC_INIT` uses `AFL_MUTEX_PC_CEILING_DEFAULT` (`99`).
Release nested priority-ceiling locks in reverse acquisition order so each
release restores the scheduling state saved by its matching acquire.

### Deadlines

Timed operations take a pointer to an absolute `struct timespec`:

| Clock | Operations |
| --- | --- |
| `CLOCK_REALTIME` | `afl_mutex_timedlock`, `afl_mutex_owner_timedlock`, `afl_mutex_recursive_timedlock` |
| `CLOCK_MONOTONIC` | `afl_rwlock_timedrdlock`, `afl_rwlock_timedwrlock`, `afl_cond_timedwait` |

A `NULL` deadline or `tv_nsec` outside `[0, 1000000000)` returns `EINVAL`
without changing the lock state. A free lock can be acquired with a deadline
in the past; contended acquisitions check the deadline while spinning and
before parking. An expired condition wait returns with the mutex still held.

### Condition variables

Condition waits require the plain `afl_mutex_lock`/`afl_mutex_unlock` pair.
They release the mutex while waiting and reacquire it before returning from a
normal wakeup, interruption or timeout. Reacquisition errors take precedence
over wait errors.

Check the predicate while holding its mutex. While it is false, wait on the
condition variable and recheck after each successful return. Change the
predicate and call `afl_cond_signal` or `afl_cond_broadcast` while holding the
same mutex. Signals wake one waiter; broadcasts wake all waiters. Waits can
return without a matching signal, so the predicate check must be a loop.
`afl_cond_destroy` requires that no thread is using or waiting on the condition
variable.

### Once-only initialization

`afl_once(&once, init)` calls the `void init(void)` function once. Other callers
wait until it returns, then observe its writes through release/acquire ordering.
The initializer must return to publish completion. Use the same initializer for
all calls on a given once word.

### Error codes

| Code | Meaning |
| --- | --- |
| `EBUSY` | A trylock could not acquire, or a ceiling change found a busy mutex. |
| `EDEADLOCK` | A nonrecursive owner-tracking acquire found the caller already owns the lock. |
| `EPERM` | An owner-tracking release found a different owner. |
| `EAGAIN` | The recursive depth or reader count would overflow. |
| `ETIMEDOUT` | A contended timed acquisition or condition wait reached its deadline. |
| `EINVAL` | An invalid deadline or priority-ceiling argument; a timed operation could not read its clock. |

Blocking paths can also return kernel errors. Priority-inheritance acquisition
retries `EINTR` and `EAGAIN`; other futex errors return to the caller. Debug
builds report misuse and syscall failures on stderr.

## Lock behavior

A plain mutex first attempts an acquire compare-and-exchange. Under contention,
it spins with backoff, sets the waiters bit and uses `FUTEX_WAIT`. Release
exchanges the word to zero and wakes a waiter if the exchanged value carried
the waiters bit. The kernel checks the expected word before parking, so a
release racing with the wait does not lose its wakeup.

Spinlocks keep retrying and never park on a futex. Their backoff can yield the
processor. Keep their critical sections short, especially when runnable threads
outnumber CPUs.

The adaptive mutex packs a contention hint into its lock word. Contended
handoffs raise the hint; uncontended acquisitions lower it. The hint selects a
spin budget between `AFL_ADAPTIVE_SPIN_MIN` and `AFL_ADAPTIVE_SPIN_MAX`.

Reader/writer locks prefer writers: a writer's claim blocks new readers while
existing readers drain.

Condition variables use a sequence counter and waiter count. A wait registers
before releasing its mutex, then waits for a sequence change. After a wakeup,
mutex reacquisition uses one fast attempt followed by parking without the
ordinary mutex spin budget.

## Tests

```sh
make
make check-san
make check check-stress
make check-tsan
make check-debug
```

`tests/test.c` checks error returns, mutual exclusion and parked handoffs. It
also covers deadlines, interrupted waits, writer preference and publication of
initialized state. A watchdog ends a stalled run. Debug builds check diagnostic
messages; ThreadSanitizer builds use pthread-created workers so the sanitizer
can observe thread lifetimes.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `AFL_TEST_THREADS` | `8` | Workers per contention test. |
| `AFL_TEST_ITERATIONS` | `50000` | Lock/unlock pairs per worker. |
| `AFL_TEST_TIMEOUT_MS` | `120000` | Watchdog timeout. |
| `AFL_TEST_CPUS` | `0-3` | CPU affinity list. |

`make check-stress` sets 32 workers and 50000 iterations. Priority-elevation
checks report a skip if the process lacks the required scheduling permissions.

## Benchmarks

```sh
make bench
./benchmarks/benchmark --list
./benchmarks/benchmark --filter=mutex_pi
./benchmarks/benchmark --cpus=0-7
AFL_BENCH_THREADS=8 ./benchmarks/benchmark
```

`make bench` builds the latency benchmarks and runs the selected programs in
sequence. The default CPU set is `0-3`; `--cpus=<list>` or
`AFL_BENCH_CPUS` selects another set within the process's allowed affinity mask.
`--filter=<substring>` matches titles or binary names, ignores case and can be
repeated. Choose a specific name such as `mutex_pi` to avoid unintended matches.
Arguments can also pass through `make bench BENCH_ARGUMENTS=--filter=mutex_pi`.

| Binary | Workload |
| --- | --- |
| `spinlock`, `spinlock_owner` | Plain and owner-tracking spins against `pthread_spin_lock`. |
| `mutex`, `mutex_owner` | Mutex lock/unlock pairs against pthread mutexes; `mutex` also measures timed locking. |
| `mutex_pi` | Owner-tracking, priority-inheritance and priority-ceiling variants, with matching pthread protocols where supported. |
| `mutex_recursive`, `mutex_recursive_simple` | Nested recursive locking and flat recursive lock/unlock pairs. |
| `mutex_adaptive` | Uncontended, two-worker and CPU-sized workloads against plain AFL and pthread mutexes. |
| `rwlock` | Readers, writers and mixed access against `pthread_rwlock_t`. |
| `uncontended` | One worker per lock, with both states of libc's single-thread mutex shortcut. |
| `cond` | A condition-variable handoff with a parked partner per worker. |

Binary names in the table are relative to `benchmarks/`. Run
`./benchmarks/once` for the separate initialization smoke test.

### Reading latency results

The harness times lock and unlock calls around the same critical-section
payload for each implementation. It reports nanoseconds per pair, with separate
lock and unlock averages. Condition-variable results cover a whole handoff.
Means include time waiting for a holder; percentiles show the distribution of
that wait. Compare repeated runs with the same affinity, workload and compiler.

On x86, the default timer uses `RDTSCP` with an `LFENCE` after the opening
read and calibrates ticks against `CLOCK_MONOTONIC_RAW`. Migrating samples are
discarded and counted. `make CLOCK=1` selects the clock timer, which is also
the default on other architectures. `RDTSCP=1` selects the x86 timer explicitly.

`AFL_BENCH_THREADS` defaults to the available CPU count. Each worker pins to a
CPU in the inherited affinity set. `BENCH_WORK` controls payload operations and
`BENCH_WARMUP` controls untimed warmup samples; `RUNS_COUNT` and `RUN_ITERATIONS`
in each benchmark source set the sample count and pairs per sample.

### Elapsed-time benchmark

```sh
make bench-throughput BENCH_ARGUMENTS="4 1000000 64 5"
```

The arguments are workers, iterations per worker, payload operations and rounds.
Defaults are `4 1000000 0 5`; the round count must be positive and odd. This
benchmark uses pthread workers and wall-clock timing for the full concurrent
run, checks protected counters and reports median nanoseconds per operation.
Its elapsed time includes the critical-section payload.

## Tuning

Define lock settings when compiling your application:

| Define | Default | Purpose |
| --- | --- | --- |
| `AFL_SPIN_LIMIT` | `32` | Fixed-budget mutex and reader/writer retries before parking; `0` disables their spin phase. |
| `AFL_SPIN_BACKOFF` | `1024` | Maximum pauses between retries. Plain spinlocks cap the gap at 16; owner spins and mutexes use this setting. |
| `AFL_SPIN_PAUSE_BUDGET` | `1024` | Accumulated pauses before yielding; the budget restarts after each yield. |
| `AFL_ADAPTIVE_SPIN_MIN` | `4` | Adaptive mutex budget at the lowest hint. |
| `AFL_ADAPTIVE_SPIN_MAX` | `32` | Adaptive mutex budget at the highest hint. |
| `AFL_DEBUG` | Off | Misuse and syscall diagnostics. `make DEBUG=1` enables it for repository builds. |

`AFL_SPIN_BACKOFF` and `AFL_SPIN_PAUSE_BUDGET` accept values from `1` to
`INT32_MAX`. Tune with your workload: more spinning can avoid futex calls for
short holds, while less spinning leaves CPU time for a descheduled holder.

Repository builds accept `COMPILER`, `CFLAGS`, `O`, `DEBUG`, `M32`, `CLOCK` and
`RDTSCP`. The default compiler is Clang and the default optimization level is
`-O2`. Use `make COMPILER=gcc` to build with GCC.

## Limits

- Locks use private futexes and do not support sharing between processes.
- Owner death and thread cancellation have no recovery protocol. An owner that
  exits while holding a lock can leave its waiters blocked.
- Plain locks cannot detect recursive acquisition or a release by a non-owner.
  Initialize or destroy a lock only when no other thread can access it.
- Priority ceilings use raw scheduling syscalls. Permission failures disable
  further boost attempts for that thread; the acquired PI mutex remains usable.
  Scheduling caches are per thread and translation unit, so keep ceiling
  operations within one translation unit. External scheduling changes can make
  those caches stale, and libc scheduling queries may not reflect a temporary
  boost.

## License

[Mozilla Public License 2.0](LICENSE).
