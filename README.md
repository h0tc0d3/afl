# afl — Atomic Fast Locks

`afl` stands for **Atomic Fast Locks**.

Small, futex based locks for user space, in a single header. No library, no
runtime, no build step: copy `afl.h` into a project and compile with any C17
compiler that supports the GCC/Clang atomic builtins.

`afl.h` provides spinlocks with and without owner tracking, a plain mutex, an
owner tracking mutex, a priority inheritance mutex, a recursive mutex, a
condition variable and a once-only initializer. The blocking paths are the raw
`futex` system call, so no lock library sits in between and the slow path does not
pay for a wrapper either.

This repository also carries the benchmark suite and the test suite that are used
to develop and validate the header:

```text
afl.h              the header
mutex.h            Wine style macro shim that maps the afl API (or pthread) onto
                   the WINE_*() macro names
benchmarks/        the benchmark suite
  benchmark.c      runs every benchmark binary, pinned to a small set of CPUs
  benchmark.h      shared benchmark harness (timing, statistics, output)
  spinlock.c       benchmark: afl_spin_lock        against pthread_spin_lock
  spinlock_owner.c benchmark: afl_spin_owner_lock  against pthread_spin_lock
  mutex.c          benchmark: afl_mutex_lock       against pthread_mutex_lock
  mutex_owner.c    benchmark: afl_mutex_owner_lock against pthread_mutex_lock
  mutex_pi.c       benchmark: afl_mutex_owner_lock against afl_mutex_pi_lock
  mutex_recursive.c        benchmark: recursive mutex, lock taken at every level
  mutex_recursive_simple.c benchmark: recursive mutex, flat lock/unlock pairs
  cond.c           benchmark: afl_cond_wait/signal against pthread_cond_wait/signal
  once.c           smoke test that afl_once() runs its initializer exactly once
tests/             the test suite
  test.c           test suite for the whole header
Makefile           build, test and benchmark targets
```

## Contents

* [Requirements](#requirements)
* [Quick start](#quick-start)
* [API](#api)
* [Design](#design)
* [Correctness](#correctness)
* [Tests](#tests)
* [Benchmarks](#benchmarks)
* [Results](#results)
* [Tuning](#tuning)
* [Limitations](#limitations)

## Requirements

* Linux, x86_64 (i386 and aarch64 have their own system call stubs in the
  header, the benchmarks have only ever been measured on x86_64).
* A C17 compiler: clang or gcc. The header uses `_Atomic`/`__atomic_*`, inline
  assembly and `__attribute__((aligned(64)))`.
* `make` for the targets in this repository, plus `gcc` or `clang` and an
  OpenMP capable compiler for the benchmark binaries (`-fopenmp`).

## Quick start

```c
#include <stdio.h>

#include "afl.h"

static afl_mutex_t mutex = AFL_MUTEX_INIT;
static unsigned counter;

int main(void)
{
    afl_mutex_lock(&mutex);
    counter++;
    afl_mutex_unlock(&mutex);

    printf("%u\n", counter);

    return 0;
}
```

```bash
clang -O2 -std=gnu17 main.c -o app
```

`afl.h` calls the futex system call directly, so nothing else has to be linked.

A condition variable is used the way a `pthread_cond_t` is used, the wait returns
with the mutex held and the predicate is re-checked in a loop:

```c
static afl_cond_t cond = AFL_COND_INIT;
static int ready;

afl_mutex_lock(&mutex);
while (!ready)
    afl_cond_wait(&cond, &mutex);
afl_mutex_unlock(&mutex);
```

## API

Every function returns 0 on success and an `errno` value on failure, it never
throws and it never blocks forever by mistake: a misused lock is reported
through the return value.

| Type | Description |
| --- | --- |
| `afl_spinlock_t` | 32 bit lock word, 64 byte aligned |
| `afl_mutex_t` | 32 bit lock word, 64 byte aligned |
| `afl_mutex_recursive_t` | lock word plus a recursion counter, 64 byte aligned |
| `afl_cond_t` | a sequence number plus a waiter count, 64 byte aligned |
| `afl_once_t` | 32 bit word for `afl_once()` |

| Initializer | Description |
| --- | --- |
| `AFL_MUTEX_INIT` | `0`, valid initial value for any of the mutex types |
| `AFL_COND_INIT` | `{0, 0}`, valid initial value for `afl_cond_t` |
| `AFL_ONCE_INIT` | `0`, valid initial value for `afl_once_t` |
| `afl_spin_init(lock, shared)` | writes the free value, returns 0 |
| `afl_cond_init(cond)` | writes the free value, returns 0 |
| `afl_mutex_recursive_init(lock)` | writes the free value and the zero counter |

| Lock | Lock | Unlock | Other |
| --- | --- | --- | --- |
| `afl_spin_lock` | `-` | `afl_spin_unlock` | `afl_spin_destroy` |
| `afl_spin_owner_lock` | `-` | `afl_spin_owner_unlock` | `afl_spin_destroy` |
| `afl_mutex_lock` | `-` | `afl_mutex_unlock` | `afl_mutex_destroy` |
| `afl_mutex_owner_lock` | `-` | `afl_mutex_owner_unlock` | `afl_mutex_destroy` |
| `afl_mutex_pi_lock` | `-` | `afl_mutex_pi_unlock` | `afl_mutex_destroy` |
| `afl_mutex_recursive_lock` | `-` | `afl_mutex_recursive_unlock` | `afl_mutex_recursive_destroy` |
| `-` | `-` | `-` | `afl_once(once, init)` |

A condition variable is not a lock, so it has a table of its own. The calls that
take a `mutex` need the plain `afl_mutex_lock`/`afl_mutex_unlock` pair:

| Call | Description |
| --- | --- |
| `afl_cond_init(cond)` | writes the free value, returns 0 |
| `afl_cond_wait(cond, mutex)` | releases `mutex`, blocks until it is woken, re-acquires `mutex`, returns 0 |
| `afl_cond_timedwait(cond, mutex, deadline)` | the same with an absolute `CLOCK_MONOTONIC` deadline, returns `ETIMEDOUT` when it expires first |
| `afl_cond_signal(cond)` | wakes one waiter, returns 0 |
| `afl_cond_broadcast(cond)` | wakes every waiter, returns 0 |
| `afl_cond_destroy(cond)` | puts the condition variable back into the free state |

Return values beyond 0:

| Value | Meaning |
| --- | --- |
| `EDEADLOCK` | the calling thread already owns the lock and the lock is not recursive (`*_owner_lock`, `afl_mutex_pi_lock`) |
| `EPERM` | the calling thread does not own the lock (`*_owner_unlock`, recursive unlock) |
| `EAGAIN` | the recursion counter of `afl_mutex_recursive_lock` would overflow |
| `ETIMEDOUT` | the deadline of `afl_cond_timedwait` passed before a signal arrived |

Semantics worth knowing:

* The `*_owner_*` variants store the thread id of the owner in the lock word, so
  they detect a recursive acquisition and refuse to be released by another
  thread. The plain variants have no owner tracking, any thread may release
  them, exactly like a raw futex mutex.
* `afl_spin_*` never blocks in the kernel: a contended spinner burns CPU until it
  gets the lock. The other types spin for a bounded time and then park.
* `afl_mutex_pi_lock` uses `FUTEX_LOCK_PI`, the kernel takes care of the priority
  inheritance bookkeeping, the uncontended case stays a compare exchange.
* `afl_cond_wait` has the spurious wake ups of `pthread_cond_wait`, so the caller
  has to re-check its predicate in a loop. `afl_cond_signal` wakes one waiter,
  `afl_cond_broadcast` wakes all of them, and a wake up that nobody can receive
  does not enter the kernel at all. Only the plain
  `afl_mutex_lock`/`afl_mutex_unlock` pair may be passed to a wait, like
  `pthread_cond_wait` only works with the mutex type it was initialized for.
  `afl_cond_timedwait` measures its deadline against `CLOCK_MONOTONIC`.
* `afl_once(once, init)` calls `init()` exactly once. Every caller that returns
  from `afl_once` observes the writes of `init()` (the release/acquire pair of
  the once word), and the callers that arrive while `init()` is running block on
  the futex instead of spinning.
* `afl_*_destroy` puts the lock back into the free state. It does not check
  whether somebody is still holding or waiting for the lock, so it is only
  correct on a lock that is not in use.

## Design

### The lock word

Every lock is one 32 bit word:

```text
 31                    30 .. 0
+---------------------+----------------------------------+
| waiters bit         | owner                            |
+---------------------+----------------------------------+
```

* The plain variants (`afl_spin_lock`, `afl_mutex_lock`, `afl_once`) use the low
  bits as a three state counter: `AFL_UNLOCKED` (0), `AFL_LOCKED` (1) and
  `AFL_LOCKED | AFL_HAVE_WAITERS`.
* The owner tracking variants (`afl_spin_owner_lock`, `afl_mutex_owner_lock`,
  `afl_mutex_pi_lock`, `afl_mutex_recursive_lock`) store `gettid() & AFL_TID_MASK`
  in the low bits, which makes the owner testable and makes a recursive
  acquisition detectable.
* Bit 31 is the waiters bit. It means "a thread announced that it is going to
  sleep on this lock, wake one up when you release it".

### Acquiring

1. **Fast path**: a compare exchange from the free value. An uncontended lock is
   therefore a single atomic instruction and no system call at all. Because the
   value that is written does not carry the waiters bit, the fast path also
   clears a waiters bit that a previous, longer hand-off left behind. The
   recursive mutex reads the lock word first, to answer a re-acquisition by its
   own owner before the compare exchange: a lock that is taken at every level of
   a recursive walk re-acquires itself far more often than it acquires a free
   lock, and a compare exchange seeded from the free value fails first in that
   case, which turns every nested acquisition into a failed atomic operation.
2. **Spin**: attempts at the lock, spaced by a backoff that doubles from 1 up to
   `AFL_SPIN_BACKOFF` PAUSE iterations. `AFL_SPIN_LIMIT` bounds the number of
   attempts a mutex makes, the spinlocks spin until they win. This is a
   test-and-test-and-set loop: the expensive atomic operation is only issued when
   a plain load shows the free value, so the cache line stays shared between the
   spinners instead of being stolen by every one of them on every iteration.
3. **Park**: the thread sets the waiters bit with a compare exchange and then
   blocks in `FUTEX_WAIT`. If the compare exchange fails because the lock was
   released in the meantime, it does not sleep, it retries with the fresh value.

### Releasing

One atomic exchange that stores the free value and returns what was stored
before it. If that previous value carried the waiters bit, one waiter is woken
with `FUTEX_WAKE`, otherwise no system call is made at all.

A thread that acquires the lock on the parked path keeps the waiters bit set in
its own lock value, so the next release wakes the following waiter again. Without
that, a `FUTEX_WAKE` that is addressed to a single waiter would end the chain of
hand-offs and the remaining waiters would only be woken by the timeout of a new
arrival.

### Once

`afl_once` uses the same word layout with a third state, `AFL_SUCCESS`:

1. Load the word with acquire semantics. `AFL_SUCCESS` set means somebody already
   ran the initializer: return immediately. This is the fast path after the first
   call and it touches no other memory.
2. Otherwise take the lock with a compare exchange and run `init()`.
3. Publish `AFL_SUCCESS` with a release exchange and wake all waiters if the
   previous value carried the waiters bit.
4. Waiters that arrive while `init()` runs announce the waiters bit and block in
   `FUTEX_WAIT` until step 3 wakes all of them with `INT32_MAX`.

### Condition variable

A condition variable hands off a wake up instead of a lock, and a wake up has no
owner to store in a word, so `afl_cond_t` uses two of them:

* `sequence` is the futex word. Every signal and every broadcast increments it,
  and a waiter sleeps as long as the word still holds the value that it read, so a
  wake up that arrives between the read and the `FUTEX_WAIT` is seen by the system
  call and the waiter returns instead of sleeping.
* `waiters` counts the threads inside `afl_cond_wait`. A signal that finds the
  count at zero returns without a system call, which is the common case when the
  predicate is already true.

A wait registers itself before it releases the mutex, so a signal that arrives
after the release cannot miss it. It re-acquires the mutex before it returns, and
it may return without a signal, which is why the caller has to re-check its
predicate in a loop, exactly like `pthread_cond_wait`.

`afl_cond_timedwait` converts its absolute `CLOCK_MONOTONIC` deadline into the
relative timeout that `FUTEX_WAIT` wants, and reports `ETIMEDOUT` when the
deadline passes first.

## Correctness

The header has to keep three properties, and the test suite checks all three:

1. **Mutual exclusion**: at most one thread is inside the critical section.
2. **No lost wakeup**: a thread that announced that it is going to sleep is woken
   up when the lock is released, otherwise it hangs.
3. **No system call when there is no contention**: the fast path of an
   uncontended acquire and of a release stays inside user space.

### The invariant

An acquire only returns success after a compare exchange that matched
`AFL_UNLOCKED`, and the free value is part of the condition of that exchange, so
no path returns success without owning the lock. The expected value of that
exchange is pinned to the free value and never to the lock value that was just
observed: a compare exchange whose expected value is the observed value also
matches a lock that is still owned, and it would hand the same lock out twice.

The condition variable has the matching invariant for its wake ups: the futex
word changes before a waiter can be woken, so a wake up that arrives while the
waiter is on its way into `FUTEX_WAIT` is not lost, and a waiter registers itself
before it releases the mutex, so a signal that arrives after the release cannot
miss it. A wake up is counted, not queued: `afl_cond_signal` wakes one waiter,
`afl_cond_broadcast` wakes all of them, and a signal that no thread can receive is
dropped, exactly like `pthread_cond_signal`.

## Tests

```bash
make check                        # 96 checks, about seven seconds on 14 cores
make check-stress                 # the same suite with 32 threads, ~35 s
make check-san                    # the same suite under asan + ubsan
./tests/test                      # run the suite directly, with any settings
```

`tests/test.c` is self contained. It prints one line per check, exits non zero
when a check fails, and runs the whole suite under a watchdog, so a lost wakeup
fails the run instead of hanging it.

Both sanitizer paths pass at the default settings: `make check-san` (address plus
undefined behaviour) reports 96 passed / 0 failed, and so does the same suite
built with `gcc -fsanitize=thread`, with no reports at all. The thread sanitizer
run is worth having for a header that blocks in a raw `futex` syscall, because the
sanitizer cannot observe the hand-off that happens in the kernel: the
happens-before edges it accepts have to come from the acquire and release pairs
on the lock word and from the futex value check, not from the syscall itself.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `AFL_TEST_THREADS` | 8 | threads per contention test |
| `AFL_TEST_ITERATIONS` | 50000 | lock/unlock pairs per thread |
| `AFL_TEST_TIMEOUT_MS` | 120000 | watchdog: the suite fails after this |

What is covered:

* the return values and error codes of every lock and unlock function, including
  the `EDEADLOCK` of a recursive acquisition and the `EPERM` of a foreign
  release, and that a rejected call leaves the lock usable;
* the state of the lock word after an uncontended acquire and after a release
  (the fast path has to leave the waiters bit clear);
* mutual exclusion under contention for `afl_spin_lock`, `afl_spin_owner_lock`,
  `afl_mutex_lock`, `afl_mutex_owner_lock`, `afl_mutex_pi_lock` and the recursive
  mutex, which takes the lock twice per iteration so one acquisition nests;
* a parked hand-off: three times as many threads as cores and a critical section
  that is longer than the spin phase, so the waiters really do block on the futex
  and the wake up chain is what is being exercised;
* `afl_once` with 20 ms long initializers: the initializer runs exactly once and
  every thread observes its writes;
* `afl_cond_wait` and `afl_cond_broadcast` with as many waiters as threads, so no
  waiter is left behind, and the mutex that a wait comes back with is checked the
  same way the locks are checked: every returning thread runs the overlap counter
  of the mutual exclusion tests;
* `afl_cond_signal` with one condition variable per thread, so a signal that
  wakes more than its own waiter shows up as a second thread that returns;
* `afl_cond_timedwait` for the three cases that matter: an expired deadline, a
  deadline that passes with nobody signalling, and a signal that arrives before
  the deadline, which has to return well before it expires.

## Benchmarks

```bash
make                                    # build every benchmark binary
./benchmarks/benchmark                  # run all of them, pinned to the CPUs 0-4
OMP_NUM_THREADS=28 ./benchmarks/mutex   # oversubscribe the cores (2x here)
./benchmarks/mutex                      # .../or run a single one, unpinned
```

Each binary measures two implementations of the same workload and prints them
side by side. The threads are the OpenMP threads of the harness
(`OMP_NUM_THREADS`, bound with `proc_bind(spread)`), the workload is
`RUNS_COUNT` samples of `RUN_ITERATIONS` lock/unlock pairs per thread.

| Binary | Left column | Right column | Notes |
| --- | --- | --- | --- |
| `benchmarks/spinlock` | `afl_spin_lock` | `pthread_spin_lock` | never parks, pure spin/sleep hand-off |
| `benchmarks/spinlock_owner` | `afl_spin_owner_lock` | `pthread_spin_lock` | same, plus the owner check in every iteration |
| `benchmarks/mutex` | `afl_mutex_lock` | `pthread_mutex_lock` | |
| `benchmarks/mutex_owner` | `afl_mutex_owner_lock` | `pthread_mutex_lock` | |
| `benchmarks/mutex_pi` | `afl_mutex_owner_lock` | `afl_mutex_pi_lock` | no pthread column: spin then park against `FUTEX_LOCK_PI`, where the kernel does the priority inheritance bookkeeping |
| `benchmarks/mutex_recursive_simple` | `afl_mutex_recursive_lock` | pthread recursive mutex | flat lock/unlock pairs |
| `benchmarks/mutex_recursive` | `afl_mutex_recursive_lock` | pthread recursive mutex | the critical section is a recursion of depth 16 that takes the lock at every level, so this one reports the whole recursion instead of a single pair |
| `benchmarks/cond` | `afl_cond_wait`/`afl_cond_signal` | `pthread_cond_wait`/`pthread_cond_signal` | every OpenMP thread ping-pongs with a parked partner of its own, so one iteration is two signal/wait round trips; reports the whole hand-off, not a lock/unlock pair |
| `benchmarks/once` | - | - | smoke test: `afl_once` over 100 OpenMP iterations, prints `Init` once and complains if the initializer runs twice |

`benchmarks/benchmark.c` runs the binaries of the table one after the other under
the title of their column pair. The shell script that used to do that is gone:
the C runner can pin a run to a set of CPUs itself, so `taskset` is not needed
any more, and it can be told which set to use:

```bash
AFL_BENCH_CPUS=0-7 ./benchmarks/benchmark    # or
./benchmarks/benchmark --cpus=0-4,8
```

`benchmarks/benchmark.h`, the shared harness, measures each half of the pair
separately, so the output attributes the cost of a hand-off to the side where it
happens:

```text
                               afl          pthread
---------------------------------------------------
 [+]    duration:    1260890803.25    2066195597.75
 [+]        mean:         12608.91         20661.96
 [+]      median:          2856.50         12931.12
 [+]       stdev:         23864.47         26268.14
 [-]         min:            31.12            30.00
 [+]         max:        387616.12        786313.25
---------------------------------------------------
 [+]   lock time:         11361.54         19779.98
 [-] unlock time:          1247.37           881.98
---------------------------------------------------
 afl/pthread mean ratio: 0.610
 iterations: 800000
```

* `mean`, `median`, `stdev`, `min` and `max` are nanoseconds per lock/unlock
  pair. The `[+]`/`[-]` marker says which column is smaller.
* `lock time` and `unlock time` are the same statistics for the two halves of the
  pair: waiting for the current owner lands in `lock time`, the `FUTEX_WAKE` of
  the release in `unlock time`.
* The mean is much larger than the median here: with more threads than the
  critical section can absorb, a sample occasionally waits for a whole scheduler
  slice. The median is the number to compare, the max shows the tail.
* A short untimed warm-up pass runs before the samples, so the startup of the
  thread pool and the first touch of the lock do not end up in the statistics.
* The critical section is `bench_payload()`: a loop of `BENCH_WORK` iterations
  that accumulates into a `volatile` thread local and ends in a compiler memory
  barrier, so the optimizer can neither fold the loop away nor move work out of
  the critical section. Both columns execute exactly the same payload.

Knobs: `RUNS_COUNT` and `RUN_ITERATIONS` are `#define`d at the top of each
benchmark source (they have to be, `benchmarks/benchmark.h` stops the build when
they are missing), `-DBENCH_WORK=<n>` overrides the size of the payload and
`OMP_NUM_THREADS=<n>` chooses the number of threads at run time. `BENCH_WORK=0`
removes the payload and reduces the benchmark to a pure hand-off measurement. The
runner pins every run to the CPUs of `AFL_BENCH_CPUS` (`0-4` by default) so that
the numbers of two runs are comparable; run the binaries directly to measure the
whole machine.

## Results

All numbers below come from one machine (14 physical cores, x86_64, clang 22,
`-O2 -march=arrowlake -mtune=arrowlake` plus the flags from the Makefile), three
rounds per benchmark. The numbers are the medians of a round in nanoseconds per
lock/unlock pair, three rounds per cell: `round 1 / round 2 / round 3`.

One thing about the method matters for reading them: code layout moves these
benchmarks. A build that differed only in `-falign-functions` and `-falign-loops`
moved one benchmark by up to 12% while this was measured, which is the same order
of magnitude as the smallest difference in the table below, so that one is quoted
as it was measured and not as an algorithmic gain.

A second property of the method matters when the thread count is not the one the
table was measured at: at `OMP_NUM_THREADS=1` glibc's mutex is not the mutex the
table compares against. libgomp runs a parallel region of a single thread on the
encountering thread, so the process never creates a thread,
`__libc_single_threaded` stays true, and `pthread_mutex_lock` and
`pthread_mutex_unlock` take glibc's single threaded path: a plain load and a
plain store, with no atomic instruction and no `lock` prefix at all, which a
mutex that may be shared is not allowed to do. Measured against that path the
three mutex rows come out at about 1.3x, while `spinlock` and `spinlock_owner`,
whose baseline has no such shortcut, come out at 0.98x.

### The header against pthread

| Benchmark | afl | baseline | Ratio |
| --- | --- | --- | --- |
| `spinlock` | 29.5 / 31.4 / 30.5 | 31.5 / 32.6 / 30.4 (`pthread_spin_lock`) | 1.0x |
| `spinlock_owner` | 40.0 / 41.4 / 41.0 | 30.4 / 32.8 / 32.3 (`pthread_spin_lock`) | 0.77x |
| `mutex` | 2949 / 2754 / 2863 | 14724 / 15439 / 16054 (`pthread_mutex_lock`) | 5.6x |
| `mutex_owner` | 3769 / 4225 / 3492 | 15235 / 15559 / 14885 (`pthread_mutex_lock`) | 4.0x |
| `mutex_pi` (owner / PI) | 3425 / 3314 / 3633 | 82024 / 80936 / 87453 (`afl_mutex_pi_lock`) | 24x |
| `mutex_recursive_simple` | 3420 / 2634 / 3716 | 14688 / 15908 / 14277 (pthread recursive) | 4.3x |
| `mutex_recursive` | 4854 / 4865 / 4672 | 8360 / 8359 / 8348 (pthread recursive) | 1.7x |

The ratio is the median of the ratios of the three rounds. `spinlock_owner` is
the one benchmark where the owner check costs more than it saves, 1.3x slower
than `pthread_spin_lock`: it reads the lock word and tests the tid in every
iteration of the spin, and it uses a compare exchange where pthread uses a plain
exchange. The `mutex_pi` row compares two afl locks against each other instead of
a lock against glibc: `afl_mutex_pi_lock` has no spin phase at all, it enters the
kernel with `FUTEX_LOCK_PI` as soon as the lock is not free and lets the kernel
do the priority inheritance bookkeeping. That is the intended trade, not a
regression: the PI lock exists for the case where a high priority thread must not
be stuck behind a low priority holder, and it costs 24x more per pair than spin
then park under this contention (on an uncontended lock the difference is smaller
but still a kernel round trip against a compare exchange).

`cond` is not in the table because it does not measure a lock/unlock pair: one
iteration is a whole hand-off, i.e. two `signal`/`wait` round trips against a
parked partner thread, so its number is a round trip time and is not comparable
with the rows above.

## Tuning

| Knob | Effect |
| --- | --- |
| `-DAFL_SPIN_LIMIT=<n>` | attempts a contended **mutex** acquire makes before it parks; the spinlocks spin until they win the lock. Default 32. The attempts are spaced by `AFL_SPIN_BACKOFF`, so this counts attempts and not PAUSE iterations: the default covers about 23000 PAUSE iterations before the thread parks. Both ends of the range measure worse than the default. At 128 the three benchmarks that acquire and release in a tight loop are 1 to 5% faster, but `mutex_recursive` goes from level with its baseline, within about 1% at five, fifteen and twenty eight threads, to 43%, 52% and 76% slower at those counts: the cost grows with the thread count. At 8 attempts those three benchmarks are 2.7 to 8 times slower than their baseline, because the waiters park in the middle of a hand-off. `cond` is not quoted either way: its own baseline moves by about 30% between runs at five threads, which is wider than the effect being measured. Set it to 0 to disable spinning. Raise it when the critical sections are short and the threads do not oversubscribe the cores; lower it when they do, because a spinner burns the core of a thread that may be the one that has to release the lock. |
| `-DAFL_SPIN_BACKOFF=<n>` | longest gap, in PAUSE iterations, between two attempts on a contended `afl_spin_lock`, `afl_spin_owner_lock` or mutex; the gap doubles from 1 up to this cap. Default 1024. Lowering it makes the waiters race the release and turns acquires into cross core hand-offs, which measures worse, see the comment in `afl.h`. It is also what makes the spin phase of a mutex pay off: with it, `mutex`, `mutex_owner` and `mutex_recursive_simple` acquire about 20 times faster than through a tight loop of the same length, 35 to 46 ns against 840 to 1080 ns at five threads. It also decides how long that spin phase lasts for a given `AFL_SPIN_LIMIT`, and a spin that is longer than it has to be is a loss on the benchmarks that hand the lock over thousands of times per measurement, which is why the limit defaults to 32 rather than to a larger count, see `AFL_SPIN_LIMIT` above. `afl_mutex_pi_lock` never spins, it goes straight to the `FUTEX_LOCK_PI` syscall. |
| `-DAFL_DEBUG` | turns on the misuse checks, for example a release from a thread that does not own the lock, reported on stderr. |
| `-DBENCH_WORK=<n>` | size of the critical section. `BENCH_WORK=0` measures a pure hand-off. |
| `RUNS_COUNT` / `RUN_ITERATIONS` | samples and pairs per sample; `#define`d at the top of each benchmark source, see [Benchmarks](#benchmarks) |
| `OMP_NUM_THREADS=<n>` | benchmark threads per column. |
| `AFL_BENCH_CPUS` / `--cpus` | CPUs the benchmark runner pins every run to, `0-4` by default. |
| `AFL_TEST_THREADS`, `AFL_TEST_ITERATIONS`, `AFL_TEST_TIMEOUT_MS` | test suite size and watchdog, see [Tests](#tests). |

## Limitations

* Linux only: the blocking paths are raw `futex` calls, and the futexes use
  `FUTEX_PRIVATE_FLAG`, so the locks work between threads of one process and are
  not shared memory locks.
* No priority inheritance outside `afl_mutex_pi_*`, and no robustness: an owner
  that dies while holding a lock leaves the lock held.
* `afl_spin_lock` and `afl_spin_owner_lock` never park, so they must not guard a
  critical section that can be long or preempted. `afl_spin_owner_lock` is also
  the one lock here that is measurably slower than what glibc offers.
* Only the recursive mutex may be acquired twice by its owner. For the owner
  tracking locks a second acquisition returns `EDEADLOCK`; for the plain ones it
  deadlocks, exactly like a raw futex mutex.
* The owner tracking locks assume a `gettid()` that fits in `AFL_TID_MASK`
  (30 bits), which is what Linux gives you.
* `afl_cond_t` has no attribute object, no clock selection and no notion of a
  process shared condition variable, and `afl_cond_destroy` does not check
  whether somebody is still waiting: it resets the state, exactly like the
  `afl_*_destroy` of the locks. A signal that is sent without holding the mutex
  can be lost, the same way `pthread_cond_signal` can lose one, so signal under
  the lock that protects the predicate.
* Every type is aligned to a cache line, which costs a cache line per object and
  makes an array of the raw type impossible: an array element has to have a size
  that is a multiple of the alignment, so wrap the type in a struct of 64 bytes
  if you need an array of them.
* The sanitizer targets need the sanitizer runtime of the compiler (`compiler-rt`
  for clang, `libasan`/`libubsan` for gcc). If only part of it is installed the
  build does not link; `make check-san COMPILER=gcc` is the fallback when clang's
  `compiler-rt` is incomplete, and there is no `make` target for the thread
  sanitizer, although the suite does pass under one (see [Tests](#tests)).
* `afl_cond_timedwait` converts its deadline with `clock_gettime`, the one call of
  the header that goes through the C library instead of a raw system call. It is a
  vDSO call on the platforms this is measured on, so it does not enter the kernel.
* The numbers are latency measurements from one machine and one compiler. They
  are a development tool for this header, not a portable comparison of lock
  libraries.
