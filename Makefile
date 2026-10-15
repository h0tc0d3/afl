#
# Makefile
#

ifndef COMPILER
COMPILER = clang
endif

ifdef M32
CFLAGS += -m32
endif

ifdef O
CFLAGS += -O$(O)
else
CFLAGS += -O2
endif

# DEBUG=1 turns the misuse diagnostics of afl.h on and keeps the debug symbols.
# The name says what the knob does: it enables AFL_DEBUG.
ifdef DEBUG
CFLAGS += -g3 -ggdb -DAFL_DEBUG
endif

CFLAGS += -std=gnu17 -Wall -Werror -DUSE_AFL -I.
LDLIBS += -lm

# The timer the benchmarks measure with. RDTSCP is the default on x86, where
# benchmark.h reads the counter with __builtin_ia32_rdtscp; every other
# architecture defaults to clock_gettime. CLOCK=1 forces the clock_gettime
# timer on any host and RDTSCP=1 is the explicit form of the x86 default, so
# the two knobs are mutually exclusive. The RDTSC knob is gone, and a request
# for it stops here instead of falling through to another timer.
#
# uname -m names the host, which is what the default timer has to exist for:
# M32=1 builds 32-bit x86 on an x86_64 host, and i386 through i686 are x86 as
# well, so the host name selects rdtscp for both.
#
# benchmark.h is the only reader of the timer macro, so it joins BENCH_CFLAGS
# below and the test rules never see it.
UNAME_M   := $(shell uname -m)
X86_ARCHS := x86_64 i386 i486 i586 i686

ifdef RDTSC
$(error The RDTSC knob is gone: the unfenced rdtsc timer is removed. Build with the default timer (rdtscp on x86), or set CLOCK=1 for the clock_gettime timer)
endif

ifdef CLOCK
ifdef RDTSCP
$(error CLOCK=1 and RDTSCP=1 are mutually exclusive: each selects a different timer)
endif
TIMER_CFLAGS = -DUSE_CLOCK_GETTIME
else
ifdef RDTSCP
TIMER_CFLAGS = -DUSE_RDTSCP
else
ifneq (,$(filter $(UNAME_M),$(X86_ARCHS)))
TIMER_CFLAGS = -DUSE_RDTSCP
else
TIMER_CFLAGS = -DUSE_CLOCK_GETTIME
endif
endif
endif

#CFLAGS := $(filter-out -fstack-protector-strong -fstack-clash-protection -fcf-protection,$(CFLAGS))
#CFLAGS += -fno-stack-protector -fno-stack-clash-protection

# The benchmark harness and the test suite pin their threads with
# sched_setaffinity and read the inherited mask with sched_getaffinity, so both
# need cpu_set_t, which glibc exposes only under _GNU_SOURCE. afl.h does not
# define the macro and neither header can define it either: a #define _GNU_SOURCE
# only takes effect before the first libc include, so it belongs on the command
# line. The definition is empty to match the "#define _GNU_SOURCE" that
# benchmark.c and mutex_pi.c already carry, which keeps the redefinition benign
# under -Wall -Werror. The timer macro stays out of the test suite, which never
# reads it: benchmark.h is its only reader.
BENCH_CFLAGS = $(CFLAGS) -D_GNU_SOURCE= $(TIMER_CFLAGS)
TEST_CFLAGS  = $(CFLAGS) -D_GNU_SOURCE=

# The benchmark sources live in benchmarks/, the test suite in tests/. The -I.
# above lets all of them include afl.h with a plain #include.
BENCHMARK_DIR = benchmarks
TEST_DIR      = tests

BENCHMARK_SOURCES =                            \
	$(BENCHMARK_DIR)/spinlock.c                \
	$(BENCHMARK_DIR)/spinlock_owner.c          \
	$(BENCHMARK_DIR)/mutex.c                   \
	$(BENCHMARK_DIR)/mutex_owner.c             \
	$(BENCHMARK_DIR)/mutex_pi.c                \
	$(BENCHMARK_DIR)/mutex_recursive.c         \
	$(BENCHMARK_DIR)/mutex_recursive_simple.c  \
	$(BENCHMARK_DIR)/mutex_adaptive.c          \
	$(BENCHMARK_DIR)/rwlock.c                  \
	$(BENCHMARK_DIR)/throughput.c              \
	$(BENCHMARK_DIR)/uncontended.c             \
	$(BENCHMARK_DIR)/cond.c                    \
	$(BENCHMARK_DIR)/once.c                    \
	$(BENCHMARK_DIR)/benchmark.c

BENCHMARK_BINARIES = $(BENCHMARK_SOURCES:.c=)
TEST_BINARY        = $(TEST_DIR)/test
TEST_SAN_BINARY    = $(TEST_DIR)/test-san
TEST_TSAN_BINARY   = $(TEST_DIR)/test-tsan
TEST_DEBUG_BINARY  = $(TEST_DIR)/test-debug

# -fPIE -pie is what tsan wants on Linux. gcc's tsan cannot model a standalone
# atomic_thread_fence and reports the PI mutex fences as -Wtsan warnings; the
# fences order critical sections around the kernel handoff, so for
# gcc that single diagnostic is kept as a warning instead of an error. -Wall and
# -Werror stay intact for everything else, and clang gets no extra option.
TSAN_CFLAGS = -fsanitize=thread -fPIE -pie
ifneq (,$(findstring gcc,$(COMPILER)))
TSAN_CFLAGS += -Wno-error=tsan
endif

all: benchmarks

# Every binary is built from the source of the same name. afl.h, afl_thread.h and
# benchmark.h are prerequisites of all of them, so a change in the library, in
# the thread layer or in the harness rebuilds the whole directory.
benchmarks: $(BENCHMARK_BINARIES)

# Throughput uses pthread workers, a common start gate, and one timer around
# the whole run. It is separate from the per-operation latency suite.
# BENCH_ARGUMENTS: threads, iterations per thread, payload operations, odd rounds.
benchmarks/throughput: benchmarks/throughput.c afl.h
	$(COMPILER) $(TEST_CFLAGS) -pthread $< -o $@ $(LDLIBS)

bench-throughput: benchmarks/throughput
	./benchmarks/throughput $(BENCH_ARGUMENTS)

# Build the whole directory and run it: one command from a clean tree to a set
# of numbers. The runner pins itself, so this needs no taskset in front of it,
# and BENCH_ARGUMENTS is what passes --list, --filter= or --cpus= through:
#
#     make bench BENCH_ARGUMENTS=--list
#     make bench BENCH_ARGUMENTS=--filter=mutex_pi
bench: $(BENCHMARK_BINARIES)
	./$(BENCHMARK_DIR)/benchmark $(BENCH_ARGUMENTS)

$(BENCHMARK_DIR)/%: $(BENCHMARK_DIR)/%.c afl.h afl_thread.h $(BENCHMARK_DIR)/benchmark.h
	$(COMPILER) $(BENCH_CFLAGS) $< -o $@ $(LDLIBS)

$(TEST_BINARY): $(TEST_DIR)/test.c afl.h afl_thread.h
	$(COMPILER) $(TEST_CFLAGS) -DAFL_TEST_EXPECT_PTHREAD=0 $< -o $@ $(LDLIBS)

test: $(TEST_BINARY)

check: $(TEST_BINARY)
	./$(TEST_BINARY)

# The same suite under more pressure: more threads than cores and more
# iterations, which is what makes a rare race show up.
check-stress: $(TEST_BINARY)
	AFL_TEST_THREADS=32 AFL_TEST_ITERATIONS=50000 ./$(TEST_BINARY)

# The same suite with the address and undefined behaviour sanitizers enabled.
# Needs the sanitizer runtime of the compiler (clang's compiler-rt or gcc's
# libasan), which some distributions install separately.
check-san:
	$(COMPILER) $(TEST_CFLAGS) -DAFL_TEST_EXPECT_PTHREAD=0 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer $(TEST_DIR)/test.c -o $(TEST_SAN_BINARY) $(LDLIBS)
	./$(TEST_SAN_BINARY)

# The same suite with the thread sanitizer, which is what proves the lock free
# code of afl.h free of data races. It is exclusive with the address sanitizer,
# so it gets a build of its own. afl_thread.h detects the sanitizer and switches
# its thread pool back to pthread for this build, because ThreadSanitizer only
# tracks threads the libc creates; the rest of the layer, and every lock the
# suite exercises, is unchanged.
check-tsan:
	$(COMPILER) $(TEST_CFLAGS) -DAFL_TEST_EXPECT_PTHREAD=1 -O1 -g $(TSAN_CFLAGS) -fno-omit-frame-pointer $(TEST_DIR)/test.c -o $(TEST_TSAN_BINARY) $(LDLIBS)
	./$(TEST_TSAN_BINARY)

# The same suite with the misuse diagnostics of afl.h compiled in. This is the
# only build that covers the error reporting of the header: it adds the checks
# that capture stderr and assert on the exact messages. It is independent of the
# DEBUG knob above, which reaches the same result through $(TEST_BINARY).
check-debug:
	$(COMPILER) $(TEST_CFLAGS) -DAFL_TEST_EXPECT_PTHREAD=0 -g3 -ggdb -DAFL_DEBUG $(TEST_DIR)/test.c -o $(TEST_DEBUG_BINARY) $(LDLIBS)
	./$(TEST_DEBUG_BINARY)

clean:
	rm -f $(BENCHMARK_BINARIES) $(TEST_BINARY) $(TEST_SAN_BINARY) $(TEST_TSAN_BINARY) $(TEST_DEBUG_BINARY)

.PHONY: all benchmarks bench bench-throughput test check check-stress check-san check-tsan check-debug clean

