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

ifdef NDEBUG
CFLAGS += -g3 -ggdb -DAFL_DEBUG
endif

CFLAGS += -std=gnu17 -Wall -Werror -lm -fopenmp -DUSE_AFL -I.

ifdef RDTSCP
CFLAGS += -DUSE_RDTSCP
else
ifdef RDTSC
CFLAGS += -DUSE_RDTSC
else
CFLAGS += -DUSE_CLOCK_GETTIME
endif
endif

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
	$(BENCHMARK_DIR)/cond.c                    \
	$(BENCHMARK_DIR)/once.c                    \
	$(BENCHMARK_DIR)/benchmark.c

BENCHMARK_BINARIES = $(BENCHMARK_SOURCES:.c=)
TEST_BINARY        = $(TEST_DIR)/test

all: benchmarks

# Every binary is built from the source of the same name. afl.h and benchmark.h
# are prerequisites of all of them, so a change in the header or in the harness
# rebuilds the whole directory.
benchmarks: $(BENCHMARK_BINARIES)

$(BENCHMARK_DIR)/%: $(BENCHMARK_DIR)/%.c afl.h $(BENCHMARK_DIR)/benchmark.h
	$(COMPILER) $(CFLAGS) $< -o $@

$(TEST_BINARY): $(TEST_DIR)/test.c afl.h
	$(COMPILER) $(CFLAGS) -lpthread $< -o $@

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
	$(COMPILER) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer $(TEST_DIR)/test.c -o $(TEST_DIR)/test-san
	./$(TEST_DIR)/test-san

clean:
	rm -f $(BENCHMARK_BINARIES) $(TEST_BINARY) $(TEST_DIR)/test-san

.PHONY: all benchmarks test check check-stress check-san clean

