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

CFLAGS += -std=gnu17 -Wall -Werror -lm -fopenmp -DUSE_AFL

ifdef RDTSCP
CFLAGS += -DUSE_RDTSCP
else
ifdef RDTSC
CFLAGS += -DUSE_RDTSC
else
CFLAGS += -DUSE_CLOCK_GETTIME
endif
endif

all: spinlock mutex mutex_recursive once

spinlock: spinlock_clean spinlock.c spinlock_owner.c
	$(COMPILER) $(CFLAGS) spinlock.c -o spinlock
	$(COMPILER) $(CFLAGS) spinlock_owner.c -o spinlock_owner

spinlock_clean:
	rm -f spinlock spinlock_owner

mutex: mutex_clean mutex.c mutex_owner.c mutex_pi.c
	$(COMPILER) $(CFLAGS) mutex.c -o mutex
	$(COMPILER) $(CFLAGS) mutex_owner.c -o mutex_owner
	$(COMPILER) $(CFLAGS) mutex_pi.c -o mutex_pi

mutex_clean:
	rm -f mutex mutex_owner mutex_pi

mutex_recursive: mutex_recursive_clean mutex_recursive.c mutex_recursive_simple.c
	$(COMPILER) $(CFLAGS) mutex_recursive.c -o mutex_recursive
	$(COMPILER) $(CFLAGS) mutex_recursive_simple.c -o mutex_recursive_simple

mutex_recursive_clean:
	rm -f mutex_recursive mutex_recursive_simple

once: once_clean once.c
	$(COMPILER) $(CFLAGS) once.c -o once

once_clean:
	rm -f once

test: test_clean test.c
	$(COMPILER) $(CFLAGS) test.c -o test

test_clean:
	rm -f test

clean: spinlock_clean mutex_clean mutex_recursive_clean once_clean

