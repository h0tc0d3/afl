/*
 * Runs every benchmark binary of this directory one after the other, under the
 * title of its column pair. This is the job that the shell script of the
 * repository used to do, without the shell: the run is pinned to a small set of
 * CPUs the same way `taskset -c 0-4` pins it, so that the numbers of two runs
 * stay comparable, and the pinning can be changed instead of being hard coded.
 *
 *     ./benchmarks/benchmark                    # pinned to the CPUs 0-4
 *     AFL_BENCH_CPUS=0-7 ./benchmarks/benchmark # pinned to the CPUs 0-7
 *     ./benchmarks/benchmark --cpus=2,4         # pinned to the CPUs 2 and 4
 *
 * The number of threads is OMP_NUM_THREADS, which the children inherit, and the
 * exit status is non zero when one of the benchmarks failed.
 *
 * Linux only, like the header itself: the affinity mask is set with
 * sched_setaffinity() and the binaries are looked up relative to /proc/self/exe.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define BENCHMARK_CPUS_DEFAULT "0-4"
#define BENCHMARK_PATH_MAX 4096

typedef struct
{
    const char *title;
    const char *binary;
} benchmark_entry;

static const benchmark_entry benchmarks[] = {
  {"Spinlock",               "spinlock"              },
  {"Spinlock Owner",         "spinlock_owner"        },
  {"Mutex",                  "mutex"                 },
  {"Mutex Owner",            "mutex_owner"           },
  {"Mutex PI",               "mutex_pi"              },
  {"Mutex Recursive",        "mutex_recursive"       },
  {"Mutex Recursive Simple", "mutex_recursive_simple"},
  {"Cond",                   "cond"                  },
};

#define BENCHMARK_COUNT (sizeof(benchmarks) / sizeof(benchmarks[0]))

static void usage(const char *program)
{
    printf("usage: %s [--cpus=<list>]\n\n", program);
    printf("  --cpus=<list>  CPUs to pin every benchmark to, a taskset style list\n");
    printf("                 such as 0-4 or 0-4,8 (default: %s, or AFL_BENCH_CPUS)\n", BENCHMARK_CPUS_DEFAULT);
}

/*
 * Turn a `taskset -c` style CPU list ("0-4", "0-4,8", "2") into a CPU set. CPUs
 * that the machine does not have are ignored, so a default that is larger than
 * the machine does not fail the run. Returns the number of CPUs that were added
 * to the set, or -1 when the list is malformed.
 */
static int parse_cpus(const char *list, cpu_set_t *cpus)
{
    long count         = sysconf(_SC_NPROCESSORS_ONLN);
    const char *cursor = list;
    int parsed         = 0;

    CPU_ZERO(cpus);

    if (count < 0)
        count = 0;

    while (*cursor) {
        char *end;
        unsigned long first;
        unsigned long last;

        if (*cursor == ',') {
            cursor++;
            continue;
        }

        first = strtoul(cursor, &end, 10);
        last  = first;

        if (end == cursor)
            return -1;

        if (*end == '-') {
            cursor = end + 1;
            last   = strtoul(cursor, &end, 10);

            if (end == cursor)
                return -1;
        }

        cursor = end;

        for (unsigned long cpu = first; cpu <= last && cpu < (unsigned long) count; cpu++) {
            CPU_SET((int) cpu, cpus);
            parsed++;
        }

        if (*cursor != ',' && *cursor != '\0')
            return -1;
    }

    return parsed;
}

/* Directory of this executable, so that the binaries are found next to it. */
static int executable_directory(char *directory, size_t size)
{
    ssize_t length = readlink("/proc/self/exe", directory, size - 1);
    char *slash;

    if (length <= 0)
        return -1;

    directory[length] = '\0';

    slash             = strrchr(directory, '/');

    if (slash == NULL)
        return -1;

    *slash = '\0';

    return 0;
}

static int run_benchmark(const benchmark_entry *benchmark, const char *directory, const cpu_set_t *cpus, int pin)
{
    char path[BENCHMARK_PATH_MAX];
    char *arguments[2];
    pid_t child;
    int status;

    snprintf(path, sizeof(path), "%s/%s", directory, benchmark->binary);

    printf("\n\n\t   \033[0;34m\033[1m%s\033[0m", benchmark->title);
    fflush(stdout);

    child = fork();

    if (child < 0) {
        fprintf(stderr, "\n\tcould not fork for %s: %s\n", benchmark->binary, strerror(errno));
        return -1;
    }

    if (child == 0) {
        arguments[0] = path;
        arguments[1] = NULL;

        if (pin)
            sched_setaffinity(0, sizeof(*cpus), cpus);

        execv(path, arguments);

        fprintf(stderr, "\n\tcould not run %s: %s\n", path, strerror(errno));
        _exit(EXIT_FAILURE);
    }

    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "\n\tcould not wait for %s: %s\n", benchmark->binary, strerror(errno));
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "\n\t%s did not run to completion\n", benchmark->binary);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    char directory[BENCHMARK_PATH_MAX];
    const char *list = getenv("AFL_BENCH_CPUS");
    cpu_set_t cpus;
    int pinned;
    int failures = 0;

    if (list == NULL || *list == '\0')
        list = BENCHMARK_CPUS_DEFAULT;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--cpus=", 7) == 0) {
            list = argv[i] + 7;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    pinned = parse_cpus(list, &cpus);

    if (pinned < 0) {
        fprintf(stderr, "could not parse the CPU list \"%s\"\n", list);
        return EXIT_FAILURE;
    }

    if (pinned == 0)
        fprintf(stderr, "none of the CPUs of \"%s\" exists on this machine, running unpinned\n", list);

    if (executable_directory(directory, sizeof(directory)) != 0) {
        fprintf(stderr, "could not find the directory of this executable\n");
        return EXIT_FAILURE;
    }

    printf("afl benchmarks: %zu binaries, pinned to \"%s\"\n", BENCHMARK_COUNT, pinned > 0 ? list : "none");

    for (size_t i = 0; i < BENCHMARK_COUNT; i++) {
        if (run_benchmark(&benchmarks[i], directory, &cpus, pinned > 0) != 0)
            failures++;
    }

    if (failures)
        fprintf(stderr, "\n%d of %zu benchmarks failed\n", failures, BENCHMARK_COUNT);

    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
