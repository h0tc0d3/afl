/*
 * Runs every benchmark binary of this directory one after the other, under the
 * title of its column pair. The run is pinned to a small set of CPUs the same
 * way `taskset -c 0-3` pins it, so that the numbers of two runs stay
 * comparable, and the pinning is a parameter instead of a hard coded mask.
 *
 *     ./benchmarks/benchmark                    # pinned to the CPUs 0-3
 *     AFL_BENCH_CPUS=0-7 ./benchmarks/benchmark # pinned to the CPUs 0-7
 *     ./benchmarks/benchmark --cpus=2,4         # pinned to the CPUs 2 and 4
 *     ./benchmarks/benchmark --list             # what would run, and its binary
 *     ./benchmarks/benchmark --filter=mutex_pi  # only the ones that match
 *
 * The number of threads is AFL_BENCH_THREADS, which the children inherit, and
 * it defaults to the number of CPUs in the pinned set, so `make bench` runs one
 * thread per performance core. The exit status is non zero when one of the
 * benchmarks failed, when a filter matched nothing, or when the CPU list is not
 * a CPU list.
 *
 * Linux only, like the header itself: the affinity mask is set with
 * sched_setaffinity() and the binaries are looked up relative to /proc/self/exe.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define BENCHMARK_CPUS_DEFAULT "0-3"
#define BENCHMARK_PATH_MAX     4096
#define BENCHMARK_FILTER_MAX   8

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
  {"Adaptive Mutex",         "mutex_adaptive"        },
  {"RWLock",                 "rwlock"                },
  {"Uncontended",            "uncontended"           },
  {"Cond",                   "cond"                  },
};

#define BENCHMARK_COUNT (sizeof(benchmarks) / sizeof(benchmarks[0]))

static void usage(const char *program)
{
    printf("usage: %s [--cpus=<list>] [--filter=<substring>]... [--list]\n\n", program);
    printf("  --cpus=<list>      CPUs to pin every benchmark to, a taskset style list\n");
    printf("                     such as 0-4 or 0-4,8 (default: %s, or AFL_BENCH_CPUS)\n", BENCHMARK_CPUS_DEFAULT);
    printf("  --filter=<substr>  run only the benchmarks whose title or binary name\n");
    printf("                     contains <substr>, case insensitive; may be given\n");
    printf("                     more than once, a benchmark matching any of them runs\n");
    printf("  --list             print the benchmarks the filters select, and exit\n");
    printf("  -h, --help         print this text and exit\n");
}

/* Case insensitive substring test, so that `--filter=PI` and `--filter=pi` are
   the same request. */
static bool contains(const char *haystack, const char *needle)
{
    size_t length = strlen(needle);

    if (length == 0)
        return true;

    for (; *haystack != '\0'; haystack++) {
        size_t i;

        for (i = 0; i < length; i++)
            if (tolower((unsigned char) haystack[i]) != tolower((unsigned char) needle[i]))
                break;

        if (i == length)
            return true;
    }

    return false;
}

/*
 * A benchmark runs when it matches one of the filters, or when there are none.
 * Both the title and the binary name are searched, so `--filter=Mutex PI` and
 * `--filter=mutex_pi` select the same benchmark, and `--filter=mutex_recursive`
 * selects both recursive ones without catching the plain one.
 */
static bool selected_benchmark(const benchmark_entry *benchmark, const char *const *filters, size_t filter_count)
{
    if (filter_count == 0)
        return true;

    for (size_t i = 0; i < filter_count; i++)
        if (contains(benchmark->title, filters[i]) || contains(benchmark->binary, filters[i]))
            return true;

    return false;
}

static void list_benchmarks(const char *const *filters, size_t filter_count, size_t selected)
{
    if (filter_count > 0) {
        printf("filters:");

        for (size_t i = 0; i < filter_count; i++)
            printf(" %s", filters[i]);

        printf("\n");
    }

    printf("%zu of %zu benchmarks, title then binary name:\n", selected, BENCHMARK_COUNT);

    for (size_t i = 0; i < BENCHMARK_COUNT; i++) {
        if (!selected_benchmark(&benchmarks[i], filters, filter_count))
            continue;

        printf("  %-24s %s\n", benchmarks[i].title, benchmarks[i].binary);
    }
}

/*
 * Turn a `taskset -c` style CPU list ("0-4", "0-4,8", "2") into a CPU set. CPUs
 * that the machine does not have are ignored, so a default that is larger than
 * the machine does not fail the run. A list that is not a CPU list is refused
 * and the reason is written to `reason`: the whole point of pinning is that two
 * runs are comparable, and a list that silently selected nothing would report
 * unpinned numbers under the heading of a pinned run.
 *
 * Returns the number of distinct CPUs that were added to the set, which is zero
 * when every number of a well formed list is beyond this machine, or -1 when the
 * list is malformed.
 */
static int parse_cpus(const char *list, cpu_set_t *cpus, char *reason, size_t reason_size)
{
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    const char *cursor = list;
    int parsed = 0;

    CPU_ZERO(cpus);

    if (count < 0)
        count = 0;

    if (*list == '\0') {
        snprintf(reason, reason_size, "the list is empty");
        return -1;
    }

    while (*cursor != '\0') {
        char *end;
        unsigned long first;
        unsigned long last;

        /* strtoul() skips white space and accepts a sign, neither of which is a
           CPU number. Rejecting the character here is what turns "-1" into a
           reported mistake instead of an enormous CPU id. */
        if (!isdigit((unsigned char) *cursor)) {
            snprintf(reason, reason_size, "expected a CPU number at \"%s\"", cursor);
            return -1;
        }

        errno = 0;
        first = strtoul(cursor, &end, 10);
        last = first;

        if (errno == ERANGE) {
            snprintf(reason, reason_size, "the CPU number at \"%s\" is too large", cursor);
            return -1;
        }

        if (*end == '-') {
            cursor = end + 1;

            if (!isdigit((unsigned char) *cursor)) {
                snprintf(reason, reason_size, "the range that starts at %lu has no end", first);
                return -1;
            }

            errno = 0;
            last = strtoul(cursor, &end, 10);

            if (errno == ERANGE) {
                snprintf(reason, reason_size, "the end of the range that starts at %lu is too large", first);
                return -1;
            }

            /* A reversed range selects nothing, and nothing at all is a different
               answer from an empty intersection with this machine: the first is a
               mistake in the list, the second is a machine that is smaller than
               the list expected. */
            if (last < first) {
                snprintf(reason, reason_size, "the range %lu-%lu is backwards", first, last);
                return -1;
            }
        }

        for (unsigned long cpu = first; cpu <= last && cpu < (unsigned long) count; cpu++) {
            if (CPU_ISSET((int) cpu, cpus))
                continue;

            CPU_SET((int) cpu, cpus);
            parsed++;
        }

        cursor = end;

        if (*cursor == ',') {
            cursor++;

            if (*cursor == '\0') {
                snprintf(reason, reason_size, "the list ends with a comma");
                return -1;
            }
        } else if (*cursor != '\0') {
            snprintf(reason, reason_size, "expected a comma or the end of the list at \"%s\"", cursor);
            return -1;
        }
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

    slash = strrchr(directory, '/');

    if (slash == NULL)
        return -1;

    *slash = '\0';

    return 0;
}

static int run_benchmark(
  const benchmark_entry *benchmark, const char *directory, const cpu_set_t *cpus, const char *cpu_list, int pin
)
{
    char path[BENCHMARK_PATH_MAX];
    char *arguments[2];
    pid_t child;
    int status;
    int length;

    length = snprintf(path, sizeof(path), "%s/%s", directory, benchmark->binary);

    if (length < 0 || (size_t) length >= sizeof(path)) {
        fprintf(stderr, "\n\tthe path of %s is longer than %d bytes\n", benchmark->binary, BENCHMARK_PATH_MAX);
        return -1;
    }

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

        /*
         * Pinning is not a nicety here: the numbers of two runs are comparable
         * only when both ran on the same CPUs. A failed pinning is reported and
         * the child gives up, so a run that measured something other than what
         * was asked for cannot pass as a success.
         */
        if (pin && sched_setaffinity(0, sizeof(*cpus), cpus) != 0) {
            fprintf(stderr, "\n\tcould not pin %s to \"%s\": %s\n", benchmark->binary, cpu_list, strerror(errno));
            _exit(EXIT_FAILURE);
        }

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
    char reason[BENCHMARK_PATH_MAX];
    const char *filters[BENCHMARK_FILTER_MAX];
    const char *list = getenv("AFL_BENCH_CPUS");
    size_t filter_count = 0;
    size_t selected = 0;
    cpu_set_t cpus;
    int pinned;
    int failures = 0;
    bool show_list;

    if (list == NULL || *list == '\0')
        list = BENCHMARK_CPUS_DEFAULT;

    show_list = false;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--cpus=", 7) == 0) {
            list = argv[i] + 7;
        } else if (strncmp(argv[i], "--filter=", 9) == 0) {
            const char *filter = argv[i] + 9;

            if (*filter == '\0') {
                fprintf(stderr, "--filter needs a non empty substring\n");
                return EXIT_FAILURE;
            }

            if (filter_count == BENCHMARK_FILTER_MAX) {
                fprintf(stderr, "at most %d filters\n", BENCHMARK_FILTER_MAX);
                return EXIT_FAILURE;
            }

            filters[filter_count++] = filter;
        } else if (strcmp(argv[i], "--list") == 0) {
            show_list = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "unknown option \"%s\"\n\n", argv[i]);
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    for (size_t i = 0; i < BENCHMARK_COUNT; i++)
        if (selected_benchmark(&benchmarks[i], filters, filter_count))
            selected++;

    if (show_list) {
        list_benchmarks(filters, filter_count, selected);

        return selected > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (selected == 0) {
        fprintf(stderr, "no benchmark matches");

        for (size_t i = 0; i < filter_count; i++)
            fprintf(stderr, "%s\"%s\"", i > 0 ? ", " : " ", filters[i]);

        fprintf(stderr, "\n\n");
        usage(argv[0]);

        return EXIT_FAILURE;
    }

    pinned = parse_cpus(list, &cpus, reason, sizeof(reason));

    if (pinned < 0) {
        fprintf(stderr, "could not parse the CPU list \"%s\": %s\n", list, reason);
        return EXIT_FAILURE;
    }

    if (pinned == 0)
        fprintf(stderr, "none of the CPUs of \"%s\" exists on this machine, running unpinned\n", list);

    if (executable_directory(directory, sizeof(directory)) != 0) {
        fprintf(stderr, "could not find the directory of this executable\n");
        return EXIT_FAILURE;
    }

    printf(
      "afl benchmarks: %zu of %zu binaries, pinned to \"%s\"\n", selected, BENCHMARK_COUNT, pinned > 0 ? list : "none"
    );

    for (size_t i = 0; i < BENCHMARK_COUNT; i++) {
        if (!selected_benchmark(&benchmarks[i], filters, filter_count))
            continue;

        if (run_benchmark(&benchmarks[i], directory, &cpus, list, pinned > 0) != 0)
            failures++;
    }

    if (failures)
        fprintf(stderr, "\n%d of %zu benchmarks failed\n", failures, selected);

    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
