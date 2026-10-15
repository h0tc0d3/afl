#ifndef __AFL_H
#define __AFL_H

#include <errno.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <elf.h>
#include <fcntl.h>

/*
 * afl.h provides process-private locks and synchronization for Linux.
 *
 * Plain locks use free/held states; owner-tracking locks store a thread ID.
 * Blocking mutex paths announce waiters before entering FUTEX_WAIT so that
 * release can wake them. PI mutexes use the kernel's PI futex protocol.
 * Spinlocks retry without futex parking. Reader/writer locks, condition
 * variables and once-only initialization have separate state protocols below.
 *
 * Lock types require 64-byte alignment. Preserve it in allocated storage and
 * wrap aligned scalar types in structs when an array is needed.
 */

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * __afl_likely and __afl_unlikely guide branch prediction and code layout.
 * They do not change the condition or provide synchronization.
 */
#define __afl_unlikely(condition) __builtin_expect((condition), 0)
#define __afl_likely(condition)   __builtin_expect((condition), 1)

/*
 * AFL_DEBUG reports API misuse and failed syscalls on file descriptor 2.
 * Reports use raw writes and require no stdio locks. A message spans several
 * writes, so concurrent reports can interleave.
 */
#ifdef AFL_DEBUG
#define __afl_debug(condition, text)  \
    if (__afl_unlikely(condition)) {  \
        __afl_write_str("[ERROR] ("); \
        __afl_write_str(__FILE__);    \
        __afl_write_str(":");         \
        __afl_write_dec(__LINE__);    \
        __afl_write_str(") ");        \
        __afl_write_str(text);        \
        __afl_write_str("\n");        \
    }

#define __afl_syscall_check_errors(ret)                \
    if (__afl_unlikely((ret) < 0 && (ret) >= -4095)) { \
        __afl_write_str("[ERROR] (");                  \
        __afl_write_str(__FILE__);                     \
        __afl_write_str(":");                          \
        __afl_write_dec(__LINE__);                     \
        __afl_write_str(") syscall error: ");          \
        __afl_write_dec((long) (ret));                 \
        __afl_write_str("\n");                         \
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
#define __afl_pause __afl_yield()
#endif

/* AFL_TID_MASK mask of the owner-ID bits in a futex word. */
#define AFL_TID_MASK 0x3FFFFFFF

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
 * Direct system calls: every operation the header performs in the kernel, the
 * futex waits and wakes of the slow paths included, is issued without the libc
 * wrapper, which saves a few cycles per call and keeps the header independent of
 * the C library. The libc syscall() fallback is gone: __afl_syscall_raw is
 * per-architecture assembly, the supported set is the x86-64, i386 and aarch64
 * the thread pointer block above already compiles for, and any other
 * architecture fails to build with the #error at the end of this block.
 * __afl_syscall wraps the raw call with the debug diagnostics of AFL_DEBUG.
 */
#if defined(__x86_64__) || defined(__amd64__)
/*
 * __afl_syscall_raw issues the system call number with the four arguments and
 * returns the raw result, a failure encoded as a negative errno, without
 * reporting it. The debug writer __afl_write_stderr below calls this variant: a
 * failed report must not run __afl_syscall_check_errors and try to report its
 * own failure. Every other caller uses the __afl_syscall wrapper after the
 * block, the same call on each supported architecture with the diagnostics
 * attached.
 */
static inline long __afl_syscall_raw(long number, long p1, long p2, long p3, long p4)
{
    long ret;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    register long r10 __asm__("r10") = p4;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"(p1), "S"(p2), "d"(p3), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
}
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
static inline long __afl_syscall_raw(long number, long p1, long p2, long p3, long p4)
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
    return ret;
}
#elif defined(__aarch64__)
static inline long __afl_syscall_raw(long number, long p1, long p2, long p3, long p4)
{
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = p1;
    register long x1 __asm__("x1") = p2;
    register long x2 __asm__("x2") = p3;
    register long x3 __asm__("x3") = p4;
    register long x4 __asm__("x4") = 0;
    register long x5 __asm__("x5") = 0;
    asm volatile("svc 0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "cc", "memory");
    return x0;
}
#else
#error "afl.h requires direct syscall support for this architecture"
#endif

#ifdef AFL_DEBUG
/*
 * The stderr writers of the debug macros above. A report goes to file descriptor
 * 2, the descriptor the stderr stream writes to, through the raw write system
 * call, so the diagnostics add no C library dependency to the header. They call
 * __afl_syscall_raw on purpose: a failed report must not run
 * __afl_syscall_check_errors and try to report its own failure.
 */

/*
 * __afl_write_stderr writes len bytes at s to file descriptor 2 with the raw
 * write system call, looping over short writes. A negative -EINTR result is
 * retried; a zero or otherwise negative result gives up on the rest of the
 * message, so a report on a descriptor nobody will accept stays silent instead
 * of spinning forever. A failure that is not -EINTR never reaches
 * __afl_syscall_check_errors because this call goes through __afl_syscall_raw.
 */
static inline void __afl_write_stderr(const char *s, size_t len)
{
    while (len != 0) {
        long written = __afl_syscall_raw(__NR_write, (long) STDERR_FILENO, (long) (uintptr_t) s, (long) len, 0);

        if (__afl_likely(written > 0)) {
            s += written;
            len -= (size_t) written;
        } else if (written != -EINTR) {
            return;
        }
    }
}

/*
 * __afl_write_str writes the NUL-terminated s to stderr, counting its length
 * with an own walk so that even the message segments need no C library string.h.
 */
static inline void __afl_write_str(const char *s)
{
    size_t len = 0;

    while (s[len] != '\0')
        len++;

    __afl_write_stderr(s, len);
}

/*
 * __afl_write_dec writes value as a signed base-10 decimal, the same bytes a
 * printf of %ld or %d would produce for it. The magnitude comes from unsigned
 * arithmetic, so even the most negative long is representable on the way to its
 * digits; the sign character goes in front after the digits are laid out from
 * right to left in a buffer sized for the longest decimal of the type. On the
 * supported 32 and 64 bit architectures the int of __LINE__ and the long of a
 * system call result both fit the buffer: 19 digits is the worst case of a
 * 64-bit long, and the sign needs one more of the 21 bytes.
 */
static inline void __afl_write_dec(long value)
{
    char digits[21];
    unsigned long magnitude = value < 0 ? 0UL - (unsigned long) value : (unsigned long) value;
    size_t first = sizeof(digits);

    do {
        first--;
        digits[first] = (char) ('0' + (int) (magnitude % 10UL));
        magnitude /= 10UL;
    } while (magnitude != 0UL);

    if (value < 0) {
        first--;
        digits[first] = '-';
    }

    __afl_write_stderr(&digits[first], sizeof(digits) - first);
}
#endif

/*
 * __afl_syscall is the __afl_syscall_raw of the calling architecture with the
 * misuse diagnostics of AFL_DEBUG attached: a result that carries a kernel
 * errno is reported on stderr when the debug build is compiled in, and the raw
 * result is returned unchanged either way, so the caller keeps its own error
 * handling.
 */
static inline long __afl_syscall(long number, long p1, long p2, long p3, long p4)
{
    long ret = __afl_syscall_raw(number, p1, p2, p3, p4);

    __afl_syscall_check_errors(ret);

    return ret;
}

/*
 * __afl_yield gives the processor up for the remainder of the scheduler's quantum
 * through the raw sched_yield system call. The return is ignored: it can only
 * fail with ENOSYS or EINTR, and neither leaves a spin loop anything to act on.
 * The bounded attempts of the mutexes end in a futex park either way, and a
 * debug build reports a failing return through __afl_syscall before the value
 * is discarded.
 */
static inline void __afl_yield(void)
{
    __afl_syscall(__NR_sched_yield, 0, 0, 0, 0);
}

/*
 * __AFL_COLD_INLINE keeps rare paths out of Clang's hot callers. GCC uses the
 * cold hint alone because it diagnoses noinline on a static inline function.
 */
#if defined(__clang__)
#define __AFL_COLD_INLINE static inline __attribute__((cold, noinline))
#else
#define __AFL_COLD_INLINE static inline __attribute__((cold))
#endif

/* __afl_gettid_slow fills this thread's cache only after a successful lookup. */
__AFL_COLD_INLINE uint32_t __afl_gettid_slow(uint32_t *cached)
{
    long ret;

    /*
     * Do not cache a failed lookup or use zero, which denotes a free lock.
     * Return a reserved nonzero owner value and leave the cache empty so the
     * next call retries the lookup.
     */
    ret = __afl_syscall(__NR_gettid, 0, 0, 0, 0);

    if (__afl_unlikely(ret <= 0))
        return AFL_TID_MASK;

    *cached = (uint32_t) (ret & AFL_TID_MASK);

    return *cached;
}

/*
 * __afl_gettid caches the thread id in thread local storage, so that a lock pays
 * for the system call once per thread instead of once per acquisition.
 */
static inline uint32_t __afl_gettid(void)
{
    static __thread uint32_t tid = 0;

    if (__afl_likely(tid))
        return tid;

    return __afl_gettid_slow(&tid);
}

/*
 * vDSO clock_gettime
 *
 * afl_clock_gettime is the header's own time read: the kernel maps a small
 * shared object, the vDSO, into every process and exports __vdso_clock_gettime
 * there, the same clock read without entering the kernel on the common path.
 * The entry point is resolved once per thread from the auxiliary vector
 * (AT_SYSINFO_EHDR), which is located by reading /proc/self/auxv through the
 * raw syscalls of this header rather than through the libc getauxval, and both
 * the resolved pointer and a "resolution was attempted" flag live in
 * thread-local storage, so the second read in a thread repeats neither the
 * search nor a failed search. The two variables are thread-private and written
 * only by their owning thread, so the cache needs no lock, no atomic and no
 * memory ordering.
 *
 * Resolution walks the ELF header the vector points at, its PT_DYNAMIC program
 * header, and the DT_SYMTAB/DT_STRTAB pair referenced through DT_GNU_HASH, or,
 * when the object carries only DT_HASH, a bounded scan of the symbol table
 * whose entry count DT_HASH gives. The current kernel builds every vDSO with a
 * link base of zero and maps it at the reported address, so the addresses the
 * tables hold are still relative and get the base added back; anything that
 * does not land inside the image after that addition is refused and answers
 * with the raw system call instead. A thread that cannot resolve the symbol
 * (no auxv, no vDSO, an object without the entry) does not retry per call: the
 * flag remembers the attempt and every later read goes straight to the raw
 * clock_gettime system call issued with this header's own syscall wrapper.
 *
 * Both the vDSO entry and the system call report failures in the kernel's
 * -errno style, so afl_clock_gettime translates them to the positive errno
 * values the rest of the header returns: 0 on success, a positive error number
 * otherwise, and every caller only has to look at whether the return is zero.
 * On i386 with a 32-bit time_t the vDSO entry is __vdso_clock_gettime64, which
 * writes two 64-bit fields; the read goes through a local copy that is
 * narrowed into the caller's struct after a range check, which returns
 * EOVERFLOW instead of truncating silently past 2038. With _TIME_BITS=64 the
 * caller's struct already has 64-bit seconds and the entry is called directly,
 * and on every other architecture __vdso_clock_gettime itself matches it.
 */

#if defined(__i386__) && defined(_TIME_BITS) && _TIME_BITS == 64 && defined(__NR_clock_gettime64)
#define __AFL_VDSO_CLOCK_NAME  "__vdso_clock_gettime64"
#define __AFL_NR_CLOCK_GETTIME __NR_clock_gettime64
#elif defined(__i386__)
#define __AFL_VDSO_CLOCK_NAME  "__vdso_clock_gettime64"
#define __AFL_NR_CLOCK_GETTIME __NR_clock_gettime
#define __AFL_CLOCK_SHIM64     1
#else
#define __AFL_VDSO_CLOCK_NAME  "__vdso_clock_gettime"
#define __AFL_NR_CLOCK_GETTIME __NR_clock_gettime
#endif

/* Upper bound on the symbol tables' span inside the image, in bytes. */
#define __AFL_VDSO_IMAGE_SPAN (1u << 20)

/* Upper bounds that refuse a table header that cannot describe a vDSO. */
#define __AFL_VDSO_MAX_SYMBOLS 4096
#define __AFL_VDSO_MAX_DYNAMIC 512
#define __AFL_VDSO_MAX_PHDRS   64

/*
 * The ELF types of this target, spelled without the libc ElfW macro, which
 * lives in <link.h>: __afl_elf(Ehdr) expands to Elf64_Ehdr on a 64-bit build
 * and to Elf32_Ehdr on a 32-bit one. <elf.h> defines both families on glibc
 * regardless of the target, and the class follows the pointer size, which is
 * what the kernel matches the vDSO to.
 */
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8
#define __AFL_ELF_CLASS 64
#else
#define __AFL_ELF_CLASS 32
#endif
#define __AFL_ELF_PASTE(a, b)  a##b
#define __AFL_ELF_EXPAND(a, b) __AFL_ELF_PASTE(a, b)
#define __afl_elf(type)        __AFL_ELF_EXPAND(__AFL_ELF_EXPAND(Elf, __AFL_ELF_CLASS), _##type)

typedef int (*__afl_clock_gettime_fn)(clockid_t clk_id, struct timespec *tp);

#ifdef __AFL_CLOCK_SHIM64
struct __afl_timespec64
{
    long long tv_sec;
    long long tv_nsec;
};

typedef int (*__afl_clock_gettime64_fn)(clockid_t clk_id, struct __afl_timespec64 *tp);
#endif

/*
 * __afl_elf_hash_gnu computes the hash the GNU symbol table of an ELF object
 * indexes with: the djb2 variant over the name bytes.
 */
static inline uint32_t __afl_elf_hash_gnu(const char *name)
{
    const unsigned char *bytes = (const unsigned char *) name;
    uint32_t hash = 5381;

    while (*bytes != '\0')
        hash = hash * 33 + (uint32_t) *bytes++;

    return hash;
}

/*
 * __afl_str_equal compares two NUL-terminated names without the C library:
 * nonzero when they are the same string, zero otherwise.
 */
static inline int __afl_str_equal(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }

    return *a == *b;
}

/*
 * __afl_vdso_auxv returns the base of the mapped vDSO, read as the
 * AT_SYSINFO_EHDR entry of /proc/self/auxv through raw syscalls, or zero when
 * the vector cannot be read or carries no such entry. The buffer covers the
 * real vector by a wide margin, and parsing stops at the AT_NULL terminator.
 */
static inline uintptr_t __afl_vdso_auxv(void)
{
    unsigned long auxv[256];
    long fd;
    long got = 0;
    long i;

    fd = __afl_syscall(__NR_openat, (long) AT_FDCWD, (long) (uintptr_t) "/proc/self/auxv", (long) O_RDONLY, 0);

    if (fd < 0)
        return 0;

    while (got < (long) sizeof(auxv)) {
        long n = __afl_syscall(
          __NR_read, fd, (long) (uintptr_t) ((unsigned char *) auxv + got),
          (long) ((size_t) sizeof(auxv) - (size_t) got), 0
        );

        if (n <= 0)
            break;

        got += n;
    }

    __afl_syscall(__NR_close, fd, 0, 0, 0);

    for (i = 0; i + 1 < got / (long) sizeof(unsigned long); i += 2) {
        if (auxv[i] == (unsigned long) AT_NULL)
            break;

        if (auxv[i] == (unsigned long) AT_SYSINFO_EHDR)
            return (uintptr_t) auxv[i + 1];
    }

    return 0;
}

/*
 * __afl_vdso_within returns nonzero when addr lies inside the image starting
 * at base and zero otherwise: the guard the table walks use to refuse an
 * address that cannot belong to the vDSO.
 */
static inline int __afl_vdso_within(uintptr_t addr, uintptr_t base)
{
    return addr >= base && addr - base <= (uintptr_t) __AFL_VDSO_IMAGE_SPAN;
}

/*
 * __afl_vdso_symbol finds the runtime address of one named symbol in the vDSO
 * image whose ELF header sits at base, or NULL when the image, its tables or
 * the entry are not there. Every table address is made absolute by adding the
 * base and must then land inside the image, which refuses an object linked
 * for another base instead of following a wild pointer; every count is capped
 * so a corrupt header bounds the walk rather than extending it. The lookup
 * prefers the GNU hash table the kernel's vDSO carries and falls back to a
 * bounded scan of DT_HASH's symbol count.
 */
static inline void *__afl_vdso_symbol(uintptr_t base, const char *name)
{
    const __afl_elf(Ehdr) *header = (const __afl_elf(Ehdr) *) base;
    const __afl_elf(Phdr) * program;
    const __afl_elf(Dyn) *dynamic = NULL;
    const __afl_elf(Sym) * symbols;
    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    uintptr_t gnu_hash = 0;
    uintptr_t sysv_hash = 0;
    uint32_t max_symbols;
    uint16_t i;

    if (
      header->e_ident[0] != ELFMAG0 || header->e_ident[1] != ELFMAG1 || header->e_ident[2] != ELFMAG2
      || header->e_ident[3] != ELFMAG3
    )
        return NULL;

    if (__afl_vdso_within(base + (uintptr_t) header->e_phoff, base) == 0 || header->e_phnum > __AFL_VDSO_MAX_PHDRS)
        return NULL;

    program = (const __afl_elf(Phdr) *) (base + (uintptr_t) header->e_phoff);

    for (i = 0; i < header->e_phnum; i++) {
        if (program[i].p_type == PT_DYNAMIC) {
            dynamic = (const __afl_elf(Dyn) *) (base + (uintptr_t) program[i].p_vaddr);
            break;
        }
    }

    if (dynamic == NULL || __afl_vdso_within((uintptr_t) dynamic, base) == 0)
        return NULL;

    for (i = 0; i < __AFL_VDSO_MAX_DYNAMIC; i++) {
        if (dynamic[i].d_tag == DT_NULL)
            break;

        if (dynamic[i].d_tag == DT_SYMTAB)
            symtab = (uintptr_t) dynamic[i].d_un.d_ptr;
        else if (dynamic[i].d_tag == DT_STRTAB)
            strtab = (uintptr_t) dynamic[i].d_un.d_ptr;
        else if (dynamic[i].d_tag == DT_GNU_HASH)
            gnu_hash = (uintptr_t) dynamic[i].d_un.d_ptr;
        else if (dynamic[i].d_tag == DT_HASH)
            sysv_hash = (uintptr_t) dynamic[i].d_un.d_ptr;
    }

    if (symtab == 0 || strtab == 0 || strtab <= symtab)
        return NULL;

    symtab += base;
    strtab += base;

    if (__afl_vdso_within(symtab, base) == 0 || __afl_vdso_within(strtab, base) == 0)
        return NULL;

    symbols = (const __afl_elf(Sym) *) symtab;

    /* The string table follows the symbol table in the image, which bounds
       the entries a corrupt table header could otherwise point past. */
    max_symbols = (uint32_t) ((strtab - symtab) / sizeof(__afl_elf(Sym)));

    if (gnu_hash != 0 && __afl_vdso_within(base + gnu_hash, base) != 0) {
        const __afl_elf(Word) *gnu = (const __afl_elf(Word) *) (base + gnu_hash);
        const __afl_elf(Word) * buckets;
        const __afl_elf(Word) * chain;
        uint32_t hash = __afl_elf_hash_gnu(name);
        uint32_t nbuckets = gnu[0];
        uint32_t first = gnu[1];
        uint32_t idx;
        uint32_t step;

        if (
          nbuckets == 0 || nbuckets > __AFL_VDSO_MAX_SYMBOLS
          || gnu[2] > __AFL_VDSO_IMAGE_SPAN / (uint32_t) sizeof(__afl_elf(Addr))
        )
            return NULL;

        /* GNU hash layout: four header words, bloom_size Addr words, then the
           buckets and the chain. The bloom is an optimization and is skipped. */
        buckets = (const __afl_elf(Word) *) ((const __afl_elf(Addr) *) (gnu + 4) + gnu[2]);
        chain = buckets + nbuckets;
        idx = buckets[hash % nbuckets];

        if (idx < first || idx >= max_symbols)
            return NULL;

        for (step = 0; step < __AFL_VDSO_MAX_SYMBOLS && idx < max_symbols; step++, idx++) {
            const __afl_elf(Sym) *sym = &symbols[idx];
            uint32_t word = chain[idx - first];

            /* The chain stores the symbol hash with bit 0 cleared, except
               for the last entry of the bucket, which carries it set. An
               entry whose hash matches is then compared by name. */
            if (
              (word & ~1u) == (hash & ~1u) && sym->st_value != 0
              && __afl_vdso_within(strtab + (uintptr_t) sym->st_name, base) != 0
              && __afl_str_equal((const char *) (uintptr_t) (strtab + (uintptr_t) sym->st_name), name)
            )
                return (void *) (base + (uintptr_t) sym->st_value);

            if (word & 1u)
                break;
        }

        return NULL;
    }

    if (sysv_hash != 0 && __afl_vdso_within(base + sysv_hash, base) != 0) {
        const __afl_elf(Word) *hash_table = (const __afl_elf(Word) *) (base + sysv_hash);
        uint32_t nchain = hash_table[1];
        uint32_t i2;

        if (nchain == 0 || nchain > max_symbols)
            return NULL;

        for (i2 = 0; i2 < nchain; i2++) {
            if (
              symbols[i2].st_value != 0 && __afl_vdso_within(strtab + (uintptr_t) symbols[i2].st_name, base) != 0
              && __afl_str_equal((const char *) (uintptr_t) (strtab + (uintptr_t) symbols[i2].st_name), name)
            )
                return (void *) (base + (uintptr_t) symbols[i2].st_value);
        }
    }

    return NULL;
}

/*
 * __afl_clock_gettime_syscall reads one clock through the raw system call and
 * answers with the afl_clock_gettime convention: 0, or a positive errno. The
 * kernel can only return 0 or -errno for clock_gettime; anything else is
 * reported as EINVAL rather than passed through.
 */
static inline int __afl_clock_gettime_syscall(clockid_t clk_id, struct timespec *tp)
{
    long ret = __afl_syscall(__AFL_NR_CLOCK_GETTIME, (long) clk_id, (long) (uintptr_t) tp, 0, 0);

    if (ret == 0)
        return 0;

    if (ret < 0 && ret >= -4095)
        return (int) (-ret);

    return EINVAL;
}

/*
 * afl_clock_gettime reads clk_id into tp without the libc wrapper: 0 on
 * success, a positive errno otherwise. The vDSO entry resolved once per thread
 * serves the read when it is there, and a thread that has no vDSO, or none
 * with this entry, falls back to the raw system call; see the section comment
 * above for the resolution and the i386 64-bit timespec shim.
 */
static inline int afl_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
#ifdef __AFL_CLOCK_SHIM64
    static __thread __afl_clock_gettime64_fn entry = NULL;
#else
    static __thread __afl_clock_gettime_fn entry = NULL;
#endif
    static __thread int resolved = 0;

    if (__afl_unlikely(resolved == 0)) {
        uintptr_t base = __afl_vdso_auxv();

        resolved = 1;

        if (base != 0)
            entry = (typeof(entry)) __afl_vdso_symbol(base, __AFL_VDSO_CLOCK_NAME);
    }

    if (__afl_likely(entry != NULL)) {
#ifdef __AFL_CLOCK_SHIM64
        struct __afl_timespec64 ts64;
        int ret = entry(clk_id, &ts64);

        if (__afl_unlikely(ret != 0)) {
            if (ret < 0 && ret >= -4095)
                return (int) (-ret);

            return EINVAL;
        }

        if (ts64.tv_sec > (long long) INT32_MAX || ts64.tv_sec < (long long) INT32_MIN)
            return EOVERFLOW;

        tp->tv_sec = (time_t) ts64.tv_sec;
        tp->tv_nsec = (long) ts64.tv_nsec;
        return 0;
#else
        int ret = entry(clk_id, tp);

        if (__afl_likely(ret == 0))
            return 0;

        if (__afl_unlikely(ret < 0 && ret >= -4095))
            return (int) (-ret);

        return EINVAL;
#endif
    }

    return __afl_clock_gettime_syscall(clk_id, tp);
}

/*
 * __afl_deadline_relative converts an absolute deadline to a relative timeout.
 * Return one if the deadline is at or behind now, with a one-nanosecond timeout
 * in relative. Callers use that result to report ETIMEDOUT before parking.
 * Future differences that exceed time_t are saturated without signed overflow.
 * The caller must obtain now from the same clock as the deadline.
 */
static inline int
  __afl_deadline_relative(const struct timespec *abstime, const struct timespec *now, struct timespec *relative)
{
    if (abstime->tv_sec < now->tv_sec || (abstime->tv_sec == now->tv_sec && abstime->tv_nsec <= now->tv_nsec)) {
        relative->tv_sec = 0;
        relative->tv_nsec = 1;
        return 1;
    }

    /* Extreme but valid deadlines must not overflow signed time_t. */
    if (__builtin_sub_overflow(abstime->tv_sec, now->tv_sec, &relative->tv_sec)) {
        relative->tv_sec = (time_t) (((uintmax_t) 1 << (sizeof(time_t) * 8 - 1)) - 1);
        relative->tv_nsec = 999999999L;
        return 0;
    }
    relative->tv_nsec = abstime->tv_nsec - now->tv_nsec;

    if (relative->tv_nsec < 0) {
        relative->tv_nsec += 1000000000L;
        relative->tv_sec--;
    }

    return 0;
}

enum __afl_state
{
    AFL_UNLOCKED = 0, // The lock is free
    AFL_LOCKED = 1    // The lock is taken, without an owner in the lock word
};

/* AFL_HAVE_WAITERS marks a waiter that has announced itself or queued. */
#define AFL_HAVE_WAITERS 0x80000000

#define __AFL_ALIGN __attribute__((aligned(64))) // Most processors have a cache line size of 64 bytes

/*
 * __AFL_INLINE specializes shared lock bodies at each call site. Constant
 * arguments remove unused recursion, clock and spin-budget branches.
 */
#define __AFL_INLINE static inline __attribute__((always_inline))

/*
 * AFL_SPIN_LIMIT bounds fixed-budget mutex and reader/writer retries before
 * futex parking. Adaptive mutexes use their own minimum and maximum budgets.
 * Each retry uses the backoff below; the limit counts attempts, not pauses.
 * Short holds can complete during this phase. A lower limit leaves more CPU
 * time for a descheduled holder. Zero disables the spin phase.
 * Spinlocks do not use this limit because they never park on a futex.
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

/* afl_spinlock_t is a 32-bit plain or owner-tracking spin word. */
typedef uint32_t afl_spinlock_t __AFL_ALIGN;

/*
 * afl_spin_init writes the free value into the spinlock with release
 * ordering and returns 0. The shared argument is accepted for shape
 * compatibility with pthread_spin_init and ignored: every lock in this
 * header parks through FUTEX_PRIVATE_FLAG, so a lock initialized here is
 * process private whatever the argument says.
 */
static inline int afl_spin_init(afl_spinlock_t *spinlock, int shared)
{
    (void) shared;
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/*
 * AFL_SPIN_BACKOFF caps the exponential pause gap between acquire attempts.
 * Each acquire starts at one pause and doubles up to this cap. The plain
 * spinlock also caps its gap at 16; owner spins and mutexes use the full cap.
 * PI and priority-ceiling mutexes use this backoff before kernel PI locking.
 */
#ifndef AFL_SPIN_BACKOFF
#define AFL_SPIN_BACKOFF 1024
#endif

/*
 * AFL_SPIN_PAUSE_BUDGET bounds accumulated pauses between scheduler yields.
 * The budget is checked after each gap, so a gap can overshoot it. Yielding
 * resets the pause counter without consuming an additional acquire attempt.
 * A yield failure does not change lock ownership or the retry/park protocol;
 * its return value is ignored.
 */
#ifndef AFL_SPIN_PAUSE_BUDGET
#define AFL_SPIN_PAUSE_BUDGET 1024
#endif

#if AFL_SPIN_BACKOFF < 1 || AFL_SPIN_BACKOFF > INT32_MAX
#error "AFL_SPIN_BACKOFF must be between 1 and INT32_MAX"
#endif
#if AFL_SPIN_PAUSE_BUDGET < 1 || AFL_SPIN_PAUSE_BUDGET > INT32_MAX
#error "AFL_SPIN_PAUSE_BUDGET must be between 1 and INT32_MAX"
#endif

typedef struct
{
    unsigned backoff; // PAUSE iterations of the next gap
    unsigned spent;   // PAUSE iterations since the last yield
} __afl_spin_backoff_t;

static inline void __afl_spin_backoff_init(__afl_spin_backoff_t *backoff)
{
    backoff->backoff = 1;
    backoff->spent = 0;
}

/*
 * __afl_spin_backoff_inline waits one gap, and once the acquire has spent AFL_SPIN_PAUSE_BUDGET
 * PAUSE iterations since its last yield, give the processor up with
 * __afl_yield() and restart the budget. The spinlocks and the spin phase of
 * the mutexes both use it; neither stops trying to win the lock, the mutexes
 * park when their AFL_SPIN_LIMIT attempts are over. Owner spin waits inline
 * this core; other callers keep the compiler's usual inlining decision through
 * __afl_spin_backoff.
 */
__AFL_INLINE void __afl_spin_backoff_inline(__afl_spin_backoff_t *backoff)
{
    unsigned pauses = backoff->backoff;

    if (pauses < 1)
        pauses = 1;

    backoff->spent += pauses;

    for (unsigned i = 0; i < pauses; i++)
        __afl_pause;

    if (pauses < AFL_SPIN_BACKOFF)
        backoff->backoff = pauses > AFL_SPIN_BACKOFF / 2 ? AFL_SPIN_BACKOFF : pauses * 2;

    if (backoff->spent >= AFL_SPIN_PAUSE_BUDGET) {
        __afl_yield();
        backoff->spent = 0;
    }
}

/* __afl_spin_backoff keeps ordinary inlining decisions at the other wait sites. */
static inline void __afl_spin_backoff(__afl_spin_backoff_t *backoff)
{
    __afl_spin_backoff_inline(backoff);
}

/*
 * __afl_spin_lock_slow keeps backoff setup out of an uncontended acquire.
 * Only compare exchange may claim the free word: an exchange could overwrite
 * a tid installed by an owner-tracking acquire between the load and claim.
 */
static inline __attribute__((cold)) int __afl_spin_lock_slow(afl_spinlock_t *spinlock)
{
    uint32_t lock;
    __afl_spin_backoff_t backoff;

    __afl_spin_backoff_init(&backoff);

    for (;;) {
        /*
         * Contended: test-and-test-and-set. Only issue the expensive atomic
         * compare exchange once the lock looks free. Spinning on a plain load
         * keeps the cache line shared until there is a chance to acquire.
         */
        lock = __atomic_load_n(spinlock, __ATOMIC_RELAXED);
        if (
          __afl_likely(lock == AFL_UNLOCKED)
          && __afl_likely(
            __atomic_compare_exchange_n(spinlock, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
          )
        )
            return 0;

        /* There is no park after spinning here. Keep probing often enough
         * to catch short holds instead of sleeping through many handoffs. */
        if (backoff.backoff > 16)
            backoff.backoff = 16;
        __afl_spin_backoff(&backoff);
    }
}

/*
 * afl_spin_lock takes the spinlock, spinning until it wins it: the
 * spinlocks of this header have no park path, so the call only returns 0,
 * with the lock held and the critical section's loads ordered after the
 * acquire. See afl_spin_owner_lock for the owner tracking variant and the
 * AFL_SPIN_BACKOFF comment for why the spin is spaced, not tight.
 */
static inline int afl_spin_lock(afl_spinlock_t *spinlock)
{
    uint32_t lock = AFL_UNLOCKED;

    if (__afl_likely(__atomic_compare_exchange_n(spinlock, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    return __afl_spin_lock_slow(spinlock);
}

/*
 * afl_spin_unlock releases the spinlock with a single release store and
 * returns 0. Releasing a lock this thread does not hold is unchecked
 * misuse, reported under AFL_DEBUG by the owner tracking variants; the
 * plain spinlock keeps no owner to check against.
 */
static inline int afl_spin_unlock(afl_spinlock_t *spinlock)
{
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/*
 * afl_spin_trylock attempts to take the spinlock without waiting: one compare
 * exchange from the free value, 0 on success and EBUSY when the word shows a
 * holder. A pinned expected value leaves the word unchanged on failure.
 */
static inline int afl_spin_trylock(afl_spinlock_t *spinlock)
{
    uint32_t lock = AFL_UNLOCKED;

    if (__afl_likely(__atomic_compare_exchange_n(spinlock, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    return EBUSY;
}

/*
 * __afl_spin_owner_lock_slow keeps the backoff loop and its register setup
 * out of an uncontended owner acquire. The caller has ruled out recursion.
 */
__AFL_COLD_INLINE int __afl_spin_owner_lock_slow(afl_spinlock_t *spinlock, uint32_t tid)
{
    uint32_t lock;
    __afl_spin_backoff_t backoff;

    __afl_spin_backoff_init(&backoff);

    for (;;) {
        /*
         * Contended: test-and-test-and-set, see afl_spin_lock: the test load
         * keeps the cache line shared while the lock is held by somebody else.
         *
         * There is no owner check in this loop. This thread cannot have written
         * its own tid (it has not acquired the lock), and no other live thread
         * carries the same tid, so the value read back here can never match; the
         * recursive case was already rejected by the caller after its failed
         * fast path observed the current owner.
         */
        lock = __atomic_load_n(spinlock, __ATOMIC_RELAXED);

        if (
          __afl_likely(
            lock == AFL_UNLOCKED
            && __atomic_compare_exchange_n(spinlock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
          )
        )
            return 0;

        __afl_spin_backoff_inline(&backoff);
    }
}

/*
 * afl_spin_owner_lock takes the owner tracking spinlock, recording the
 * calling thread in the low bits of the word, and returns 0. A recursive
 * acquisition is invalid use, not a deadlock to sit in: the call refuses
 * it with EDEADLOCK and leaves the lock held by the same owner. The spin
 * waits are spaced by the backoff, and this variant never parks.
 */
static inline int afl_spin_owner_lock(afl_spinlock_t *spinlock)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();

    /*
     * Fast path: one compare exchange from the free value, without a separate
     * test load. The expected value is pinned to the free value, never the value
     * that was just observed: the latter also matches a lock that is still owned
     * by another thread, the exchange then succeeds and hands out the same
     * spinlock twice. An uncontended acquire is a single atomic instruction, and
     * a failed attempt leaves the lock word unchanged.
     */
    if (__afl_likely(__atomic_compare_exchange_n(spinlock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    /* Only this thread may own it, a stale read or a recursive call. */
    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned spinlock.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    return __afl_spin_owner_lock_slow(spinlock, tid);
}

/*
 * afl_spin_owner_unlock releases the owner tracking spinlock and returns
 * 0. A release by a thread that does not own the lock is refused with
 * EPERM, the word untouched, so the real holder keeps its critical
 * section; AFL_DEBUG also reports the attempt.
 */
static inline int afl_spin_owner_unlock(afl_spinlock_t *spinlock)
{
    uint32_t lock = 0;
    uint32_t tid = __afl_gettid();

    __atomic_load(spinlock, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a spinlock from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);

    return 0;
}

/*
 * afl_spin_owner_trylock attempts to take the owner tracking spinlock without
 * waiting, the same pinned compare exchange as the fast path of
 * afl_spin_owner_lock and nothing else: 0 when the free word admits this
 * thread as the owner, EBUSY otherwise, and a failed attempt never writes, so
 * the lock word is unchanged. A hold by the calling thread itself reads as
 * held and is refused with EBUSY too, like every trylock and not with the
 * EDEADLOCK of afl_spin_owner_lock; the value the exchange reports back makes
 * that self acquisition visible to AFL_DEBUG as the misuse it is.
 */
static inline int afl_spin_owner_trylock(afl_spinlock_t *spinlock)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();

    if (__afl_likely(__atomic_compare_exchange_n(spinlock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned spinlock.");

    return EBUSY;
}

/*
 * afl_spin_destroy writes the free value back over the spinlock and
 * returns 0. Destroying a held lock is misuse: it drops the lock without
 * a release, so it is only sound when no thread can still observe the
 * word.
 */
static inline int afl_spin_destroy(afl_spinlock_t *spinlock)
{
    __atomic_store_n(spinlock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/* afl_mutex_t is the word used by plain, owner-tracking and PI mutexes. */
typedef uint32_t afl_mutex_t __AFL_ALIGN;

/* AFL_MUTEX_INIT initializes a free plain, owner-tracking or PI mutex word. */
#define AFL_MUTEX_INIT 0

/*
 * __afl_validate_abstime applies the abstime rules that need no clock, for
 * every timed entry point of this header: a NULL deadline, or a tv_nsec field
 * outside [0, 1000000000), is an invalid argument and is rejected before any
 * lock state is touched. The already-expired check is not here: it needs the
 * clock and would slow down the uncontended path, and pthread_mutex_timedlock
 * takes a free mutex even when abstime lies in the past.
 */
static inline int __afl_validate_abstime(const struct timespec *abstime)
{
    if (__afl_unlikely(abstime == NULL))
        return EINVAL;

    if (__afl_unlikely(abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000L))
        return EINVAL;

    return 0;
}

/*
 * __afl_mutex_lock_slow_core shares the spin, announce and park protocol used
 * by plain, owner-tracking and recursive mutexes, including timed acquires.
 *
 * want is the held value to install: AFL_LOCKED or the caller's thread ID.
 * tid enables the recursive-acquire check; AFL_UNLOCKED disables it. Recursive
 * mutex callers handle their own nesting before entering this helper.
 * observed is the value already read by the caller. It avoids a redundant
 * fast attempt when another owner is known to hold the word.
 *
 * Callers validate timed deadlines. timed is a call-site constant: zero with
 * a NULL abstime, or one with a CLOCK_REALTIME deadline. This lets untimed
 * paths omit clock checks. spin_limit can be zero for condition-wait relocking.
 * The uint32_t pointer also accepts lock members without assuming that the
 * member has the alignment attribute of the public scalar mutex type.
 *
 * Public callers inline the initial CAS; separate timed and untimed slow
 * entries keep clock checks and stack setup out of uncontended acquisition.
 */
__AFL_INLINE int __afl_mutex_lock_slow_core(
  uint32_t *mutex, uint32_t want, uint32_t tid, uint32_t observed, const struct timespec *abstime, int timed,
  int spin_limit
)
{
    struct timespec now, relative, *timeout = NULL;
    __afl_spin_backoff_t backoff;
    uint32_t lock = observed;
    long ret = 0;

    /*
     * One pointer carries the whole timed/untimed distinction into the futex
     * call below: NULL makes it wait forever. It is set from the constant
     * `timed` and not from abstime, see the comment above the function.
     */
    if (timed)
        timeout = &relative;

    /*
     * Recursion is reported before the clock is read: a self deadlock is
     * invalid use, not a timeout, and afl_mutex_owner_lock returns EDEADLOCK
     * for an acquire with a deadline far in the future too.
     */
    if (__afl_unlikely(tid != AFL_UNLOCKED && tid == (lock & AFL_TID_MASK))) {
        __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");
        return EDEADLOCK;
    }

    /*
     * Contended: compute the deadline once, before any spinning, and refuse
     * an acquire whose deadline is already at or behind now.
     */
    if (timed) {
        if (__afl_unlikely(afl_clock_gettime(CLOCK_REALTIME, &now) != 0))
            return EINVAL;

        if (__afl_deadline_relative(abstime, &now, &relative))
            return ETIMEDOUT;
    }

    /*
     * Spin for up to AFL_SPIN_LIMIT attempts, spaced by the backoff, the
     * critical section might be tiny. See the comment on AFL_SPIN_LIMIT for
     * why the attempts are not a tight loop.
     */
    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < spin_limit; spin++) {
        if (lock == AFL_UNLOCKED && __atomic_compare_exchange_n(mutex, &lock, want, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return 0;

        __afl_spin_backoff(&backoff);
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);

        /* Spin only while time remains, so the backoff stops at the deadline. */
        if (timed) {
            if (__afl_unlikely(afl_clock_gettime(CLOCK_REALTIME, &now) != 0))
                return EINVAL;

            if (__afl_deadline_relative(abstime, &now, &relative))
                return ETIMEDOUT;
        }
    }

    for (;;) {
        if (lock == AFL_UNLOCKED) {
            /*
             * Contended path: keep the waiters bit set. This thread has to
             * wake the next waiter when it releases the lock, otherwise a
             * wake up that is addressed to a single waiter would end the
             * chain, and an acquire that wins here after other threads parked
             * owes that wake up just as the holder does.
             */
            if (__atomic_compare_exchange_n(mutex, &lock, want | AFL_HAVE_WAITERS, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return 0;
            continue;
        }

        if (!(lock & AFL_HAVE_WAITERS)) {
            lock = __afl_futex_announce(mutex, lock);
            continue;
        }

        /*
         * Recompute the remaining timeout before every park: a spurious wake
         * up cannot stretch the deadline and no sleep passes abstime. A
         * deadline that ran out while spinning or parked is reported here,
         * a clock that does not answer with EINVAL, matching the rules
         * applied before the first attempt.
         */
        if (timed) {
            if (__afl_unlikely(afl_clock_gettime(CLOCK_REALTIME, &now) != 0))
                return EINVAL;

            if (__afl_deadline_relative(abstime, &now, &relative))
                return ETIMEDOUT;
        }

        ret = __afl_syscall(
          __NR_futex, (intptr_t) mutex, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, lock, (long) (intptr_t) timeout
        );

        if (__afl_unlikely(ret < 0 && ret != -EAGAIN && ret != -EINTR))
            return (int) -ret;
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }
}

/* Keep the fast path small. Separate timed and untimed entry points let the
 * shared body specialize away clock reads and deadline branches. */
static inline __attribute__((cold)) int
  __afl_mutex_lock_slow(uint32_t *mutex, uint32_t want, uint32_t tid, uint32_t observed)
{
    return __afl_mutex_lock_slow_core(mutex, want, tid, observed, NULL, 0, AFL_SPIN_LIMIT);
}

static inline __attribute__((cold)) int __afl_mutex_timedlock_slow(
  uint32_t *mutex, uint32_t want, uint32_t tid, uint32_t observed, const struct timespec *abstime
)
{
    return __afl_mutex_lock_slow_core(mutex, want, tid, observed, abstime, 1, AFL_SPIN_LIMIT);
}

__AFL_INLINE int __afl_mutex_lock_core(
  uint32_t *mutex, uint32_t want, uint32_t tid, uint32_t observed, const struct timespec *abstime, int timed
)
{
    if (
      __afl_likely(observed == AFL_UNLOCKED)
      && __afl_likely(__atomic_compare_exchange_n(mutex, &observed, want, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    )
        return 0;

    if (timed)
        return __afl_mutex_timedlock_slow(mutex, want, tid, observed, abstime);
    return __afl_mutex_lock_slow(mutex, want, tid, observed);
}

/*
 * afl_mutex_lock takes the mutex and returns 0, with the critical
 * section's loads ordered after the acquire. A contended acquire makes
 * the bounded number of attempts of AFL_SPIN_LIMIT, spaced by the
 * backoff, announces itself with the waiters bit and then parks on the
 * futex until afl_mutex_unlock wakes it, so the call cannot livelock
 * against a spinning winner. The word states are free, locked and locked
 * with waiters; see the section comment and AFL_SPIN_LIMIT for the
 * protocol the waiters bit implements. The plain mutex keeps no owner, so
 * the recursion check of the shared body is off and there is no deadline.
 */
static inline int afl_mutex_lock(afl_mutex_t *mutex)
{
    return __afl_mutex_lock_core(mutex, AFL_LOCKED, AFL_UNLOCKED, AFL_UNLOCKED, NULL, 0);
}

/*
 * afl_mutex_unlock releases the mutex and returns 0: one release
 * exchange, and one wake up only when the word it took still carried the
 * waiters bit. Releasing an unlocked mutex is unchecked misuse; as with
 * afl_mutex_lock the plain variant keeps no owner, so nobody else can be
 * blamed for it.
 */
static inline int afl_mutex_unlock(afl_mutex_t *mutex)
{
    uint32_t lock = __atomic_exchange_n(mutex, AFL_UNLOCKED, __ATOMIC_RELEASE);

    __afl_debug(lock == AFL_UNLOCKED, "An attempt was made to unlock an unlocked mutex.");

    if (__afl_unlikely(lock & AFL_HAVE_WAITERS))
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

/*
 * afl_mutex_trylock attempts to take the mutex without waiting: one compare
 * exchange from the free value, 0 on success and EBUSY when the word shows a
 * holder or a waiters bit. A word that still carries the waiters bit of a
 * hand-off in progress is refused too, like in afl_mutex_pc_trylock, because
 * the mutex is not free until that release completes; nothing is written, so
 * no wake up is lost and the caller may simply retry.
 */
static inline int afl_mutex_trylock(afl_mutex_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;

    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    return EBUSY;
}

/*
 * afl_mutex_owner_lock takes the owner tracking mutex, recording the
 * calling thread in the low bits of the word, and returns 0. A recursive
 * acquisition is refused with EDEADLOCK, the mutex untouched and still
 * held; the wait path is that of afl_mutex_lock, the same shared body with
 * the thread id as both the value written and the owner the recursion check
 * compares against. The recursive check can only fire on a failed compare
 * exchange, where the exchange leaves the current owner behind, so it costs
 * the uncontended path nothing. The recorded owner is what
 * afl_mutex_owner_unlock and afl_mutex_owner_trylock check against.
 */
static inline int afl_mutex_owner_lock(afl_mutex_t *mutex)
{
    uint32_t tid = __afl_gettid();

    return __afl_mutex_lock_core(mutex, tid, tid, AFL_UNLOCKED, NULL, 0);
}

/*
 * afl_mutex_owner_unlock releases the owner tracking mutex and returns 0.
 * A release by a thread that does not own it is refused with EPERM, the
 * mutex untouched; AFL_DEBUG reports the attempt. The release wakes one
 * waiter exactly when the word it took still carried the waiters bit,
 * the same exchange and wake protocol as afl_mutex_unlock.
 */
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

/*
 * afl_mutex_owner_trylock attempts to take the owner tracking mutex without
 * waiting, the single pinned compare exchange of the fast path of
 * afl_mutex_owner_lock and nothing else: 0 when the free word admits this
 * thread as the owner, EBUSY otherwise, and a failed attempt never writes, so
 * the lock word is unchanged. As with afl_spin_owner_trylock, a
 * re-acquisition by the owning thread is refused with EBUSY rather than the
 * EDEADLOCK of afl_mutex_owner_lock, and the reported value lets AFL_DEBUG
 * flag it.
 */
static inline int afl_mutex_owner_trylock(afl_mutex_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();

    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");

    return EBUSY;
}

/*
 * afl_mutex_pi_lock takes the priority inheriting mutex. The word is the futex
 * PI format the kernel expects (tid in the low bits, FUTEX_WAITERS set by the
 * kernel when it queues a waiter), so the same userspace fast path and spin
 * phase as the owner tracking mutex apply: a compare exchange from the free
 * value wins without any system call. The kernel only has to get involved
 * once the word shows a holder or the waiters bit, and the spin budget keeps
 * the tail bounded there too, exactly as in afl_mutex_lock.
 *
 * Interrupted waits and an exiting owner are retried. Other kernel errors
 * are returned as positive errno values: only a successful syscall grants
 * ownership. The acquire fence orders the critical section after that grant.
 */
static inline int afl_mutex_pi_lock(afl_mutex_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();
    __afl_spin_backoff_t backoff;

    /*
     * Fast path: one compare exchange from the free value, see afl_mutex_lock.
     * On failure the compare exchange leaves the observed value in lock.
     */
    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (lock == AFL_UNLOCKED && __atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return 0;

        __afl_spin_backoff(&backoff);
        lock = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }

    for (;;) {
        long ret = __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

        if (__afl_likely(ret == 0)) {
            __atomic_thread_fence(__ATOMIC_ACQUIRE);
            break;
        }
        if (ret != -EINTR && ret != -EAGAIN)
            return (int) -ret;
    }

    return 0;
}

/*
 * afl_mutex_pi_unlock releases the priority inheriting mutex and returns
 * 0. A release by a thread that does not own it is refused with EPERM,
 * the mutex untouched. The plain case is one release compare exchange
 * from the recorded tid to the free value; it fails precisely when the
 * kernel set the PI waiters bit on behalf of a queued waiter, and then
 * FUTEX_UNLOCK_PI hands the PI state over in the kernel instead.
 */
static inline int afl_mutex_pi_unlock(afl_mutex_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();

    __atomic_load(mutex, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    if (!__atomic_compare_exchange_n(mutex, &tid, AFL_UNLOCKED, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        __atomic_thread_fence(__ATOMIC_RELEASE);
        long ret = __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);
        if (__afl_unlikely(ret < 0))
            return (int) -ret;
    }

    return 0;
}

/*
 * afl_mutex_pi_trylock attempts to take the priority inheriting mutex without
 * waiting: the same single pinned compare exchange as the fast path of
 * afl_mutex_pi_lock, 0 on success and EBUSY when the word shows a holder, the
 * kernel's waiters bit, or this thread's own hold. A mutex the kernel has
 * never been introduced to stays a pure userspace hand-off, and a failed
 * attempt never writes, leaving the word and the kernel PI state untouched;
 * unlike afl_mutex_timedlock there is no FUTEX_LOCK_PI with a zero timeout;
 * the kernel is only involved by the blocking acquires.
 * Re-acquisition by the owner is refused with EBUSY, not EDEADLOCK, and the
 * reported value lets AFL_DEBUG flag it like the other owner tracking
 * variants.
 */
static inline int afl_mutex_pi_trylock(afl_mutex_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();

    if (__afl_likely(__atomic_compare_exchange_n(mutex, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");

    return EBUSY;
}

/*
 * afl_mutex_destroy writes the free value back over the mutex and returns
 * 0, for every mutex flavour of this header. Destroying a held or waited
 * on mutex is misuse, sound only once no thread can observe the word
 * again.
 */
static inline int afl_mutex_destroy(afl_mutex_t *mutex)
{
    __atomic_store_n(mutex, AFL_UNLOCKED, __ATOMIC_RELEASE);
    return 0;
}

/*
 * Timed Mutex Locks
 *
 * afl_mutex_timedlock, afl_mutex_owner_timedlock and
 * afl_mutex_recursive_timedlock mirror pthread_mutex_timedlock: 0 once the
 * mutex is held, ETIMEDOUT once the deadline passes before it could be
 * acquired, and an error return never leaves the mutex half held.
 *
 * The deadline is an absolute CLOCK_REALTIME time, exactly as the POSIX
 * interface specifies. This differs from afl_cond_timedwait and the rwlock
 * timed acquires, which are documented to take CLOCK_MONOTONIC deadlines; a
 * caller mixing them must not build one abstime for both. The conversion of
 * an absolute deadline into the relative timeout a FUTEX_WAIT expects reuses
 * __afl_deadline_relative, which is pure subtraction and does not care which
 * clock fed the two operands, so no deadline math is duplicated.
 *
 * The three timed acquires and the three untimed ones are the same call to
 * __afl_mutex_lock_core with and without a deadline, so a timed acquire waits
 * exactly the way its untimed sibling does and only adds the deadline checks;
 * see the comment on that helper for what the shared body guarantees.
 *
 * Like glibc, the uncontended fast path never reads the clock: a free mutex
 * is taken with one compare exchange even when abstime lies in the past, so
 * an uncontended timed lock costs what an uncontended lock costs, and the
 * deadline is computed once the first attempt fails and only refused as
 * expired once contention has been observed. A NULL abstime, a tv_nsec
 * outside [0, 1000000000) or a clock that does not answer is rejected with
 * EINVAL, the same rules afl_cond_timedwait applies, the first two before
 * any state is touched. The spin phase checks the deadline on every attempt,
 * so it stops as soon as time runs out, and every park recomputes the
 * remaining timeout from the absolute deadline, so a spurious wake up cannot
 * stretch it and no sleep passes abstime. The lock word is only ever written
 * by a compare exchange that succeeds and counts as an acquisition; a giving
 * up waiter at most leaves the waiters bit set, which costs one harmless
 * extra wake up and can never lose one, the trade the rwlock timed acquires
 * already make.
 */

/*
 * afl_mutex_timedlock takes the mutex like afl_mutex_lock, but gives up with
 * ETIMEDOUT once abstime, an absolute CLOCK_REALTIME deadline, passes
 * without the mutex being acquired. A NULL abstime, or a tv_nsec field
 * outside [0, 1000000000), returns EINVAL before the lock state is touched.
 * The mutex is not held on any nonzero return. Like pthread_mutex_timedlock,
 * and unlike afl_cond_timedwait, a free mutex is taken even when abstime
 * lies in the past: the deadline is only consulted once contention has been
 * observed.
 */
static inline int afl_mutex_timedlock(afl_mutex_t *mutex, const struct timespec *abstime)
{
    int rc = __afl_validate_abstime(abstime);

    if (__afl_unlikely(rc != 0))
        return rc;

    return __afl_mutex_lock_core(mutex, AFL_LOCKED, AFL_UNLOCKED, AFL_UNLOCKED, abstime, 1);
}

/*
 * afl_mutex_owner_timedlock takes the mutex like afl_mutex_owner_lock,
 * recording the calling thread as the owner, and refuses EDEADLOCK when the
 * caller already owns it, before the deadline is consulted. Apart from that
 * the abstime rules and return values are those of afl_mutex_timedlock.
 */
static inline int afl_mutex_owner_timedlock(afl_mutex_t *mutex, const struct timespec *abstime)
{
    uint32_t tid = __afl_gettid();
    int rc = __afl_validate_abstime(abstime);

    if (__afl_unlikely(rc != 0))
        return rc;

    return __afl_mutex_lock_core(mutex, tid, tid, AFL_UNLOCKED, abstime, 1);
}

/*
 * Recursive Mutex
 */
typedef struct
{
    uint32_t lock;
    size_t count;
} afl_mutex_recursive_t __AFL_ALIGN;

/*
 * afl_mutex_recursive_init stores the free value into the lock word with
 * release ordering, zeroes the recursion counter and returns 0. The two
 * words are the whole state; a static initializer of the struct with
 * zeroes is equivalent to this call.
 */
static inline int afl_mutex_recursive_init(afl_mutex_recursive_t *mutex)
{
    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    mutex->count = 0;

    return 0;
}

/*
 * afl_mutex_recursive_lock takes the recursive mutex and returns 0,
 * either as the first owner (the word records this thread and count
 * becomes 1) or as a re-acquisition by the owning thread (count
 * increases, answered from a plain load without any atomic operation).
 * A re-acquisition at the largest representable count returns EAGAIN and
 * leaves the mutex as it was, the one recoverable error of this call;
 * foreign acquires wait exactly as in afl_mutex_owner_lock, on the same
 * shared body.
 */
static inline int afl_mutex_recursive_lock(afl_mutex_recursive_t *mutex)
{
    uint32_t tid = __afl_gettid();
    uint32_t lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);
    int rc;

    /*
     * Recursive acquisition: the calling thread already owns the mutex. This is
     * the common case for a recursive mutex, a lock that is taken at every level
     * of a recursive walk re-acquires it on the way down, so it is answered from
     * the plain load alone and costs no atomic operation at all. A compare
     * exchange seeded from the free value cannot answer it on its own: it fails
     * first and only then leaves the owner in lock, which would turn every nested
     * acquisition into a failed atomic operation. That is why this variant reads
     * the word before it hands over to the shared body, and the plain and owner
     * tracking mutexes do not.
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
     * Foreign acquire: the shared body of every blocking acquire, writing this
     * thread as the owner. The recursion check of the body is off here, because
     * the load above has just answered the self acquisition and no other thread
     * can put this thread's id into the word, so the body could never observe
     * one. count is written only once the word really is held, which is what
     * keeps a failed acquire from leaving the mutex half taken.
     */
    rc = __afl_mutex_lock_core(&mutex->lock, tid, AFL_UNLOCKED, lock, NULL, 0);

    if (__afl_likely(rc == 0))
        mutex->count = 1;

    return rc;
}

/*
 * afl_mutex_recursive_unlock decrements the recursion counter and
 * returns 0; the mutex is only truly released, and one waiter woken, when
 * the counter reaches zero. A call by a thread that does not own the
 * mutex is refused with EPERM before anything is decremented; releasing
 * more times than the owner acquired it is misuse and wraps count, which
 * AFL_DEBUG reports.
 */
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

/*
 * afl_mutex_recursive_trylock attempts to take the recursive mutex without
 * waiting. Unlike the other trylocks it is recursive by design, matching
 * pthread_mutex_trylock on a recursive mutex: a hold by the calling thread
 * re-acquires, returning 0 and bumping count, or EAGAIN when count would
 * overflow; a free mutex is taken with one compare exchange from the free
 * value and count set to 1; a mutex held by another thread, or one whose word
 * still carries the waiters bit, is refused with EBUSY and left untouched.
 * As in afl_mutex_recursive_lock the expected value of the exchange is pinned
 * to the free value, so a failed attempt never writes.
 */
static inline int afl_mutex_recursive_trylock(afl_mutex_recursive_t *mutex)
{
    uint32_t tid = __afl_gettid();
    uint32_t lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);

    /*
     * Recursive acquisition: answered from the plain load alone, exactly as in
     * afl_mutex_recursive_lock, so a nested trylock costs no atomic operation.
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

    lock = AFL_UNLOCKED;

    if (__afl_likely(__atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))) {
        mutex->count = 1;
        return 0;
    }

    return EBUSY;
}

/*
 * afl_mutex_recursive_destroy writes the free value and a zero count back
 * over the recursive mutex and returns 0. As with afl_mutex_destroy,
 * destroying while held or waited on is misuse.
 */
static inline int afl_mutex_recursive_destroy(afl_mutex_recursive_t *mutex)
{
    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    mutex->count = 0;

    return 0;
}

/*
 * afl_mutex_recursive_timedlock takes the recursive mutex with an absolute
 * CLOCK_REALTIME deadline. Re-acquisition by the owning thread bypasses the
 * timeout check entirely, as it does in pthread_mutex_timedlock: it returns
 * 0, or EAGAIN on a counter overflow, whatever abstime says, as long as
 * abstime is not NULL. For a thread that does not own the mutex the rules
 * are those of afl_mutex_timedlock; the mutex is free and untouched on any
 * nonzero return, because count is only written after the lock word has
 * actually been acquired.
 */
static inline int afl_mutex_recursive_timedlock(afl_mutex_recursive_t *mutex, const struct timespec *abstime)
{
    uint32_t tid = __afl_gettid();
    uint32_t lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);
    int rc;

    if (__afl_unlikely(abstime == NULL))
        return EINVAL;

    /*
     * Recursive acquisition, see afl_mutex_recursive_lock: the owner re-entry
     * is answered from the plain load alone and never consults the deadline.
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

    rc = __afl_validate_abstime(abstime);

    if (__afl_unlikely(rc != 0))
        return rc;

    /*
     * Foreign acquire: the shared body, with the recursion check off for the
     * reason afl_mutex_recursive_lock gives, so a self acquisition can never
     * come back as EDEADLOCK from here - the fast path above has already
     * answered it with 0.
     */
    rc = __afl_mutex_lock_core(&mutex->lock, tid, AFL_UNLOCKED, lock, abstime, 1);

    if (rc == 0)
        mutex->count = 1;

    return rc;
}

/*
 * afl_cond_t stores a sequence number and a count of registered waiters.
 * Signal and broadcast advance the sequence before waking waiters. A waiter
 * registers while holding its plain mutex, releases it, then waits on the
 * observed sequence; a signal racing with the wait prevents futex parking.
 * The waiter count avoids a syscall when no thread can receive the wakeup.
 *
 * Use only the plain afl_mutex_lock/afl_mutex_unlock pair. The mutex protects
 * the predicate; condition waits can wake spuriously and must recheck it.
 */
typedef struct
{
    uint32_t sequence; // Futex word: bumped by every signal and every broadcast
    uint32_t waiters;  // Threads that are currently inside afl_cond_wait()
} afl_cond_t __AFL_ALIGN;

/* AFL_COND_INIT initializes the sequence and waiter count to zero. */
#define AFL_COND_INIT {0, 0}

/*
 * afl_cond_init zeroes the sequence word and the waiter count and returns
 * 0. The condition variable itself never blocks, so there is no lock
 * state to drain; pairing mutexes are initialized separately.
 */
static inline int afl_cond_init(afl_cond_t *cond)
{
    cond->sequence = 0;
    cond->waiters = 0;

    return 0;
}

/*
 * afl_cond_destroy reinitializes the condition variable and returns 0.
 * Destroying it while a thread is inside afl_cond_wait is misuse, which
 * AFL_DEBUG reports by way of the waiter count.
 */
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

/*
 * afl_cond_signal wakes one waiter of the condition variable and returns
 * 0; the choice of which waiter is the kernel's. A signal with no waiter
 * is a no-op that never reaches the kernel, see __afl_cond_wake. The
 * caller still holds the paired mutex here: the woken thread runs when
 * that mutex is released.
 */
static inline int afl_cond_signal(afl_cond_t *cond)
{
    return __afl_cond_wake(cond, 1);
}

/*
 * afl_cond_broadcast wakes every current waiter of the condition
 * variable and returns 0, with the same missed-signal protection and the
 * same zero-waiter no-op as afl_cond_signal. Every woken thread races
 * for the paired mutex when the caller releases it, so a predicate must be
 * re-checked in a loop.
 */
static inline int afl_cond_broadcast(afl_cond_t *cond)
{
    return __afl_cond_wake(cond, INT32_MAX);
}

/*
 * __afl_cond_relock reacquires the paired mutex after a condition wait. The
 * signaller often still holds it and needs CPU time to reach its unlock.
 * After one fast attempt, park without the ordinary mutex's spin budget.
 * The shared slow path preserves the waiters bit and its wake chain. Even
 * a timed condition wait must reacquire without a deadline before returning.
 */
static inline __attribute__((cold)) int __afl_cond_relock(afl_mutex_t *mutex)
{
    uint32_t observed = AFL_UNLOCKED;

    if (__atomic_compare_exchange_n(mutex, &observed, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;

    return __afl_mutex_lock_slow_core(mutex, AFL_LOCKED, 0, observed, NULL, 0, 0);
}

/*
 * afl_cond_wait releases the held plain mutex while waiting on cond, then
 * reacquires it. Spurious wakeups and signal interruptions return success;
 * other futex errors return after reacquisition. A reacquisition error takes
 * precedence. The caller must recheck its protected predicate in a loop.
 */
static inline int afl_cond_wait(afl_cond_t *cond, afl_mutex_t *mutex)
{
    uint32_t sequence = __atomic_load_n(&cond->sequence, __ATOMIC_RELAXED);

    /*
     * Register before the mutex is released, so that a signal which arrives right
     * after the release sees this waiter. The release pairs with the lock the
     * signaller holds while it signals, which is what makes the relaxed waiters
     * load of __afl_cond_wake see this registration; no SEQ_CST is needed.
     */
    __atomic_fetch_add(&cond->waiters, 1, __ATOMIC_RELEASE);

    afl_mutex_unlock(mutex);

    /*
     * A spurious wake, signal interruption or changed sequence (EAGAIN) ends
     * the wait normally. Other kernel errors are returned after reacquiring
     * the mutex, so the caller can still inspect its protected predicate.
     */
    long ret = __afl_syscall(__NR_futex, (intptr_t) &cond->sequence, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, sequence, 0);

    __atomic_fetch_sub(&cond->waiters, 1, __ATOMIC_RELAXED);

    int rc = __afl_cond_relock(mutex);
    if (rc != 0)
        return rc;
    return ret < 0 && ret != -EAGAIN && ret != -EINTR ? (int) -ret : 0;
}

/*
 * afl_cond_timedwait waits with an absolute CLOCK_MONOTONIC deadline.
 * A NULL deadline or tv_nsec outside [0, 1000000000) returns EINVAL without
 * changing state. An expired deadline returns ETIMEDOUT with the mutex held.
 * After a parked wait, reacquisition is untimed and its error takes precedence
 * over the wait result. Success can be a spurious wakeup; recheck the predicate.
 */
static inline int afl_cond_timedwait(afl_cond_t *cond, afl_mutex_t *mutex, const struct timespec *abstime)
{
    struct timespec now, relative;
    uint32_t sequence;
    long ret;
    int rc;

    /*
     * A NULL deadline or an out of range nanosecond field is refused before
     * anything is touched, on the one validator every timed entry point of
     * this header shares, so a missing deadline is an EINVAL here too rather
     * than a dereference of it.
     */
    rc = __afl_validate_abstime(abstime);

    if (__afl_unlikely(rc != 0))
        return rc;

    /*
     * FUTEX_WAIT wants a relative timeout while pthread_cond_timedwait() wants
     * an absolute deadline, so the deadline is measured against
     * CLOCK_MONOTONIC and converted by the helper the timed mutex and rwlock
     * acquires use. A deadline that is at or behind now comes back as
     * ETIMEDOUT with the mutex still held: the zero case is refused here
     * instead of being left to the kernel, because a FUTEX_WAIT with a zero
     * timeout comes back with EAGAIN, which the code below cannot tell apart
     * from a wake up that raced with the sleep.
     */
    if (__afl_unlikely(afl_clock_gettime(CLOCK_MONOTONIC, &now) != 0))
        return EINVAL;

    if (__afl_deadline_relative(abstime, &now, &relative))
        return ETIMEDOUT;

    /*
     * The sequence is read only once the wait is really going to happen, so
     * the read sits next to the registration exactly as it does in
     * afl_cond_wait, and a deadline refused above cannot leave this call
     * holding a word it read before it knew whether it would sleep on it.
     */
    sequence = __atomic_load_n(&cond->sequence, __ATOMIC_RELAXED);

    __atomic_fetch_add(&cond->waiters, 1, __ATOMIC_RELEASE);

    afl_mutex_unlock(mutex);

    ret = __afl_syscall(
      __NR_futex, (intptr_t) &cond->sequence, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, sequence, (long) (intptr_t) &relative
    );

    __atomic_fetch_sub(&cond->waiters, 1, __ATOMIC_RELAXED);

    rc = __afl_cond_relock(mutex);

    if (rc != 0)
        return rc;

    /* Raw syscalls return -errno; libc's errno may be stale. */
    return ret < 0 && ret != -EAGAIN && ret != -EINTR ? (int) -ret : 0;
}

/*
 * afl_once_t uses the plain mutex states plus AFL_SUCCESS. The initializer
 * publishes completion with release ordering; other callers observe it with
 * acquire ordering before using the initialized state.
 */
typedef uint32_t afl_once_t __AFL_ALIGN;

/* AFL_SUCCESS marks completed once-only initialization. */
#define AFL_SUCCESS 0x40000000

/* AFL_ONCE_INIT initializes an unclaimed once word. */
#define AFL_ONCE_INIT 0

/*
 * afl_once runs init exactly once across all threads: the first call
 * claims the word, runs init, publishes AFL_SUCCESS with release
 * ordering and wakes the threads that announced themselves as waiters;
 * every call after that, and every racing call that lost the claim,
 * returns 0 after observing AFL_SUCCESS with acquire ordering, so the
 * caller sees the initialized state. A later call with a different init
 * is misuse: it returns without calling anything, like pthread_once.
 */
static inline int afl_once(afl_once_t *once, void (*init)(void))
{
    uint32_t lock = __atomic_load_n(once, __ATOMIC_ACQUIRE);

    if (__afl_likely(lock & AFL_SUCCESS))
        return 0;

    /* Try to become the thread that runs the initialization routine. */
    if (lock == AFL_UNLOCKED) {
        uint32_t expected = AFL_UNLOCKED;

        /* A losing CAS can observe AFL_SUCCESS directly, so its failure
         * ordering must also acquire the initializer's published data. */
        if (__atomic_compare_exchange_n(once, &expected, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
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

/*
 * afl_rwlock_t packs waiters (bit 31), writer hold (30), writer claim (29) and
 * reader count (28..0) into one word. A writer claim excludes new readers while
 * current readers drain. Acquires spin up to AFL_SPIN_LIMIT before parking.
 *
 * Readers and writers share one futex, so a wake targets all waiters, which
 * recheck their mode before acquiring. A reader wakes only when it is the last
 * reader under a writer claim.
 * A failed or timed-out writer must deregister its claim; stale waiter bits
 * may cause an extra wake but must not suppress a required wakeup.
 * The count saturates at AFL_RW_COUNT. Release by a non-holder corrupts state.
 */
typedef uint32_t afl_rwlock_t __AFL_ALIGN;

/* AFL_RWLOCK_INIT initializes a free reader/writer lock. */
#define AFL_RWLOCK_INIT 0

/* AFL_RW_WRITER marks an active writer. */
#define AFL_RW_WRITER 0x40000000
/* AFL_RW_WCLAIM blocks new readers while a writer waits for readers to drain. */
#define AFL_RW_WCLAIM 0x20000000
/* AFL_RW_COUNT masks the reader count and sets its saturation limit. */
#define AFL_RW_COUNT 0x1FFFFFFF

/*
 * __afl_rw_read_hint predicts the count for this thread's next read acquire.
 * It is advisory, shared across locks in this translation unit, and lives in
 * the thread's TLS. A compare exchange verifies it before granting ownership;
 * a stale prediction, a different lock, or writer/waiter flags fall back to
 * the checked slow path. A valid reader unlock leaves at most COUNT - 1,
 * so adding one to the prediction cannot overflow into the writer flags.
 */
static __thread uint32_t __afl_rw_read_hint;

/*
 * afl_rwlock_init initializes a read/write lock to the free state.
 */
static inline int afl_rwlock_init(afl_rwlock_t *rwlock)
{
    __atomic_store_n(rwlock, AFL_UNLOCKED, __ATOMIC_RELEASE);

    return 0;
}

/*
 * afl_rwlock_destroy resets a read/write lock. Destroying a lock that is
 * still held, still read or still claimed is reported with AFL_DEBUG and
 * otherwise ignored, the way the other destroy functions of this header
 * behave.
 */
static inline int afl_rwlock_destroy(afl_rwlock_t *rwlock)
{
    __afl_debug(
      __atomic_load_n(rwlock, __ATOMIC_RELAXED) != AFL_UNLOCKED,
      "An attempt was made to destroy a rwlock that is still held."
    );

    return afl_rwlock_init(rwlock);
}

/*
 * __afl_rwlock_blocked tells whether a lock word that reads `value` admits
 * neither a new reader nor a new claim: a writer holds the lock, or a writer
 * has claimed it and waits for the readers to drain.
 */
static inline int __afl_rwlock_blocked(uint32_t value)
{
    return (value & (AFL_RW_WRITER | AFL_RW_WCLAIM)) != 0;
}

/*
 * __afl_rwlock_wake wakes every waiter of the lock. Readers and writers park
 * on the same word, so a wake up cannot address one class.
 */
static inline void __afl_rwlock_wake(afl_rwlock_t *rwlock)
{
    __afl_syscall(__NR_futex, (intptr_t) rwlock, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, INT32_MAX, 0);
}

/*
 * __afl_rwlock_validate_timeout applies the rules of afl_cond_timedwait() to
 * the abstime of a timed acquire before any state is touched: EINVAL for a
 * nanosecond field outside [0, 1000000000) or a clock that does not answer,
 * ETIMEDOUT for a deadline that is already at or behind now, 0 otherwise,
 * with the converted relative timeout left in `relative`.
 */
static inline int
  __afl_rwlock_validate_timeout(const struct timespec *abstime, struct timespec *now, struct timespec *relative)
{
    int rc = __afl_validate_abstime(abstime);

    if (__afl_unlikely(rc != 0))
        return rc;

    if (__afl_unlikely(afl_clock_gettime(CLOCK_MONOTONIC, now) != 0))
        return EINVAL;

    if (__afl_deadline_relative(abstime, now, relative))
        return ETIMEDOUT;

    return 0;
}

/*
 * __afl_rwlock_deregister drops the writer claim of a timed acquire that gave
 * up. A claim bit without its writer would keep every new reader out forever
 * and no other thread may clear it, so the giving up writer has to: the claim
 * bit goes together with the waiters bit, which the unconditional wake all
 * below then covers. The compare exchange can lose to a reader that refreshed
 * the word, so the loop retries on the fresh value until the claim is gone.
 */
static inline void __afl_rwlock_deregister(afl_rwlock_t *rwlock)
{
    uint32_t value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);

    while (value & AFL_RW_WCLAIM) {
        uint32_t desired = value & ~(AFL_RW_WCLAIM | AFL_HAVE_WAITERS);

        if (__atomic_compare_exchange_n(rwlock, &value, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }

    __afl_rwlock_wake(rwlock);
}

/*
 * __afl_rwlock_rdlock is the shared body of the read acquires: abstime is
 * NULL for afl_rwlock_rdlock, an absolute CLOCK_MONOTONIC deadline for
 * afl_rwlock_timedrdlock.
 *
 * The fast path and the spin phase try to join the reader count with a
 * compare exchange from the observed value, so the waiters bit of parked
 * readers or of a waiting writer survives the increment and only the count
 * changes. A failed attempt leaves the word unchanged. Before parking
 * the waiter announces itself, exactly as the mutexes do; a timed acquire
 * refreshes its relative deadline from the absolute one before every park,
 * so a spurious wake up cannot stretch the timeout.
 */
static inline __attribute__((cold)) int __afl_rwlock_rdlock(afl_rwlock_t *rwlock, const struct timespec *abstime)
{
    struct timespec now, relative, *timeout = NULL;
    __afl_spin_backoff_t backoff;
    uint32_t value;
    long ret = 0;
    int rc;

    if (abstime != NULL) {
        rc = __afl_rwlock_validate_timeout(abstime, &now, &relative);
        if (rc != 0)
            return rc;

        timeout = &relative;
    }

    value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);

    if (__afl_unlikely((value & AFL_RW_COUNT) == AFL_RW_COUNT))
        return EAGAIN;

    if (
      __afl_likely(!__afl_rwlock_blocked(value))
      && __afl_likely(__atomic_compare_exchange_n(rwlock, &value, value + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    )
        return 0;

    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (timeout != NULL) {
            rc = __afl_rwlock_validate_timeout(abstime, &now, &relative);
            if (__afl_unlikely(rc != 0)) {
                return rc;
            }
        }
        if (__afl_unlikely((value & AFL_RW_COUNT) == AFL_RW_COUNT))
            return EAGAIN;
        if (
          !__afl_rwlock_blocked(value)
          && __atomic_compare_exchange_n(rwlock, &value, value + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
        )
            return 0;

        __afl_spin_backoff(&backoff);
        value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);
    }

    for (;;) {
        if (timeout != NULL) {
            rc = __afl_rwlock_validate_timeout(abstime, &now, &relative);
            if (__afl_unlikely(rc != 0)) {
                return rc;
            }
        }
        if (__afl_unlikely((value & AFL_RW_COUNT) == AFL_RW_COUNT))
            return EAGAIN;
        if (!__afl_rwlock_blocked(value)) {
            if (__atomic_compare_exchange_n(rwlock, &value, value + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return 0;
            continue;
        }

        if (!(value & AFL_HAVE_WAITERS)) {
            value = __afl_futex_announce(rwlock, value);
            continue;
        }

        /*
         * A timed acquire recomputes the relative deadline before every park,
         * so a spurious wake up cannot stretch the timeout; a deadline that
         * has run out is reported directly, a clock that does not answer with
         * EINVAL, matching the validation before the first attempt.
         */
        if (timeout != NULL) {
            if (__afl_unlikely(afl_clock_gettime(CLOCK_MONOTONIC, &now) != 0))
                return EINVAL;

            if (__afl_deadline_relative(abstime, &now, &relative))
                return ETIMEDOUT;
        }

        ret = __afl_syscall(
          __NR_futex, (intptr_t) rwlock, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, value, (long) (intptr_t) timeout
        );

        if (__afl_unlikely(ret < 0 && ret != -EAGAIN && ret != -EINTR)) {
            return (int) -ret;
        }
        value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);
    }
}

/*
 * __afl_rwlock_wrlock is the shared body of the write acquires: abstime is
 * NULL for afl_rwlock_wrlock, an absolute CLOCK_MONOTONIC deadline for
 * afl_rwlock_timedwrlock.
 *
 * The writer works in three steps: win the free word in one compare exchange,
 * or plant the claim bit on a word that only readers hold, then wait for the
 * count to drain, then turn its own claim into the writer bit, carrying the
 * waiters bit over so that the readers that parked behind the claim learn
 * about the eventual unlock. The single loop always tries the step the
 * current word calls for and only spends a spin attempt when no step can win,
 * so the claim is planted before the first park: that is what gives the
 * waiting writer its preference over arriving readers.
 */
static inline __attribute__((cold)) int __afl_rwlock_wrlock(afl_rwlock_t *rwlock, const struct timespec *abstime)
{
    struct timespec now, relative, *timeout = NULL;
    __afl_spin_backoff_t backoff;
    uint32_t value;
    long ret = 0;
    int claimed = 0;
    int rc;

    if (abstime != NULL) {
        rc = __afl_rwlock_validate_timeout(abstime, &now, &relative);
        if (rc != 0)
            return rc;

        timeout = &relative;
    }

    __afl_spin_backoff_init(&backoff);
    value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (timeout != NULL) {
            rc = __afl_rwlock_validate_timeout(abstime, &now, &relative);
            if (__afl_unlikely(rc != 0)) {
                if (claimed)
                    __afl_rwlock_deregister(rwlock);
                return rc;
            }
        }
        if (claimed) {
            if (!(value & AFL_RW_COUNT)) {
                uint32_t desired = (value & ~AFL_RW_WCLAIM) | AFL_RW_WRITER;

                if (__atomic_compare_exchange_n(rwlock, &value, desired, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                    return 0;
                continue;
            }
        } else if (value == AFL_UNLOCKED) {
            if (
              __afl_likely(
                __atomic_compare_exchange_n(rwlock, &value, AFL_RW_WRITER, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
              )
            )
                return 0;
            continue;
        } else if (!__afl_rwlock_blocked(value)) {
            if (__atomic_compare_exchange_n(rwlock, &value, value | AFL_RW_WCLAIM, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                claimed = 1;
                spin = 0;
            }
            continue;
        }

        __afl_spin_backoff(&backoff);
        value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);
    }

    for (;;) {
        if (timeout != NULL) {
            rc = __afl_rwlock_validate_timeout(abstime, &now, &relative);
            if (__afl_unlikely(rc != 0)) {
                if (claimed)
                    __afl_rwlock_deregister(rwlock);
                return rc;
            }
        }
        if (claimed) {
            if (!(value & AFL_RW_COUNT)) {
                uint32_t desired = (value & ~AFL_RW_WCLAIM) | AFL_RW_WRITER;

                if (__atomic_compare_exchange_n(rwlock, &value, desired, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                    return 0;
                continue;
            }
        } else if (value == AFL_UNLOCKED) {
            if (
              __afl_likely(
                __atomic_compare_exchange_n(rwlock, &value, AFL_RW_WRITER, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
              )
            )
                return 0;
            continue;
        } else if (!__afl_rwlock_blocked(value)) {
            /* The claim reads the word one of the unlocking paths wrote with a
               release, so it is the point where the writer acquires the data the
               readers released; the promote below only reads its own claim. */
            if (__atomic_compare_exchange_n(rwlock, &value, value | AFL_RW_WCLAIM, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                claimed = 1;
            continue;
        }

        if (!(value & AFL_HAVE_WAITERS)) {
            value = __afl_futex_announce(rwlock, value);
            continue;
        }

        /*
         * Recompute the relative deadline before every park, see
         * __afl_rwlock_rdlock. A writer that gives up has to hand its claim
         * back before returning, otherwise the claim would keep every new
         * reader out with nobody left to release it.
         */
        if (timeout != NULL) {
            if (__afl_unlikely(afl_clock_gettime(CLOCK_MONOTONIC, &now) != 0)) {
                if (claimed)
                    __afl_rwlock_deregister(rwlock);

                return EINVAL;
            }

            if (__afl_deadline_relative(abstime, &now, &relative)) {
                if (claimed)
                    __afl_rwlock_deregister(rwlock);

                return ETIMEDOUT;
            }
        }

        ret = __afl_syscall(
          __NR_futex, (intptr_t) rwlock, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, value, (long) (intptr_t) timeout
        );

        if (__afl_unlikely(ret < 0 && ret != -EAGAIN && ret != -EINTR)) {
            if (claimed)
                __afl_rwlock_deregister(rwlock);
            return (int) -ret;
        }
        value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);
    }
}

/*
 * afl_rwlock_rdlock acquires the lock for reading. Up to AFL_RW_COUNT readers
 * hold it at the same time; EAGAIN reports a saturated reader count. The call
 * waits while a writer holds the lock or waits behind its claim (see the
 * section comment on the writer preference).
 */
static inline int afl_rwlock_rdlock(afl_rwlock_t *rwlock)
{
    /* Predict from the last release instead of first loading a shared cache
     * line that the following compare exchange needs exclusively. */
    uint32_t value = __afl_rw_read_hint;

    if (__atomic_compare_exchange_n(rwlock, &value, value + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;

    return __afl_rwlock_rdlock(rwlock, NULL);
}

/*
 * afl_rwlock_tryrdlock acquires the lock for reading without waiting: EBUSY
 * when a writer holds or claims it, or when the word changed under the
 * attempt, EAGAIN when the reader count is saturated, 0 on success.
 */
static inline int afl_rwlock_tryrdlock(afl_rwlock_t *rwlock)
{
    uint32_t value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);

    if (__afl_unlikely((value & AFL_RW_COUNT) == AFL_RW_COUNT))
        return EAGAIN;

    if (__afl_rwlock_blocked(value))
        return EBUSY;

    if (__atomic_compare_exchange_n(rwlock, &value, value + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;

    return EBUSY;
}

/*
 * afl_rwlock_timedrdlock is afl_rwlock_rdlock with a deadline: abstime is an
 * absolute point on CLOCK_MONOTONIC. It returns EINVAL for a NULL abstime,
 * for a nanosecond field outside [0, 1000000000) and for a clock that does
 * not answer, without touching the lock, and ETIMEDOUT when the deadline is
 * at or behind now or expires while waiting; the lock is not held on any
 * non zero return.
 */
static inline int afl_rwlock_timedrdlock(afl_rwlock_t *rwlock, const struct timespec *abstime)
{
    if (abstime == NULL)
        return EINVAL;

    return __afl_rwlock_rdlock(rwlock, abstime);
}

/*
 * afl_rwlock_wrlock acquires the lock for writing. It waits until no reader
 * and no other writer holds or claims the lock; once it has claimed the lock
 * new readers wait behind it.
 */
static inline int afl_rwlock_wrlock(afl_rwlock_t *rwlock)
{
    uint32_t value = AFL_UNLOCKED;

    if (__afl_likely(__atomic_compare_exchange_n(rwlock, &value, AFL_RW_WRITER, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    return __afl_rwlock_wrlock(rwlock, NULL);
}

/*
 * afl_rwlock_trywrlock acquires the lock for writing without waiting: EBUSY
 * unless the word shows neither readers nor a writer nor a claim, 0 on
 * success.
 */
static inline int afl_rwlock_trywrlock(afl_rwlock_t *rwlock)
{
    uint32_t value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);

    if (value & (AFL_RW_WRITER | AFL_RW_WCLAIM | AFL_RW_COUNT))
        return EBUSY;

    if (__atomic_compare_exchange_n(rwlock, &value, value | AFL_RW_WRITER, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;

    return EBUSY;
}

/*
 * afl_rwlock_timedwrlock is afl_rwlock_wrlock with a deadline, with the same
 * abstime validation as afl_rwlock_timedrdlock(). On ETIMEDOUT the lock is
 * not held and a claim this call had planted is gone, together with its
 * effect on arriving readers.
 */
static inline int afl_rwlock_timedwrlock(afl_rwlock_t *rwlock, const struct timespec *abstime)
{
    if (abstime == NULL)
        return EINVAL;

    return __afl_rwlock_wrlock(rwlock, abstime);
}

/*
 * afl_rwlock_unlock releases the lock in whichever mode it was taken: the
 * writer bit in the word tells the two apart. A writer release empties the
 * word and wakes everybody. A reader release only wakes when it is the last
 * reader out while a writer waits behind its claim, and then it wakes all,
 * the parked readers that still see the claim simply go back to sleep; a
 * reader that can still share never wakes a writer. Releasing a lock that is
 * not held, or in the wrong mode, corrupts the word and is documented misuse.
 */
static inline void afl_rwlock_unlock(afl_rwlock_t *rwlock)
{
    uint32_t value = __atomic_load_n(rwlock, __ATOMIC_RELAXED);

    if (value & AFL_RW_WRITER) {
        __afl_rw_read_hint = 0;
        value = __atomic_exchange_n(rwlock, AFL_UNLOCKED, __ATOMIC_RELEASE);

        if (__afl_unlikely(value & AFL_HAVE_WAITERS))
            __afl_rwlock_wake(rwlock);

        return;
    }

    value = __atomic_fetch_sub(rwlock, 1, __ATOMIC_ACQ_REL);

    __afl_rw_read_hint = (value - 1) & AFL_RW_COUNT;
    if (__afl_unlikely((value & (AFL_RW_WCLAIM | AFL_RW_COUNT)) == (AFL_RW_WCLAIM | 1) && (value & AFL_HAVE_WAITERS)))
        __afl_rwlock_wake(rwlock);
}

/*
 * Adaptive Mutex
 *
 * Bits 24..27 hold a contention hint alongside the holder and waiters bits.
 * The hint selects a spin budget: AFL_ADAPTIVE_SPIN_MIN doubled per hint step,
 * capped at AFL_ADAPTIVE_SPIN_MAX. A contended acquire multiplies the hint by four
 * (zero becomes one); an uncontended acquire lowers it by one.
 *
 * Hint updates share the atomic operations that acquire or release the lock.
 * No separate hint store can overwrite a concurrent state transition. While
 * held, the hint stays fixed and waiters can only add the waiters bit; release
 * decides whether to wake from the value its exchange returned.
 *
 * The zero-hint fast path uses one CAS for acquisition and one for release.
 * A hinted path inspects the observed word, and a contended path parks after
 * its selected spin budget. This variant tracks no owner.
 */

/*
 * AFL_ADAPTIVE_SPIN_MIN is the retry budget at hint zero. It limits spinning
 * when recent acquisitions provide little evidence of short contended holds.
 */
#ifndef AFL_ADAPTIVE_SPIN_MIN
#define AFL_ADAPTIVE_SPIN_MIN 4
#endif

/*
 * AFL_ADAPTIVE_SPIN_MAX caps the retry budget selected by the contention hint.
 * It is configured independently of AFL_SPIN_LIMIT. The hint can remain above
 * the first step that reaches this cap, allowing it to decay over several
 * uncontended acquisitions without immediately reducing the spin budget.
 */
#ifndef AFL_ADAPTIVE_SPIN_MAX
#define AFL_ADAPTIVE_SPIN_MAX 32
#endif

/* AFL_ADAPTIVE_HINT_SHIFT locates the least significant contention-hint bit. */
#define AFL_ADAPTIVE_HINT_SHIFT 24
/* AFL_ADAPTIVE_HINT_MASK masks the contention-hint field. */
#define AFL_ADAPTIVE_HINT_MASK (0xFu << AFL_ADAPTIVE_HINT_SHIFT)
/* AFL_ADAPTIVE_HINT_MAX caps the stored contention hint. */
#define AFL_ADAPTIVE_HINT_MAX 4

/* afl_mutex_adaptive_t is the adaptive mutex word described above. */
typedef uint32_t afl_mutex_adaptive_t __AFL_ALIGN;

/* AFL_MUTEX_ADAPTIVE_INIT is the free word: no holder, no waiters, no hint. */
#define AFL_MUTEX_ADAPTIVE_INIT 0

/* __afl_adaptive_hint_of extracts the hint field of an observed lock word. */
static inline uint32_t __afl_adaptive_hint_of(uint32_t word)
{
    return (word & AFL_ADAPTIVE_HINT_MASK) >> AFL_ADAPTIVE_HINT_SHIFT;
}

/* __afl_adaptive_free tells whether a word admits an acquisition: no holder
   bit and no waiters bit, whatever the hint says. */
static inline int __afl_adaptive_free(uint32_t word)
{
    return (word & (AFL_LOCKED | AFL_HAVE_WAITERS)) == 0;
}

/* __afl_adaptive_lowered returns the hint field of a word decayed by one,
   floored at zero: the value written by an acquire that found the word
   free. A quieted lock walks the ladder down to the floor in
   AFL_ADAPTIVE_HINT_MAX uncontended acquisitions. */
static inline uint32_t __afl_adaptive_lowered(uint32_t word)
{
    uint32_t hint = __afl_adaptive_hint_of(word);

    return (hint != 0 ? hint - 1 : 0) << AFL_ADAPTIVE_HINT_SHIFT;
}

/* __afl_adaptive_raised returns the hint field of a word multiplied by four,
   floored at one and capped at AFL_ADAPTIVE_HINT_MAX: the value written by
   an acquire or a release that observed the hand-off of this lock. With the
   default cap a raised hint that is not at the floor lands on the cap, so
   an active hand-off regime keeps the budget at AFL_ADAPTIVE_SPIN_MAX past
   the one step decay of the acquisitions that found the word free. */
static inline uint32_t __afl_adaptive_raised(uint32_t word)
{
    uint32_t hint = __afl_adaptive_hint_of(word);
    uint32_t raised = hint != 0 ? hint * 4u : 1u;

    return (raised > AFL_ADAPTIVE_HINT_MAX ? (uint32_t) AFL_ADAPTIVE_HINT_MAX : raised) << AFL_ADAPTIVE_HINT_SHIFT;
}

/* __afl_adaptive_budget is the spin budget a word prescribes: the minimum
   doubled once per hint step, clamped at the maximum. */
static inline unsigned __afl_adaptive_budget(uint32_t word)
{
    unsigned budget = (unsigned) AFL_ADAPTIVE_SPIN_MIN << __afl_adaptive_hint_of(word);

    return budget < (unsigned) AFL_ADAPTIVE_SPIN_MAX ? budget : (unsigned) AFL_ADAPTIVE_SPIN_MAX;
}

/*
 * afl_mutex_adaptive_init resets an adaptive mutex to the free word. It is
 * the initialization of a zeroed static AFL_MUTEX_ADAPTIVE_INIT, so a mutex
 * that starts at zero does not need it.
 */
static inline int afl_mutex_adaptive_init(afl_mutex_adaptive_t *mutex)
{
    __atomic_store_n(mutex, AFL_MUTEX_ADAPTIVE_INIT, __ATOMIC_RELEASE);

    return 0;
}

/*
 * afl_mutex_adaptive_lock takes the adaptive mutex. The return is 0 once the
 * mutex is held, as in afl_mutex_lock; the hint is read from the word the
 * acquire observed on its first attempt and every write of it rides on the
 * compare exchange that changes the lock state, so the acquire is race free
 * without ever taking the word out of the atomic domain. The phases are those
 * of afl_mutex_lock, a fast path
 * from the free value, a spaced spin phase and the announce/park loop, with
 * two differences: the spin phase runs for the adaptive budget instead of
 * AFL_SPIN_LIMIT attempts, and the winning exchange of each phase writes the
 * hint the transition prescribes, decayed by one on the fast path and
 * multiplied once the hand-off has been observed.
 */
static inline int afl_mutex_adaptive_lock(afl_mutex_adaptive_t *mutex)
{
    __afl_spin_backoff_t backoff;
    uint32_t word = AFL_UNLOCKED;

    /*
     * Fast path: one compare exchange from the free and undecorated word,
     * without a separate test load, so a fully decayed lock costs the single
     * atomic of afl_mutex_lock and nothing more. The expected value is pinned
     * to the free word rather than read first, which is what removes the load:
     * a word that is free but still carries a hint does not match, and neither
     * does a word with a holder, and the exchange then reports which of the
     * two it found. On failure the exchange leaves the observed value in word,
     * which is the hint read of the acquire and what the two loops below need.
     * A waiters bit without a holder cannot exist by the protocol below, the
     * release clears both bits together.
     */
    if (__afl_likely(__atomic_compare_exchange_n(mutex, &word, AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)))
        return 0;

    /*
     * Free, but the word still carries a hint: take it with the decayed hint,
     * so a decay costs no extra atomic either. The exchange is seeded from the
     * value the fast path just observed, and on failure leaves the fresher one
     * behind for the loops below.
     */
    if (__afl_likely(__afl_adaptive_free(word))) {
        uint32_t expected = word;

        if (
          __afl_likely(__atomic_compare_exchange_n(
            mutex, &expected, AFL_LOCKED | __afl_adaptive_lowered(word), 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED
          ))
        )
            return 0;

        word = expected;
    }

    /*
     * Contended: spin for the budget the hint prescribes, spaced by the
     * backoff, the critical section might be tiny. The attempts of the spin
     * phase are all hand-off observations: reaching them means the holder bit
     * was set on the load, so a win here raises the hint.
     */
    __afl_spin_backoff_init(&backoff);

    for (unsigned spin = 0, budget = __afl_adaptive_budget(word); spin < budget; spin++) {
        if (__afl_adaptive_free(word)) {
            uint32_t expected = word;

            if (
              __afl_likely(__atomic_compare_exchange_n(
                mutex, &expected, AFL_LOCKED | __afl_adaptive_raised(word), 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED
              ))
            )
                return 0;

            word = expected;
            continue;
        }

        __afl_spin_backoff(&backoff);
        word = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }

    /*
     * The budget ran out while the holder was still marked running: escalate
     * to the futex, with the waiters protocol of afl_mutex_lock unchanged.
     */
    for (;;) {
        if (__afl_adaptive_free(word)) {
            /*
             * Contended path: keep the waiters bit set, this thread has to
             * wake the next waiter when it releases the lock. The win also
             * raises the hint, an acquire that had to wait for the kernel is
             * the strongest hand-off observation there is.
             */
            uint32_t expected = word;

            if (
              __atomic_compare_exchange_n(
                mutex, &expected, AFL_LOCKED | AFL_HAVE_WAITERS | __afl_adaptive_raised(word), 0, __ATOMIC_ACQUIRE,
                __ATOMIC_RELAXED
              )
            )
                return 0;

            word = expected;
            continue;
        }

        if (!(word & AFL_HAVE_WAITERS)) {
            word = __afl_futex_announce(mutex, word);
            continue;
        }

        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, word, 0);
        word = __atomic_load_n(mutex, __ATOMIC_RELAXED);
    }
}

/*
 * afl_mutex_adaptive_trylock attempts to take the adaptive mutex without
 * waiting: EBUSY when the word shows a holder or waiters, or when the word
 * changed under the attempt, 0 on success. It leaves the hint alone: a
 * successful trylock never spent spin budget on this lock, so it is no
 * evidence either way, and the decay or raise belongs to the acquires that
 * observed something.
 */
static inline int afl_mutex_adaptive_trylock(afl_mutex_adaptive_t *mutex)
{
    uint32_t word = __atomic_load_n(mutex, __ATOMIC_RELAXED);

    if (!__afl_adaptive_free(word))
        return EBUSY;

    if (__atomic_compare_exchange_n(mutex, &word, word | AFL_LOCKED, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;

    return EBUSY;
}

/*
 * afl_mutex_adaptive_unlock releases the adaptive mutex and returns 0. As in
 * afl_mutex_unlock the release is refused by nobody, this variant tracks no
 * owner. The exchange writes a free word back that carries the hint, raised
 * by the same rule the acquires use when the held word still had the waiters
 * bit: a release to a waiter is an observed hand-off, and the raise keeps
 * the budget of the woken chain at the contended optimum. A release of a word
 * that carries neither a hint nor a waiters bit, the state a fully decayed
 * lock is held in, is answered by one compare exchange from the held word
 * instead, so the quiet release costs the single atomic of afl_mutex_unlock
 * and never reaches the exchange. The value the exchange writes is computed
 * from the word that compare exchange observed: while the holder bit is set
 * the waiters bit can only be added, by an announce, and never removed, so
 * the word the exchange observes carries a superset of the waiters bit the
 * failed attempt reported, and the wake up is issued whenever the word the
 * exchange actually returned carried it, which covers the observation racing
 * with a just arriving waiter.
 */
static inline int afl_mutex_adaptive_unlock(afl_mutex_adaptive_t *mutex)
{
    uint32_t word = AFL_LOCKED;

    /*
     * Fast path: the held word carries no hint and no waiters, so freeing it
     * writes the free word back unchanged and there is nothing to raise or
     * preserve. The expected value is pinned to the held word, which is what
     * keeps the release to a single atomic: any hint or any waiters bit makes
     * the attempt fail without writing, and reports the word it found.
     */
    if (__afl_likely(__atomic_compare_exchange_n(mutex, &word, AFL_UNLOCKED, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)))
        return 0;

    word = __atomic_exchange_n(
      mutex, (word & AFL_HAVE_WAITERS) ? __afl_adaptive_raised(word) : (word & AFL_ADAPTIVE_HINT_MASK), __ATOMIC_RELEASE
    );

    __afl_debug((word & AFL_LOCKED) == 0, "An attempt was made to unlock an unlocked adaptive mutex.");

    if (__afl_unlikely(word & AFL_HAVE_WAITERS))
        __afl_syscall(__NR_futex, (intptr_t) mutex, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);

    return 0;
}

/*
 * afl_mutex_adaptive_destroy resets an adaptive mutex. Destroying one that
 * still has a holder or waiters is reported with AFL_DEBUG and otherwise
 * ignored, the way the other destroy functions of this header behave; the
 * hint is reset with the rest of the word.
 */
static inline int afl_mutex_adaptive_destroy(afl_mutex_adaptive_t *mutex)
{
    __afl_debug(
      !__afl_adaptive_free(__atomic_load_n(mutex, __ATOMIC_RELAXED)),
      "An attempt was made to destroy an adaptive mutex that is still held."
    );

    return afl_mutex_adaptive_init(mutex);
}

/*
 * Priority Ceiling Mutex
 *
 * afl_mutex_pc_t is a mutex layered on the same priority inheriting futex that
 * afl_mutex_pi_lock uses, with one addition: while the mutex is held its
 * holder borrows the priority ceiling attached to it, the mechanism that
 * prevents unbounded priority inversion in the priority ceiling protocol and
 * the counterpart of a pthread mutex whose attribute object carries
 * PTHREAD_PRIO_PROTECT and a ceiling.
 *
 * The ceiling is a scheduling priority hint, and it is given on the scale this
 * header uses for every ceiling: a lower number means a higher priority. The
 * value is validated against sched_get_priority_min(SCHED_FIFO) and
 * sched_get_priority_max(SCHED_FIFO), 1 and 99 on Linux. Those two calls also
 * define the mapping the borrowing performs, because sched_setscheduler ranks
 * SCHED_FIFO and SCHED_RR by a number where a higher value wins: the ceiling
 * is inverted onto the kernel range before it is applied,
 *
 *     kernel_priority = min + (max - ceiling)
 *
 * so that ceiling 1 borrows the most favoured kernel priority and ceiling 99
 * the least favoured one. A holder whose kernel priority already is at or
 * above the mapped ceiling is never touched.
 *
 * The borrowing is the documented userspace protocol that glibc implements for
 * PTHREAD_PRIO_PROTECT, and it has to be userspace for the same reason: the
 * fourth argument of FUTEX_LOCK_PI is a struct timespec timeout, not a
 * ceiling, and the kernel knows nothing about ceilings. The thread that wins
 * the lock word saves its own scheduling parameters, raises itself to the
 * mapped ceiling with the raw sched_setscheduler system call while it holds
 * the lock, and puts the saved parameters back on unlock, deterministically,
 * before the word is handed to the next acquirer. On a machine where the
 * process lacks the privilege for real time scheduling the attempt fails with
 * EPERM; that is tolerated by this protocol - the mutex stays a correct
 * priority inheriting mutex, the ceiling bookkeeping keeps working, no thread
 * is elevated - and
 * the refusal of the first attempt is remembered per thread, the way
 * __afl_gettid remembers the thread id, so the next acquisition does not ask
 * again.
 *
 * If the kernel declines the priority inheriting futex itself, initialization
 * fails with the error it reports, ENOSYS or EPERM as it stands, and never
 * silently degrades to a non-PI lock: afl_mutex_pc_init probes the futex with
 * one real FUTEX_LOCK_PI/FUTEX_UNLOCK_PI pair on a private word, so the
 * locking paths can take the kernel's willingness for granted.
 *
 * The mutex is not recursive: an acquisition by the owning thread is detected
 * from the owner tid in the word and reported as EDEADLOCK (the synonym of
 * EDEADLK) by afl_mutex_pc_lock and as EBUSY by afl_mutex_pc_trylock.
 *
 * One thread holding two of these mutexes at once must release them in the
 * order last-locked-first-unlocked: the restore of the earlier acquisition
 * puts back the parameters the later one saved, which were already elevated,
 * so an interleaved release would leave that later holder below its ceiling.
 * The priority ceiling protocol rules out nested critical sections anyway.
 */

/*
 * afl_mutex_pc_t is the priority ceiling mutex: the PI futex word of
 * afl_mutex_pi_lock, the current ceiling, and the parameters the holder saved
 * when it borrowed. The three holder fields are written after the lock word
 * was won and read before it is released, so they belong to the holder alone;
 * every field that is not the word itself is accessed with __atomic operations
 * because the ceiling is also read while the mutex is free. Those accesses are
 * relaxed: the mutex hands out the holder fields through the acquire and
 * release of the lock word, and the atomics are there to keep the accesses
 * race free, not to add order.
 */
typedef struct
{
    uint32_t lock;    // the PI futex word: the owner tid plus the kernel waiters bit
    int ceiling;      // the current ceiling, on the scale __afl_pc_priority maps
    int saved_policy; // the scheduling policy the holder saved when it borrowed
    int saved_prio;   // the scheduling priority the holder saved when it borrowed
    int borrowed;     // 1 while the holder runs at a borrowed ceiling and has to restore
} afl_mutex_pc_t __AFL_ALIGN;

/*
 * AFL_MUTEX_PC_CEILING_DEFAULT is the ceiling of a statically initialized
 * mutex, the weakest one the mapping has on Linux: it asks for nothing above
 * the lowest real time priority, so a static mutex never elevates an RT holder
 * until afl_mutex_pc_init or afl_mutex_pc_setceiling raises the ceiling.
 */
#define AFL_MUTEX_PC_CEILING_DEFAULT 99

/*
 * AFL_MUTEX_PC_INIT initializes a static priority ceiling mutex. The sketch of
 * this macro in the task brief is a scalar 0; the type carries ceiling and
 * holder bookkeeping, so the initializer is the brace form, the same shape
 * AFL_COND_INIT already uses.
 */
#define AFL_MUTEX_PC_INIT {AFL_UNLOCKED, AFL_MUTEX_PC_CEILING_DEFAULT, 0, 0, 0}

/*
 * __afl_pc_range is the SCHED_FIFO range the ceilings live in. The kernel
 * range of a policy is constant for the lifetime of the process and reading
 * it costs two system calls, so the pair is remembered per thread the way the
 * thread id is (see __afl_gettid): the first call of a thread pays the two
 * system calls, every later one reads the cached pair back. A failed read is
 * not cached, so a thread that asked at the wrong moment can succeed later.
 */
static inline int __afl_pc_range(int *min, int *max)
{
    static __thread int cached_min; // the cached pair, valid once cached_ready
    static __thread int cached_max;
    static __thread int cached_ready; // 0 until the range has been read once

    if (__afl_unlikely(cached_ready == 0)) {
        int lo = sched_get_priority_min(SCHED_FIFO);
        int hi = sched_get_priority_max(SCHED_FIFO);

        if (__afl_unlikely(lo < 0 || hi < 0))
            return errno != 0 ? errno : EINVAL;

        cached_min = lo;
        cached_max = hi;
        cached_ready = 1;
    }

    *min = cached_min;
    *max = cached_max;

    return 0;
}

/*
 * __afl_pc_priority validates a ceiling and maps it onto the kernel priority
 * it borrows. The ceiling is valid when it lies inside the SCHED_FIFO range,
 * which is the range the protocol of this header is defined on, and the map is
 * the inversion documented above the type. It returns 0, or EINVAL when the
 * ceiling is out of range, or the error of the range read when there is no
 * such policy; prio may be NULL when only the validation is wanted.
 */
static inline int __afl_pc_priority(int ceiling, int *prio)
{
    int min;
    int max;
    int error = __afl_pc_range(&min, &max);

    if (__afl_unlikely(error != 0))
        return error;

    if (__afl_unlikely(ceiling < min || ceiling > max))
        return EINVAL;

    if (prio != NULL)
        *prio = min + (max - ceiling);

    return 0;
}

/*
 * The three scheduling system calls below are the whole interface the
 * priority ceiling borrowing keeps to the kernel. Their numbers exist on every
 * architecture this header supports (x86-64, i386 and aarch64), and the file
 * already fails to compile for a TLS on anything else, so a missing number
 * here means an unsupported platform rather than a missing feature.
 */
#if !defined(__NR_sched_getscheduler) || !defined(__NR_sched_getparam) || !defined(__NR_sched_setscheduler)
#error "afl.h needs the sched_getscheduler, sched_getparam and sched_setscheduler system call numbers"
#endif

/*
 * __AFL_SCHED_RESET_ON_FORK is the flag bit the kernel ORs into the policy
 * value returned by sched_getscheduler. glibc names it SCHED_RESET_ON_FORK but
 * only exposes that name with _GNU_SOURCE, so the header carries the value and
 * masks it off every policy it reads.
 */
#ifdef SCHED_RESET_ON_FORK
#define __AFL_SCHED_RESET_ON_FORK SCHED_RESET_ON_FORK
#else
#define __AFL_SCHED_RESET_ON_FORK 0x40000000
#endif

/*
 * __afl_sched_error maps the failed return of __afl_syscall onto the positive
 * errno convention this header returns everywhere: ret is negative with the
 * errno encoded in it, and anything that is not a kernel error value becomes
 * EINVAL, the same fallback afl_clock_gettime applies to an unexpected entry
 * result. A successful return never reaches this function.
 */
static inline int __afl_sched_error(long ret)
{
    if (ret < 0 && ret >= -4095)
        return (int) (-ret);

    return EINVAL;
}

/*
 * __afl_sched_cache_t caches this thread's scheduling policy and priority.
 * The first read queries the kernel; successful __afl_sched_setparam calls
 * refresh the cache. This avoids repeated scheduler reads during ceiling use.
 *
 * Each translation unit has its own TLS cache. A priority change through one
 * unit does not update another unit's cache, and external scheduler changes
 * bypass it too. Keep ceiling borrow/restore operations in one translation
 * unit and route scheduling changes through that unit's scheduling helper.
 */
typedef struct
{
    int policy;   // the cached policy, meaningful once ready is set
    int priority; // the cached priority, meaningful once ready is set
    int ready;    // 0 until the pair has been read from the kernel once
} __afl_sched_cache_t;

/* __afl_sched_cache hands out the scheduling mirror of the calling thread. */
static inline __afl_sched_cache_t *__afl_sched_cache(void)
{
    static __thread __afl_sched_cache_t cache;

    return &cache;
}

/*
 * __afl_sched_getparam reads the scheduling policy and priority of the calling
 * thread; it returns 0 on success and a positive errno otherwise, the
 * convention of the pthread_getschedparam it replaces. The first call of a
 * thread asks the kernel through the raw sched_getscheduler and sched_getparam
 * system calls on the cached __afl_gettid() and fills the mirror, every later
 * call answers from the mirror without a system call, see the comment above
 * it. The policy is the sched_getscheduler result with the SCHED_RESET_ON_FORK
 * flag masked off, so a thread carrying only that flag reports its plain
 * policy. A failed read leaves the mirror unfilled, so the next call asks the
 * kernel again instead of caching the failure.
 */
static inline int __afl_sched_getparam(int *policy, int *priority)
{
    __afl_sched_cache_t *cache = __afl_sched_cache();
    struct sched_param param;
    long scheduler;
    long tid;
    long ret;

    if (__afl_likely(cache->ready != 0)) {
        *policy = cache->policy;
        *priority = cache->priority;

        return 0;
    }

    tid = (long) __afl_gettid();

    scheduler = __afl_syscall(__NR_sched_getscheduler, tid, 0, 0, 0);

    if (__afl_unlikely(scheduler < 0))
        return __afl_sched_error(scheduler);

    ret = __afl_syscall(__NR_sched_getparam, tid, (long) (uintptr_t) &param, 0, 0);

    if (__afl_unlikely(ret < 0))
        return __afl_sched_error(ret);

    cache->policy = (int) scheduler & ~__AFL_SCHED_RESET_ON_FORK;
    cache->priority = param.sched_priority;
    cache->ready = 1;

    *policy = cache->policy;
    *priority = cache->priority;

    return 0;
}

/*
 * __afl_sched_setparam applies a scheduling policy and priority to the calling
 * thread through the raw sched_setscheduler system call on the cached
 * __afl_gettid(); it returns 0 on success and a positive errno otherwise, the
 * convention of the pthread_setschedparam it replaces. Policy and parameters
 * change in one call, so the elevation cannot be interrupted between them. A
 * successful call is what the thread now runs at, so it also writes the mirror
 * __afl_sched_getparam answers from, which keeps the two in step without a
 * read back; a refused call leaves the mirror describing the parameters the
 * thread still has. The libc cache of the scheduling parameters in the thread
 * control block is not updated; see the comment above __afl_pc_borrow for the
 * consequence.
 */
static inline int __afl_sched_setparam(int policy, int priority)
{
    __afl_sched_cache_t *cache = __afl_sched_cache();
    struct sched_param param;
    long ret;

    param.sched_priority = priority;

    ret = __afl_syscall(__NR_sched_setscheduler, (long) __afl_gettid(), (long) policy, (long) (uintptr_t) &param, 0);

    if (__afl_unlikely(ret != 0))
        return __afl_sched_error(ret);

    cache->policy = policy;
    cache->priority = priority;
    cache->ready = 1;

    return 0;
}

/*
 * __afl_pc_borrow saves the new holder's scheduling parameters and raises it
 * to the mapped ceiling while the PI lock word remains held. Save and restore
 * use the same per-thread scheduling cache and raw syscalls.
 *
 * These calls do not update libc's scheduling cache, so pthread scheduling
 * queries can report pre-borrow parameters during a temporary boost.
 * EPERM or EACCES disables later boost attempts for this thread. Other failures
 * produce debug diagnostics. In either case the caller keeps the acquired PI
 * mutex without a boost; only a successful elevation needs restoration.
 */
static inline void __afl_pc_borrow(afl_mutex_pc_t *mutex)
{
    static __thread int boost_possible = 1; // 0 once this thread has been refused the elevation
    int priority;
    int policy;
    int target;
    int error;

    /*
     * Remember a permission refusal for this thread and translation unit.
     * Save parameters only when an elevation is needed; an already sufficient
     * priority requires no scheduler write or later restoration.
     */
    if (__afl_unlikely(boost_possible == 0))
        return;

    error = __afl_sched_getparam(&policy, &priority);

    if (__afl_unlikely(error != 0)) {
        __afl_debug(1, "A priority ceiling mutex could not read the parameters of its new holder.");
        return;
    }

    error = __afl_pc_priority(__atomic_load_n(&mutex->ceiling, __ATOMIC_RELAXED), &target);

    if (__afl_unlikely(error != 0)) {
        __afl_debug(1, "A priority ceiling mutex carries a ceiling outside the real time range.");
        return;
    }

    // at or above the ceiling already: there is nothing to borrow and nothing to restore
    if (priority >= target)
        return;

    __atomic_store_n(&mutex->saved_policy, policy, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->saved_prio, priority, __ATOMIC_RELAXED);

    // only the real time policies carry a priority that can be raised; a thread
    // on another policy asks for SCHED_FIFO at the ceiling, the way the boost of
    // glibc does, and gets its own policy back from the saved parameters
    error = __afl_sched_setparam((policy == SCHED_FIFO || policy == SCHED_RR) ? policy : SCHED_FIFO, target);

    if (__afl_likely(error == 0)) {
        __atomic_store_n(&mutex->borrowed, 1, __ATOMIC_RELAXED);
        return;
    }

    if (error == EPERM || error == EACCES)
        boost_possible = 0;
    else
        __afl_debug(1, "The kernel refused the elevation of a priority ceiling mutex holder.");
}

/*
 * __afl_pc_restore is the release side of the documented protocol. It runs
 * while the lock word is still held, so the parameters of this holder are put
 * back before the word can pass to the next one, which is what makes the
 * save/restore pair deterministic. Only a holder that borrowed has something
 * to restore. Restoring the parameters of the calling thread to the values
 * that same thread read moments before cannot fail for permissions; the
 * return is checked and reported under AFL_DEBUG like every other one.
 */
static inline void __afl_pc_restore(afl_mutex_pc_t *mutex)
{
    if (__afl_likely(__atomic_load_n(&mutex->borrowed, __ATOMIC_RELAXED) == 0))
        return;

    __atomic_store_n(&mutex->borrowed, 0, __ATOMIC_RELAXED);

    if (
      __afl_sched_setparam(
        __atomic_load_n(&mutex->saved_policy, __ATOMIC_RELAXED), __atomic_load_n(&mutex->saved_prio, __ATOMIC_RELAXED)
      )
      != 0
    )
        __afl_debug(1, "A priority ceiling mutex could not restore the parameters of its holder.");
}

/*
 * afl_mutex_pc_init resets the mutex and attaches the given ceiling to it, on
 * the scale documented above the type; like every other init function of this
 * header it is a reset, not a guard, so the caller must not initialize a
 * mutex somebody still holds. It returns 0, EINVAL when the mutex pointer or
 * the ceiling is not valid, and the error of the kernel, propagated as an int
 * errno value, when the probe of the priority inheriting futex is declined
 * (ENOSYS or EPERM as it stands): the caller that needs the ceiling has to
 * take the refusal as the answer that PI is not available here, the mutex is
 * never silently degraded to a non-PI lock. The probe is one real
 * FUTEX_LOCK_PI/FUTEX_UNLOCK_PI pair on a private word on the stack and not
 * on the mutex itself: an init may be handed memory that was never used
 * before, and the kernel must never be asked to interpret such a word.
 */
static inline int afl_mutex_pc_init(afl_mutex_pc_t *mutex, int ceiling)
{
    uint32_t probe = AFL_UNLOCKED;
    int error;
    long ret;

    if (__afl_unlikely(mutex == NULL))
        return EINVAL;

    error = __afl_pc_priority(ceiling, NULL);

    if (__afl_unlikely(error != 0))
        return error;

    ret = __afl_syscall(__NR_futex, (intptr_t) &probe, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

    if (__afl_unlikely(ret < 0)) {
        __afl_debug(1, "The kernel declined the priority inheriting futex; the mutex was not initialized.");
        return (int) -ret;
    }

    ret = __afl_syscall(__NR_futex, (intptr_t) &probe, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

    if (__afl_unlikely(ret < 0)) {
        __afl_debug(1, "The kernel declined the release of the priority inheriting probe.");
        return (int) -ret;
    }

    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    __atomic_store_n(&mutex->ceiling, ceiling, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->saved_policy, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->saved_prio, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->borrowed, 0, __ATOMIC_RELAXED);

    return 0;
}

/*
 * afl_mutex_pc_destroy resets a priority ceiling mutex, ceiling and all, back
 * to the state of the static initializer. Destroying one that a thread still
 * holds is reported with AFL_DEBUG and otherwise ignored, the way the other
 * destroy functions of this header behave.
 */
static inline int afl_mutex_pc_destroy(afl_mutex_pc_t *mutex)
{
    if (__afl_unlikely(mutex == NULL))
        return EINVAL;

    __afl_debug(
      __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED) != AFL_UNLOCKED,
      "An attempt was made to destroy a priority ceiling mutex that is still held."
    );

    __atomic_store_n(&mutex->lock, AFL_UNLOCKED, __ATOMIC_RELEASE);
    __atomic_store_n(&mutex->ceiling, AFL_MUTEX_PC_CEILING_DEFAULT, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->saved_policy, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->saved_prio, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mutex->borrowed, 0, __ATOMIC_RELAXED);

    return 0;
}

/*
 * afl_mutex_pc_lock acquires the PI mutex and attempts the mapped priority
 * ceiling for this hold. EINTR and EAGAIN from FUTEX_LOCK_PI are retried;
 * other kernel errors return as positive errno values. Only a successful
 * acquire permits ceiling borrowing. Boost failures leave the PI mutex held
 * without a boost, as described by __afl_pc_borrow.
 * Recursive acquisition returns EDEADLOCK.
 */
static inline int afl_mutex_pc_lock(afl_mutex_pc_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();
    __afl_spin_backoff_t backoff;
    long ret;

    if (__afl_unlikely(mutex == NULL))
        return EINVAL;

    /*
     * Fast path: one compare exchange from the free value, see
     * afl_mutex_pi_lock. The ceiling is borrowed after the word is won, so the
     * save of the parameters belongs to the holder alone.
     */
    if (__afl_likely(__atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))) {
        __afl_pc_borrow(mutex);
        return 0;
    }

    __afl_debug(tid == (lock & AFL_TID_MASK), "An attempt was made to lock an already owned mutex.");

    if (__afl_unlikely(tid == (lock & AFL_TID_MASK)))
        return EDEADLOCK;

    __afl_spin_backoff_init(&backoff);

    for (int spin = 0; spin < AFL_SPIN_LIMIT; spin++) {
        if (
          lock == AFL_UNLOCKED
          && __atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
        ) {
            __afl_pc_borrow(mutex);
            return 0;
        }

        __afl_spin_backoff(&backoff);
        lock = __atomic_load_n(&mutex->lock, __ATOMIC_RELAXED);
    }

    for (;;) {
        ret = __afl_syscall(__NR_futex, (intptr_t) &mutex->lock, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

        if (__afl_likely(ret == 0)) {
            __atomic_thread_fence(__ATOMIC_ACQUIRE);
            break;
        }

        // -EAGAIN: the word changed under the call, -EINTR: a signal cut the wait
        // short; both are benign and the loop simply asks again.
        if (ret == -EAGAIN || ret == -EINTR)
            continue;

        __afl_debug(1, "FUTEX_LOCK_PI failed on a priority ceiling mutex.");

        return (int) -ret;
    }

    __afl_pc_borrow(mutex);

    return 0;
}

/*
 * afl_mutex_pc_trylock attempts to take the priority ceiling mutex without
 * waiting: EBUSY when the word shows a holder or waiters - including this
 * thread's own hold, the mutex is not recursive - or when the word changed
 * under the attempt, 0 with the ceiling borrowed on success.
 */
static inline int afl_mutex_pc_trylock(afl_mutex_pc_t *mutex)
{
    uint32_t lock = AFL_UNLOCKED;
    uint32_t tid = __afl_gettid();

    if (__afl_unlikely(mutex == NULL))
        return EINVAL;

    if (!__atomic_compare_exchange_n(&mutex->lock, &lock, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return EBUSY;

    __afl_pc_borrow(mutex);

    return 0;
}

/*
 * afl_mutex_pc_unlock releases the priority ceiling mutex and hands the
 * priority back first: the saved parameters are restored while the word is
 * still held, so the restore of this holder is sequenced before the borrow of
 * the next one and the pair is deterministic. A release by a thread that does
 * not own the mutex is refused with EPERM, like every owner tracking variant.
 * When the word still shows waiters the kernel has to move the PI state, and
 * the error of FUTEX_UNLOCK_PI is propagated as an int errno value.
 */
static inline int afl_mutex_pc_unlock(afl_mutex_pc_t *mutex)
{
    uint32_t lock;
    uint32_t tid = __afl_gettid();
    long ret;

    if (__afl_unlikely(mutex == NULL))
        return EINVAL;

    __atomic_load(&mutex->lock, &lock, __ATOMIC_RELAXED);

    __afl_debug(tid != (lock & AFL_TID_MASK), "An attempt was made to unlock a mutex from a non-owner thread.");

    if (__afl_unlikely(tid != (lock & AFL_TID_MASK)))
        return EPERM;

    __afl_pc_restore(mutex);

    if (__atomic_compare_exchange_n(&mutex->lock, &tid, AFL_UNLOCKED, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        return 0;

    __atomic_thread_fence(__ATOMIC_RELEASE);
    ret = __afl_syscall(__NR_futex, (intptr_t) &mutex->lock, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0);

    if (__afl_unlikely(ret < 0)) {
        __afl_debug(1, "FUTEX_UNLOCK_PI failed on a priority ceiling mutex.");
        return (int) -ret;
    }

    return 0;
}

/*
 * afl_mutex_pc_setceiling replaces the ceiling of a mutex that nobody holds,
 * which is the guard that makes a change safe: EINVAL when the mutex pointer
 * or the ceiling is not valid (validated before the state of the word is
 * consulted), EBUSY while the word shows a holder or waiters, 0 otherwise. An
 * acquisition that won the word just before this call borrows the ceiling that
 * was in effect while it was being taken; the new one applies from the next
 * acquisition on.
 */
static inline int afl_mutex_pc_setceiling(afl_mutex_pc_t *mutex, int ceiling)
{
    int error;

    if (__afl_unlikely(mutex == NULL))
        return EINVAL;

    error = __afl_pc_priority(ceiling, NULL);

    if (__afl_unlikely(error != 0))
        return error;

    if (__afl_unlikely(__atomic_load_n(&mutex->lock, __ATOMIC_ACQUIRE) != AFL_UNLOCKED))
        return EBUSY;

    __atomic_store_n(&mutex->ceiling, ceiling, __ATOMIC_RELEASE);

    return 0;
}

/*
 * afl_mutex_pc_getceiling stores the current ceiling of the mutex in
 * *ceiling and returns 0, or EINVAL when either pointer is NULL. Reading the
 * ceiling of a held mutex is safe: the value is the one the call observed,
 * and a concurrent afl_mutex_pc_setceiling can only replace it while the mutex
 * is free.
 */
static inline int afl_mutex_pc_getceiling(const afl_mutex_pc_t *mutex, int *ceiling)
{
    if (__afl_unlikely(mutex == NULL || ceiling == NULL))
        return EINVAL;

    *ceiling = __atomic_load_n(&mutex->ceiling, __ATOMIC_ACQUIRE);

    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __AFL_H */
