/*
 * afl_thread.h supplies workers for the repository's tests and benchmarks.
 * Raw clone creates threads; futexes implement join. The stack and TLS share
 * one mmap allocation, owned by the handle and freed by join. Detached raw
 * threads retain that allocation until process exit.
 *
 * TLS setup reproduces the loaded modules' offsets from the creating thread's
 * DTV. Each block starts from its PT_TLS image, not the parent's live data,
 * so thread-local caches and other mutable state are not copied into children.
 * Initialization uses dl_iterate_phdr and dlsym and depends on libc TLS details.
 * Creation, join and detach then use raw system calls.
 *
 * The raw backend supports x86-64 and AArch64. ThreadSanitizer builds use
 * pthread creation, join and detach so the sanitizer can track worker lifetimes.
 * This thread layer is separate from the lock API in afl.h.
 */
#ifndef __AFL_THREAD_H
#define __AFL_THREAD_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <elf.h>

#include "afl.h"

/*
 * The ELF class of the running process, the spelling <link.h> would give
 * through ElfW; the header carries it because it does not include that header.
 */
#if defined(__LP64__) || defined(_LP64) || (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8)
#define __AFL_ELF(type) Elf64_##type
#else
#define __AFL_ELF(type) Elf32_##type
#endif

/*
 * The module walk, declared here instead of through <link.h>: the libc header
 * announces struct dl_phdr_info and dl_iterate_phdr only under _GNU_SOURCE,
 * which is a command line decision this header cannot make for its consumers,
 * and the layout below is a stable part of the ABI (debuggers read it). The
 * alias keeps the declaration from colliding with the libc one in a translation
 * unit that does define _GNU_SOURCE.
 */
struct __afl_dl_phdr_info
{
    __AFL_ELF(Addr) dlpi_addr;
    const char *dlpi_name;
    const __AFL_ELF(Phdr) * dlpi_phdr;
    __AFL_ELF(Half) dlpi_phnum;
    unsigned long long dlpi_adds;
    unsigned long long dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
};

extern int __afl_dl_iterate_phdr(int (*callback)(struct __afl_dl_phdr_info *, size_t, void *), void *data) __asm__(
  "dl_iterate_phdr"
);

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Whether the layer is compiled on top of pthread. ThreadSanitizer can only
 * track threads it created itself, so its build keeps the pthread backend; see
 * the comment at the top of the file.
 */
#if defined(__SANITIZE_THREAD__)
#define __AFL_THREAD_WITH_PTHREAD 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __AFL_THREAD_WITH_PTHREAD 1
#else
#define __AFL_THREAD_WITH_PTHREAD 0
#endif
#else
#define __AFL_THREAD_WITH_PTHREAD 0
#endif

#if __AFL_THREAD_WITH_PTHREAD
#include <pthread.h>
#endif

/*
 * One mmap'd zone per thread: the stack first, then the static TLS blocks, then
 * the thread control block and the state this layer keeps about the thread. The
 * thread pointer has to sit where the process wide offsets say it sits, so the
 * zone is laid out around those offsets; the constants below size the parts
 * that do not depend on the module table.
 */
#define __AFL_THREAD_STACK_SIZE  (1u << 20) /* 1 MiB, like the libc default */
#define __AFL_THREAD_TCB_SIZE    128        /* the libc control block, with room to grow */
#define __AFL_THREAD_STATE_OFF   128        /* this layer's state, right after the control block */
#define __AFL_THREAD_DTV_OFF     192        /* the dynamic thread vector, right after the state */
#define __AFL_THREAD_MAX_MODULES 64         /* objects with a TLS block the layer can carry */
#define __AFL_THREAD_DTV_ENTRY   16         /* sizeof the libc dtv_t, two pointers */

/*
 * afl_thread_t owns a created thread's handle. Join waits for completion and
 * frees the raw backend's stack/TLS mapping; detach relinquishes that cleanup
 * and retains the mapping until process exit. Do not copy or reuse live handles.
 */
typedef struct
{
    void *zone;
    size_t zone_size;
    int *tid;
} afl_thread_t;

#if !__AFL_THREAD_WITH_PTHREAD

/*
 * The clone flags of a POSIX thread. The values are the generic ones of Linux
 * and the same on x86-64 and aarch64; the header carries them because it
 * includes no GNU extension header. CLONE_SETTLS installs the thread pointer,
 * the remaining sharing flags are the pthread set.
 */
#define __AFL_THREAD_CLONE_VM             0x00000100
#define __AFL_THREAD_CLONE_FS             0x00000200
#define __AFL_THREAD_CLONE_FILES          0x00000400
#define __AFL_THREAD_CLONE_SIGHAND        0x00000800
#define __AFL_THREAD_CLONE_THREAD         0x00010000
#define __AFL_THREAD_CLONE_SYSVSEM        0x00040000
#define __AFL_THREAD_CLONE_SETTLS         0x00080000
#define __AFL_THREAD_CLONE_PARENT_SETTID  0x00100000
#define __AFL_THREAD_CLONE_CHILD_CLEARTID 0x00200000

#define __AFL_THREAD_CLONE_FLAGS                                                                           \
    (__AFL_THREAD_CLONE_VM | __AFL_THREAD_CLONE_FS | __AFL_THREAD_CLONE_FILES | __AFL_THREAD_CLONE_SIGHAND \
     | __AFL_THREAD_CLONE_THREAD | __AFL_THREAD_CLONE_SYSVSEM | __AFL_THREAD_CLONE_SETTLS                  \
     | __AFL_THREAD_CLONE_PARENT_SETTID | __AFL_THREAD_CLONE_CHILD_CLEARTID)

/* The mmap the zone allocator calls, again without a libc header. */
#define __AFL_THREAD_PROT_READ     0x1
#define __AFL_THREAD_PROT_WRITE    0x2
#define __AFL_THREAD_MAP_PRIVATE   0x02
#define __AFL_THREAD_MAP_ANONYMOUS 0x20

/*
 * __afl_thread_syscall6 issues a system call with six arguments, the shape mmap
 * needs; __afl_syscall of afl.h carries four and cannot. Each supported
 * architecture spells the argument registers its own way.
 */
#if defined(__x86_64__) || defined(__amd64__)
static inline long __afl_thread_syscall6(long number, long p1, long p2, long p3, long p4, long p5, long p6)
{
    long ret;
    register long r10 __asm__("r10") = p4;
    register long r8 __asm__("r8") = p5;
    register long r9 __asm__("r9") = p6;

    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"(p1), "S"(p2), "d"(p3), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
}
#elif defined(__aarch64__)
static inline long __afl_thread_syscall6(long number, long p1, long p2, long p3, long p4, long p5, long p6)
{
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = p1;
    register long x1 __asm__("x1") = p2;
    register long x2 __asm__("x2") = p3;
    register long x3 __asm__("x3") = p4;
    register long x4 __asm__("x4") = p5;
    register long x5 __asm__("x5") = p6;

    asm volatile("svc 0" : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "cc", "memory");
    return x0;
}
#else
#error "afl_thread.h needs the six argument system call of x86-64 or aarch64; the 32 bit targets are not supported"
#endif

/*
 * The pristine TLS image of one loaded object, and where the object expects its
 * block to sit relative to the thread pointer. A negative rel is the usual case:
 * the static TLS blocks of a variant II target live below the control block.
 */
typedef struct
{
    size_t modid;
    long rel;
    size_t memsz;
    size_t filesz;
    const unsigned char *image;
} __afl_thread_module_t;

/*
 * What a creating thread leaves for its child: the function to run, its
 * argument, and the two words the join reads. `tid` is written by the kernel
 * when the thread is created (CLONE_PARENT_SETTID) and cleared by the kernel
 * when it has finished (CLONE_CHILD_CLEARTID), with a futex wake: the join
 * waits for the clear, so it can free the zone only once the thread that was
 * standing on it is really gone. `detached` says that no joiner will come.
 */
typedef struct
{
    void (*fn)(void *);
    void *arg;
    int tid;
    int detached;
} __afl_thread_state_t;

/*
 * The process wide module table and the geometry the zone allocator needs, all
 * filled once by __afl_thread_modules_init and read only afterwards.
 */
static __afl_thread_module_t __afl_thread_modules[__AFL_THREAD_MAX_MODULES] __attribute__((unused));
static size_t __afl_thread_module_count __attribute__((unused));
static size_t __afl_thread_dtv_count __attribute__((unused)); /* highest module id seen */
static size_t __afl_thread_tls_span __attribute__((unused));  /* thread pointer minus the lowest block */
static long __afl_thread_tls_low __attribute__((unused));     /* lowest offset, <= 0 */
static size_t __afl_thread_guard[2] __attribute__((unused));  /* stack and pointer guard of the init thread */
static size_t __afl_thread_dtv_generation __attribute__((unused));
static size_t __afl_thread_tid_offset __attribute__((unused)); /* the libc descriptor's tid field, 0 when unknown */
static uintptr_t __afl_thread_init_tp __attribute__((unused));
static uintptr_t __afl_thread_init_dtv __attribute__((unused));
static int __afl_thread_init_error __attribute__((unused));
static afl_once_t __afl_thread_init_once __attribute__((unused)) = AFL_ONCE_INIT;

/*
 * __libc_single_threaded controls libc's single-thread fast paths. Clear it
 * before starting raw-clone workers so libc uses its internal locks.
 * The weak reference names the executable's copy; RTLD_NEXT resolves libc's
 * own storage when a copy relocation gives the two distinct addresses.
 */
extern bool __libc_single_threaded __attribute__((weak));

/*
 * dlsym under a private name, so a consumer that includes <dlfcn.h> keeps its
 * own declaration. RTLD_NEXT is the load order search that skips the calling
 * object, which is exactly what reaches past the copy relocation.
 */
extern void *__afl_thread_dlsym(void *handle, const char *symbol) __asm__("dlsym");

#define __AFL_THREAD_RTLD_NEXT ((void *) -1L)

static void *__afl_thread_single_threaded_libc __attribute__((unused));
static void (*__afl_thread_enable_locks)(void) __attribute__((unused));

/*
 * __afl_thread_mark_multithreaded enables libc locking before raw-clone workers
 * can call it. Clear both the executable's and libc's single-threaded flags,
 * and call _IO_enable_locks to enable locking on existing streams.
 * RTLD_NEXT resolves symbols past executable copy relocations. Missing symbols
 * are skipped; _IO_enable_locks is a private libc interface.
 */
static inline void __afl_thread_mark_multithreaded(void)
{
    uintptr_t tp;

    __afl_thread_pointer(tp);

    /*
     * The thread control block of the creating thread carries the same flag:
     * the libc's SINGLE_THREAD_P macro reads either the global below or the
     * multiple_threads field of the calling thread's control block, depending
     * on the architecture, and the creating thread (usually the main one) is
     * left marked single-threaded by the process startup. The field sits right
     * after the two pointers and the self pointer of the block, and this layer
     * writes it for every thread it creates as it builds the block.
     */
    ((int *) tp)[6] = 1;

    __afl_thread_single_threaded_libc = __afl_thread_dlsym(__AFL_THREAD_RTLD_NEXT, "__libc_single_threaded");

    if (__afl_thread_single_threaded_libc != NULL)
        *(volatile signed char *) __afl_thread_single_threaded_libc = 0;

    if (&__libc_single_threaded != NULL)
        __libc_single_threaded = false;

    __afl_thread_enable_locks = (void (*)(void)) __afl_thread_dlsym(__AFL_THREAD_RTLD_NEXT, "_IO_enable_locks");

    if (__afl_thread_enable_locks != NULL)
        __afl_thread_enable_locks();

    /*
     * The libc keeps the kernel thread id of a thread in its own descriptor,
     * next to the control block, and parts of it read that field back through
     * THREAD_GETMEM instead of asking the kernel: pthread_rwlock_t compares the
     * recorded writer against it, for example. The descriptor is private to the
     * libc, so the offset of the field is found here rather than spelled out:
     * the creating thread's own id is unique in its descriptor, so the scan
     * below finds the field, and every thread the layer makes then writes its
     * own id there. A descriptor where the id is absent or ambiguous leaves the
     * offset zero, and the layer skips the write.
     */
    {
        int own = (int) __afl_gettid();
        size_t found = 0, matches = 0;

        for (size_t offset = 0; offset + sizeof(int) <= 2048; offset += sizeof(int)) {
            if (*(int *) (tp + offset) == own) {
                found = offset;
                matches++;
            }
        }

        if (matches == 1)
            __afl_thread_tid_offset = found;
    }
}

/*
 * __afl_thread_tp reads the thread pointer of the calling thread, the value the
 * layer installs with CLONE_SETTLS and reads back from the child's control
 * block.
 */
static inline uintptr_t __afl_thread_tp(void)
{
    uintptr_t tp;

    __afl_thread_pointer(tp);

    return tp;
}

/*
 * __afl_thread_round_up rounds size up to the next multiple of alignment, both
 * powers of two, the shape the zone allocator needs.
 */
static inline size_t __afl_thread_round_up(size_t size, size_t alignment)
{
    return (size + alignment - 1u) & ~(alignment - 1u);
}

/*
 * __afl_thread_entry is the first C code a new thread runs. It is reached by a
 * branch from __afl_thread_clone below, never by a call, so it never returns;
 * it finds its state through the thread pointer the layer installed. The branch
 * in the assembly names the symbol, and the attributes keep it alive, out of
 * line and non-returning.
 */
static void __afl_thread_entry(void) __attribute__((noreturn, noinline, used));
static void __afl_thread_entry(void)
{
    uintptr_t tp = __afl_thread_tp();
    __afl_thread_state_t *state = (__afl_thread_state_t *) (tp + __AFL_THREAD_STATE_OFF);

    /* The libc's own descriptor field for this thread's id, when the layer found it. */
    if (__afl_thread_tid_offset != 0)
        *(int *) (tp + __afl_thread_tid_offset) = (int) __afl_gettid();

    state->fn(state->arg);

    /*
     * End this thread with the raw exit system call: the libc exit would run
     * the process exit handlers, which belong to the process and not to a
     * thread. It is the kernel that tells the joiner, too: CLONE_CHILD_CLEARTID
     * clears the tid word and wakes its futex once the thread is really gone,
     * and that clear is what makes freeing the zone safe.
     */
    __afl_syscall(__NR_exit, 0, 0, 0, 0);

    __builtin_unreachable();
}

/*
 * __afl_thread_clone issues the clone of __AFL_THREAD_CLONE_FLAGS and branches
 * the child, and only the child, to __afl_thread_entry; the creating thread
 * gets the kernel's return value. The branch has to live in this assembly,
 * because after the system call the child is on a brand new stack while the
 * calling C function still has the frame of the creating thread: any C code
 * between here and the entry would read the wrong stack.
 */
static inline long __afl_thread_clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long tls)
{
#if defined(__x86_64__) || defined(__amd64__)
    long ret;
    register long r10 __asm__("r10") = (long) (intptr_t) ctid;
    register long r8 __asm__("r8") = (long) tls;

    asm volatile("syscall\n\t"
                 "testq %%rax, %%rax\n\t"
                 "jz __afl_thread_entry\n\t"
                 : "=a"(ret)
                 : "a"((long) __NR_clone), "D"((long) flags), "S"((long) (intptr_t) child_stack),
                   "d"((long) (intptr_t) ptid), "r"(r10), "r"(r8)
                 : "rcx", "r11", "memory");
    return ret;
#else
    register long x0 __asm__("x0") = (long) flags;
    register long x1 __asm__("x1") = (long) (intptr_t) child_stack;
    register long x2 __asm__("x2") = (long) (intptr_t) ptid;
    register long x3 __asm__("x3") = (long) (intptr_t) ctid;
    register long x4 __asm__("x4") = (long) tls;
    register long x8 __asm__("x8") = __NR_clone;

    asm volatile("svc 0\n\t"
                 "cbnz %%x0, 1f\n\t"
                 "b __afl_thread_entry\n\t"
                 "1:\n\t"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                 : "cc", "memory");
    return x0;
#endif
}

/*
 * __AFL_THREAD_STACK_TOP is the first stack address the child gets. On x86-64 a
 * function entered by a branch has to see the alignment a call would leave,
 * eight bytes below a 16 byte boundary; aarch64 only wants the 16 byte
 * alignment. The stack base is page aligned, so the x86-64 term is exact.
 */
#if defined(__x86_64__) || defined(__amd64__)
#define __AFL_THREAD_STACK_TOP(base) ((void *) ((uintptr_t) (base) - 8u))
#else
#define __AFL_THREAD_STACK_TOP(base) ((void *) ((uintptr_t) (base) & ~(uintptr_t) 15u))
#endif

/*
 * __afl_thread_collect is the dl_iterate_phdr callback of the module table. An
 * object with a TLS module id contributes one row: its thread pointer offset
 * and its pristine image.
 *
 * The offset comes from dlpi_tls_data, the address the dynamic linker gave this
 * module's block in the calling thread, which is the only source for a module
 * whose block is static: such a block is well below the thread pointer and its
 * DTV slot stays empty, because nothing looks it up through the DTV.
 *
 * The image is the object's PT_TLS segment in the loaded object, at
 * dlpi_addr + p_vaddr, and it has to be that copy and not the bytes in the
 * file: the segment holds pointers that the dynamic linker relocates at load
 * time, and a raw file image would hand every new thread the link time offsets
 * of those pointers instead of their addresses. This is the same source the
 * libc copies from for its own threads.
 *
 * A module id the table cannot hold, a missing block, or a block that does not
 * lie below the control block is an error, and a non zero answer stops the walk.
 */
static int __afl_thread_collect(struct __afl_dl_phdr_info *info, size_t size, void *data)
{
    const __AFL_ELF(Phdr) *tls = NULL;
    size_t modid = info->dlpi_tls_modid;
    uintptr_t block = (uintptr_t) info->dlpi_tls_data;
    long rel;

    (void) size;
    (void) data;

    for (__AFL_ELF(Half) i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_TLS) {
            tls = &info->dlpi_phdr[i];
            break;
        }
    }

    /*
     * The main executable reports module id zero in some loaders even when it
     * carries a TLS block; it is the first module, id one, by definition.
     */
    if (modid == 0) {
        if (tls == NULL)
            return 0;

        modid = 1;
    }

    if (modid >= __AFL_THREAD_MAX_MODULES || tls == NULL) {
        __afl_thread_init_error = E2BIG;
        return 1;
    }

    if (block == 0) {
        __afl_thread_init_error = EINVAL;
        return 1;
    }

    rel = (long) block - (long) __afl_thread_init_tp;

    /* Every static TLS block of a variant II target lies below the control block. */
    if (rel + (long) tls->p_memsz > 0) {
        __afl_thread_init_error = EINVAL;
        return 1;
    }

    if (__afl_thread_module_count == 0 || rel < __afl_thread_tls_low)
        __afl_thread_tls_low = rel;

    __afl_thread_modules[__afl_thread_module_count].modid = modid;
    __afl_thread_modules[__afl_thread_module_count].rel = rel;
    __afl_thread_modules[__afl_thread_module_count].memsz = tls->p_memsz;
    __afl_thread_modules[__afl_thread_module_count].filesz = tls->p_filesz;
    __afl_thread_modules[__afl_thread_module_count].image = (const unsigned char *) (info->dlpi_addr + tls->p_vaddr);

    if (modid > __afl_thread_dtv_count)
        __afl_thread_dtv_count = modid;

    __afl_thread_module_count++;

    return 0;
}

/*
 * __afl_thread_modules_init builds the process wide module table once, on the
 * creating thread, before any other thread exists, so its statics need no lock;
 * afl_once serializes the call all the same. It reads the geometry off the
 * creating thread's own control block and DTV, then walks the loaded objects.
 */
static inline void __afl_thread_modules_init(void)
{
    unsigned char **dtv;

    __afl_thread_init_tp = __afl_thread_tp();
    __afl_thread_init_dtv = __afl_thread_init_tp + 8;

    dtv = (unsigned char **) __afl_thread_init_dtv;

    __afl_thread_dtv_generation = (size_t) dtv[0];
    __afl_thread_guard[0] = ((size_t *) __afl_thread_init_tp)[4];
    __afl_thread_guard[1] = ((size_t *) __afl_thread_init_tp)[5];

    __afl_thread_mark_multithreaded();

    if (__afl_dl_iterate_phdr(__afl_thread_collect, NULL) != 0 && __afl_thread_init_error == 0)
        __afl_thread_init_error = EINVAL;

    if (__afl_thread_init_error != 0)
        return;

    __afl_thread_tls_span = (size_t) (0 - __afl_thread_tls_low);
}

/*
 * __afl_thread_pad is the alignment filler that makes the thread pointer of a
 * zone a multiple of 64, the widest alignment the static TLS blocks use.
 */
static inline size_t __afl_thread_pad(void)
{
    return (64u - (__afl_thread_tls_span & 63u)) & 63u;
}

/*
 * __afl_thread_above is the part of a zone that sits at and above the thread
 * pointer: the control block, the state, and the DTV with one entry per module
 * id plus the generation word.
 */
static inline size_t __afl_thread_above(void)
{
    size_t above = __AFL_THREAD_DTV_OFF + __AFL_THREAD_DTV_ENTRY * (__afl_thread_dtv_count + 1u);

    /*
     * The libc's descriptor field for the thread id has to be inside the zone
     * too, at the offset the scan found; the rest of the descriptor is never
     * read by the layer or by the libc code the layer is used with.
     */
    if (__afl_thread_tid_offset != 0 && above < __afl_thread_tid_offset + sizeof(int))
        above = __afl_thread_tid_offset + sizeof(int);

    return above;
}

/*
 * __afl_thread_zone_size is the mapped length of a zone, page rounded.
 */
static inline size_t __afl_thread_zone_size(void)
{
    return __afl_thread_round_up(
      __AFL_THREAD_STACK_SIZE + __afl_thread_pad() + __afl_thread_tls_span + __afl_thread_above(), 4096u
    );
}

/*
 * __afl_thread_tp_of is the thread pointer of a zone: the control block sits
 * after the stack, the alignment filler and the TLS blocks.
 */
static inline uintptr_t __afl_thread_tp_of(void *base)
{
    return (uintptr_t) base + __AFL_THREAD_STACK_SIZE + __afl_thread_pad() + __afl_thread_tls_span;
}

/*
 * __afl_thread_zone maps and builds one thread's zone and answers its base, or
 * NULL with errno set. It lays the stack first, the pristine images at the
 * offsets the module table records, then the control block with a DTV of this
 * thread's own. The table has to be initialized first.
 */
static inline void *__afl_thread_zone(__afl_thread_state_t **state_out, unsigned long *tls_out, void *stack_out[1])
{
    size_t mapped = __afl_thread_zone_size();
    unsigned char *base;
    uintptr_t tp;
    size_t i;

    base = (unsigned char *) __afl_thread_syscall6(
      __NR_mmap, 0, (long) mapped, __AFL_THREAD_PROT_READ | __AFL_THREAD_PROT_WRITE,
      __AFL_THREAD_MAP_PRIVATE | __AFL_THREAD_MAP_ANONYMOUS, -1, 0
    );

    if ((long) base < 0) {
        errno = (int) -(long) base;
        return NULL;
    }

    tp = __afl_thread_tp_of(base);

    /* The pristine images, at the offsets the dynamic linker gave them. */
    for (i = 0; i < __afl_thread_module_count; i++) {
        const __afl_thread_module_t *module = &__afl_thread_modules[i];

        if (module->filesz != 0)
            __builtin_memcpy((void *) (uintptr_t) ((long) tp + module->rel), module->image, module->filesz);
    }

    /*
     * The control block. The self pointer, the DTV and the flags are the
     * layer's; the stack and pointer guards are process wide secrets and are
     * copied from the creating thread, as the libc copies them for a pthread.
     */
    {
        uintptr_t *tcb = (uintptr_t *) tp;

        tcb[0] = tp;                        /* tcb, the pointer to itself */
        tcb[1] = tp + __AFL_THREAD_DTV_OFF; /* dtv */
        tcb[2] = tp;                        /* self */

        ((int *) tcb)[6] = 1; /* multiple_threads */
        ((int *) tcb)[7] = 0; /* gscope_flag */

        tcb[4] = __afl_thread_guard[0]; /* stack_guard */
        tcb[5] = __afl_thread_guard[1]; /* pointer_guard */
    }

    /* The DTV of this thread: the generation, then one block per module. */
    {
        size_t *dtv = (size_t *) (tp + __AFL_THREAD_DTV_OFF);

        dtv[0] = __afl_thread_dtv_generation;

        for (i = 0; i < __afl_thread_module_count; i++) {
            const __afl_thread_module_t *module = &__afl_thread_modules[i];

            dtv[2 * module->modid] = (size_t) ((long) tp + module->rel);
            dtv[2 * module->modid + 1] = 0; /* to_free, null for a static block */
        }
    }

    *state_out = (__afl_thread_state_t *) (tp + __AFL_THREAD_STATE_OFF);
    *tls_out = (unsigned long) tp;
    stack_out[0] = (void *) (base + __AFL_THREAD_STACK_SIZE);

    return base;
}

/*
 * __afl_thread_state_of maps a handle back to the state of its thread.
 */
static inline __afl_thread_state_t *__afl_thread_state_of(const afl_thread_t *thread)
{
    return (__afl_thread_state_t *) (__afl_thread_tp_of(thread->zone) + __AFL_THREAD_STATE_OFF);
}

#endif /* !__AFL_THREAD_WITH_PTHREAD */

/*
 * afl_thread_init prepares TLS module metadata and enables libc locking.
 * afl_thread_create performs the same initialization on its first call.
 * Explicit initialization also enables locking before a single-worker region
 * that creates no thread. Returns zero or the cached initialization error.
 */
static inline int afl_thread_init(void)
{
#if __AFL_THREAD_WITH_PTHREAD
    return 0;
#else
    afl_once(&__afl_thread_init_once, __afl_thread_modules_init);

    return __afl_thread_init_error;
#endif
}

/*
 * afl_thread_create starts fn(arg) on a new thread and fills thread with its
 * handle. It answers 0, or a positive error number. The thread is a real kernel
 * thread of the process: it shares memory, file descriptors and signal
 * handlers, and a fatal signal ends the process the same way a pthread does.
 */
static inline int afl_thread_create(afl_thread_t *thread, void (*fn)(void *), void *arg)
{
#if __AFL_THREAD_WITH_PTHREAD
    pthread_t id;

    if (pthread_create(&id, NULL, (void *(*)(void *) ) fn, arg) != 0)
        return errno;

    thread->zone = (void *) id;
    thread->zone_size = 0;
    thread->tid = NULL;

    return 0;
#else
    __afl_thread_state_t *state;
    unsigned long tls;
    void *stack[1];
    void *zone;
    long tid;

    afl_once(&__afl_thread_init_once, __afl_thread_modules_init);

    if (__afl_unlikely(__afl_thread_init_error != 0))
        return __afl_thread_init_error;

    zone = __afl_thread_zone(&state, &tls, stack);

    if (zone == NULL)
        return errno;

    state->fn = fn;
    state->arg = arg;
    state->tid = 0;
    state->detached = 0;

    /*
     * The child gets its thread pointer from CLONE_SETTLS and finds its state
     * through it. The two tid pointers are the same word: the kernel stores the
     * new tid there for the parent and clears it when the thread has finished.
     * A failed clone frees the zone it never handed to anyone.
     */
    tid = __afl_thread_clone(__AFL_THREAD_CLONE_FLAGS, __AFL_THREAD_STACK_TOP(stack[0]), &state->tid, &state->tid, tls);

    if (tid < 0) {
        int error = (int) -tid;

        __afl_syscall(__NR_munmap, (long) (uintptr_t) zone, (long) __afl_thread_zone_size(), 0, 0);
        return error;
    }

    thread->zone = zone;
    thread->zone_size = __afl_thread_zone_size();
    thread->tid = &state->tid;

    return 0;
#endif
}

/*
 * afl_thread_join waits until the thread has finished and frees its zone. It
 * answers 0, or EINVAL when the handle is empty or already joined. A detached
 * thread must not be joined.
 */
static inline int afl_thread_join(afl_thread_t *thread)
{
#if __AFL_THREAD_WITH_PTHREAD
    if (thread->zone == NULL)
        return EINVAL;

    pthread_join((pthread_t) thread->zone, NULL);
    thread->zone = NULL;

    return 0;
#else
    if (thread->zone == NULL)
        return EINVAL;

    /*
     * The kernel clears the tid word (CLONE_CHILD_CLEARTID) and wakes its futex
     * when the thread is gone, and that wake is not private, so the wait is not
     * either. Once the word reads zero nothing is still running on the zone and
     * it can be unmapped.
     */
    for (;;) {
        int tid = __atomic_load_n(thread->tid, __ATOMIC_ACQUIRE);

        if (tid == 0)
            break;

        __afl_syscall(__NR_futex, (intptr_t) thread->tid, FUTEX_WAIT, tid, 0);
    }

    __afl_syscall(__NR_munmap, (long) (uintptr_t) thread->zone, (long) thread->zone_size, 0, 0);

    thread->zone = NULL;
    thread->tid = NULL;

    return 0;
#endif
}

/*
 * afl_thread_detach relinquishes the handle; it must not be joined afterward.
 * With the raw-clone backend, the stack/TLS mapping remains allocated until
 * process exit. The pthread backend delegates resource cleanup to pthreads.
 */
static inline int afl_thread_detach(afl_thread_t *thread)
{
#if __AFL_THREAD_WITH_PTHREAD
    if (thread->zone == NULL)
        return EINVAL;

    pthread_detach((pthread_t) thread->zone);
    thread->zone = NULL;

    return 0;
#else
    if (thread->zone == NULL)
        return EINVAL;

    __atomic_store_n(&__afl_thread_state_of(thread)->detached, 1, __ATOMIC_RELEASE);

    thread->zone = NULL;
    thread->tid = NULL;

    return 0;
#endif
}

/*
 * afl_thread_self answers the kernel thread id of the calling thread, the value
 * a targeted signal needs and the value afl.h caches for its owner tracking.
 */
static inline unsigned long afl_thread_self(void)
{
    return (unsigned long) __afl_gettid();
}

#ifdef __cplusplus
}
#endif

#endif /* __AFL_THREAD_H */
