#ifndef __WINE_WINE_MUTEX_H
#define __WINE_WINE_MUTEX_H

#ifdef USE_AFL

#include "afl.h"

#define WINE_SPINLOCK_TYPE afl_spinlock_t
#define WINE_MUTEX_TYPE afl_mutex_t
#define WINE_MUTEX_RECURSIVE_TYPE afl_mutex_recursive_t
#define WINE_ONCE_TYPE afl_once_t

#define WINE_SPIN_INIT(__SPINLOCK__, __SHARED__) afl_spin_init(__SPINLOCK__, __SHARED__)
#define WINE_SPIN_LOCK(__SPINLOCK__) afl_spin_lock(__SPINLOCK__)
#define WINE_SPIN_UNLOCK(__SPINLOCK__) afl_spin_unlock(__SPINLOCK__)
#define WINE_SPIN_DESTROY(__SPINLOCK__) afl_spin_destroy(__SPINLOCK__)

#define WINE_MUTEX_INIT AFL_MUTEX_INIT
#define WINE_MUTEX_LOCK(__MUTEX__) afl_mutex_lock(__MUTEX__)
#define WINE_MUTEX_UNLOCK(__MUTEX__) afl_mutex_unlock(__MUTEX__)
#define WINE_MUTEX_DESTROY(__MUTEX__) afl_mutex_destroy(__MUTEX__)

#define WINE_MUTEX_RECURSIVE_INIT(__MUTEX__) afl_mutex_recursive_init(__MUTEX__)
#define WINE_MUTEX_RECURSIVE_LOCK(__MUTEX__) afl_mutex_recursive_lock(__MUTEX__)
#define WINE_MUTEX_RECURSIVE_UNLOCK(__MUTEX__) afl_mutex_recursive_unlock(__MUTEX__)
#define WINE_MUTEX_RECURSIVE_DESTROY(__MUTEX__) afl_mutex_recursive_destroy(__MUTEX__)

#define WINE_ONCE_INIT AFL_ONCE_INIT;
#define WINE_ONCE(__ONCE__, __FUNCTION__) afl_once(__ONCE__, __FUNCTION__)

#else

#error USE_AFL is not defined!

#include "pthread.h"

#define WINE_SPINLOCK_TYPE pthread_spinlock_t
#define WINE_MUTEX_TYPE pthread_mutex_t
#define WINE_MUTEX_RECURSIVE_TYPE pthread_mutex_t
#define WINE_ONCE_TYPE pthread_once_t

#define WINE_SPIN_INIT(__SPINLOCK__, __SHARED__) pthread_spin_init(__SPINLOCK__, __SHARED__)
#define WINE_SPIN_LOCK(__SPINLOCK__) pthread_spin_lock(__SPINLOCK__)
#define WINE_SPIN_UNLOCK(__SPINLOCK__) pthread_spin_unlock(__SPINLOCK__)
#define WINE_SPIN_DESTROY(__SPINLOCK__) pthread_spin_destroy(__SPINLOCK__)

#define WINE_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#define WINE_MUTEX_LOCK(__MUTEX__) pthread_mutex_owner_lock(__MUTEX__)
#define WINE_MUTEX_UNLOCK(__MUTEX__) pthread_mutex_owner_unlock(__MUTEX__)
#define WINE_MUTEX_DESTROY(__MUTEX__) pthread_mutex_destroy(__MUTEX__)

#define WINE_MUTEX_RECURSIVE_INIT(__MUTEX__)                       \
    do {                                                           \
        pthread_mutexattr_t attr;                                  \
        pthread_mutexattr_init(&attr);                             \
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); \
        pthread_mutex_init(__MUTEX__, &attr);                      \
        pthread_mutexattr_destroy(&attr);                          \
    } while (0)
#define WINE_MUTEX_RECURSIVE_LOCK(__MUTEX__) pthread_mutex_lock(__MUTEX__)
#define WINE_MUTEX_RECURSIVE_UNLOCK(__MUTEX__) pthread_mutex_unlock(__MUTEX__)
#define WINE_MUTEX_RECURSIVE_DESTROY(__MUTEX__) pthread_mutex_destroy(__MUTEX__)

#define WINE_ONCE_INIT PTHREAD_ONCE_INIT;
#define WINE_ONCE(__ONCE__, __FUNCTION__) pthread_once(__ONCE__, __FUNCTION__)

#endif

#endif /* __WINE_WINE_MUTEX_H */
