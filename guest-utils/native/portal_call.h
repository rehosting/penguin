#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <stdarg.h>

#if __SIZEOF_POINTER__ == 8
#define PORTAL_MAGIC ((unsigned long)0xc1d1e1f1)
#else
#define PORTAL_MAGIC ((int)0xc1d1e1f1)
#endif

static inline long portal_call(unsigned long user_magic, int argc, uint64_t *args) {
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, argc, args, 0, 0);
}
static inline long portal_call1(unsigned long user_magic, uint64_t a1) {
    uint64_t args[1] = {a1};
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, 1, args, 0, 0);
}
static inline long portal_call2(unsigned long user_magic, uint64_t a1, uint64_t a2) {
    uint64_t args[2] = {a1, a2};
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, 2, args, 0, 0);
}
static inline long portal_call3(unsigned long user_magic, uint64_t a1, uint64_t a2, uint64_t a3) {
    uint64_t args[3] = {a1, a2, a3};
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, 3, args, 0, 0);
}
static inline long portal_call4(unsigned long user_magic, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
    uint64_t args[4] = {a1, a2, a3, a4};
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, 4, args, 0, 0);
}
static inline long portal_call5(unsigned long user_magic, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    uint64_t args[5] = {a1, a2, a3, a4, a5};
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, 5, args, 0, 0);
}

static inline long portal_callN(unsigned long user_magic, int argc, ...) {
    uint64_t args[10];
    va_list ap;
    va_start(ap, argc);
    for (int i = 0; i < argc; ++i) {
        args[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);
    return syscall(SYS_sendto, PORTAL_MAGIC, user_magic, argc, args, 0, 0);
}

