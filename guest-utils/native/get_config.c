#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include "portal_call.h"

#define GET_CONFIG_MAGIC 0x6E7C04F0
#define BUFFER_SIZE 4096
#define CONFIG_CACHE_DIR "/igloo/config_tmpfs"
#define CONFIG_LOCK_FILE CONFIG_CACHE_DIR ".lock"

#define DEBUG 0

#define PRINT_MSG(fmt, ...) do { if (DEBUG) { fprintf(stderr, "%s: "fmt, __FUNCTION__, __VA_ARGS__); } } while (0)

static void require(bool condition, const char *s)
{
	if (!condition) {
		fprintf(stderr, "get_config: error: %s\n", s);
		exit(1);
	}
}

static int _libinject_flock_asm(int fd, int op) {
    // File lock with SYS_flock. We do this in assembly
    // for portability - libc may not be available / match versions
    // with the library we're building
    int retval;
#if defined(__mips64__)
    asm volatile(
    "daddiu $a0, %1, 0\n"  // Move fd to $a0
    "daddiu $a1, %2, 0\n"  // Move op to $a1
    "li $v0, %3\n"         // Load SYS_flock (the system call number) into $v0
    "syscall\n"            // Make the system call
    "move %0, $v0\n"       // Move the result from $v0 to retval
    : "=r" (retval)        // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "v0", "a0", "a1"     // Clobber list
);
#elif defined(__mips__)
    asm volatile(
    "move $a0, %1\n"        // Correctly move fd (from C variable) to $a0
    "move $a1, %2\n"        // Correctly move op (from C variable) to $a1
    "li $v0, %3\n"          // Load the syscall number for flock into $v0
    "syscall\n"             // Perform the syscall
    "move %0, $v0"          // Move the result from $v0 to retval
    : "=r" (retval)         // Output
    : "r" (fd), "r" (op), "i" (SYS_flock) // Inputs; "i" for immediate syscall number
    : "v0", "a0", "a1"      // Clobber list
);
#elif defined(__arm__)
    asm volatile(
    "mov r0, %1\n"  // Move fd to r0, the first argument for the system call
    "mov r1, %2\n"  // Move op to r1, the second argument for the system call
    "mov r7, %3\n"  // Move SYS_flock (the system call number) to r7
    "svc 0x00000000\n"  // Make the system call
    "mov %[result], r0"  // Move the result from r0 to retval
    : [result]"=r" (retval)  // Output
    : "r"(fd), "r"(op), "i"(SYS_flock)  // Inputs
    : "r0", "r1", "r7"  // Clobber list
);
#elif defined(__aarch64__)  // AArch64
    // XXX: using %w registers for 32-bit movs. This made the compiler
    // happy but I'm not sure why we can't be operating on 64-bit ints
    asm volatile(
    "mov w0, %w1\n"        // Move fd to w0, the first argument for the system call
    "mov w1, %w2\n"        // Move op to w1, the second argument for the system call
    "mov x8, %3\n"         // Move SYS_flock (the system call number) to x8
    "svc 0\n"              // Make the system call (Supervisor Call)
    "mov %w0, w0\n"        // Move the result from w0 to retval
    : "=r" (retval)        // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "x0", "x1", "x8"     // Clobber list
);
#elif defined(__x86_64__)  // x86_64
    // XXX: movl's for 32-bit movs. This made the compiler
    // happy but I'm not sure why we can't be operating on 64-bit ints
    // I think it should be fine though
    asm volatile(
    "movl %1, %%edi\n"       // Move fd to rdi (1st argument)
    "movl %2, %%esi\n"       // Move op to rsi (2nd argument)
    "movl %3, %%eax\n"       // Move SYS_flock to rax (syscall number)
    "syscall\n"             // Make the syscall
    "movl %%eax, %0\n"       // Move the result from rax to retval
    : "=r" (retval)         // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "rax", "rdi", "rsi"   // Clobber list
);
#elif defined(__i386__)  // x86 32-bit
    asm volatile(
    "movl %1, %%ebx\n"      // Move fd to ebx
    "movl %2, %%ecx\n"      // Move op to ecx
    "movl %3, %%eax\n"      // Move SYS_flock to eax
    "int $0x80\n"           // Make the syscall
    "movl %%eax, %0\n"      // Move the result from eax to retval
    : "=r" (retval)         // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "eax", "ebx", "ecx"   // Clobber list
);
#elif defined(__powerpc__) || defined(__powerpc64__)
    asm volatile(
    "mr 3, %1\n"           // Move fd to r3 (1st argument)
    "mr 4, %2\n"           // Move op to r4 (2nd argument)
    "li 0, %3\n"           // Load SYS_flock (the system call number) into r0
    "sc\n"                 // Make the system call
    "mr %0, 3\n"           // Move the result from r3 to retval
    : "=r" (retval)        // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "r0", "r3", "r4"     // Clobber list
);
#elif defined(__riscv)
    asm volatile(
    "mv a0, %1\n"          // Move fd to a0 (1st argument)
    "mv a1, %2\n"          // Move op to a1 (2nd argument)
    "li a7, %3\n"          // Load SYS_flock (the system call number) into a7
    "ecall\n"              // Make the system call
    "mv %0, a0\n"          // Move the result from a0 to retval
    : "=r" (retval)        // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "a0", "a1", "a7"     // Clobber list
);
#elif defined(__loongarch64)
    asm volatile(
    "move $a0, %1\n"       // Move fd to $a0 (1st argument)
    "move $a1, %2\n"       // Move op to $a1 (2nd argument)
    "addi.d $a7, $zero, %3\n" // Load SYS_flock (the system call number) into $a7
    "syscall 0\n"          // Make the system call
    "move %0, $a0\n"       // Move the result from $a0 to retval
    : "=r" (retval)        // Output
    : "r" (fd), "r" (op), "i" (SYS_flock)  // Inputs
    : "a0", "a1", "a7"     // Clobber list
);
#else
#error "Unsupported architecture"
#endif
    return retval;
}

static int _libinject_config_lock() {
    int lockfd;

    lockfd = open(CONFIG_LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (lockfd < 0) {
        PRINT_MSG("Lock file open failed, creating cache dir %s\n", CONFIG_CACHE_DIR);
        if (mkdir(CONFIG_CACHE_DIR, 0755) == -1 && errno != EEXIST) {
            PRINT_MSG("Failed to create config cache dir %s\n", CONFIG_CACHE_DIR);
            return -1;
        }

        if (mount("tmpfs", CONFIG_CACHE_DIR, "tmpfs", 0, NULL) == -1) {
            PRINT_MSG("Failed to mount tmpfs at %s\n", CONFIG_CACHE_DIR);
        }

        lockfd = open(CONFIG_LOCK_FILE, O_CREAT | O_RDWR, 0644);
        if (lockfd < 0) {
            PRINT_MSG("Still couldn't open lock file %s\n", CONFIG_LOCK_FILE);
            return -1;
        }
    }

    if (_libinject_flock_asm(lockfd, LOCK_EX) < 0) {
        PRINT_MSG("Couldn't lock %s\n", CONFIG_LOCK_FILE);
        close(lockfd);
        return -1;
    }

    return lockfd;
}

static void _libinject_config_unlock(int lockfd) {
    if (lockfd >= 0) {
        _libinject_flock_asm(lockfd, LOCK_UN);
        close(lockfd);
    }
}

static int _libinject_mkdir_p(const char *path) {
    char *tmp = strdup(path);
    if (!tmp) return -1;

    size_t len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                free(tmp);
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
        free(tmp);
        return -1;
    }

    free(tmp);
    return 0;
}

static int value_to_bool(char *value) {
    printf("value_to_bool: value='%s'\n", value);
    if (!strncmp(value, "False", 5) || !strncmp(value, "None", 4) ||
        !strncmp(value, "false", 5) || !strncmp(value, "", 1)) {
        return 1;
    }
    return 0;
}

int libinject_get_config(const char *key, char *output, unsigned long buf_size) {
    unsigned long rv;
    PRINT_MSG("Getting config key '%s'\n", key);
    rv = portal_call3(GET_CONFIG_MAGIC, (unsigned long) key, (unsigned long) output, buf_size);
    PRINT_MSG("Got config key '%s' with return value %lu\n", key, rv);
    return (int) rv;
}

int libinject_get_config_int(const char *config_key) {
    char *str = malloc(64);
    int result;
    if(!libinject_get_config(config_key, str, 64)) {
        result = 0;
    } else {
        result = atoi(str);
    }
    free(str);
    return result;
}

int libinject_get_config_bool(const char *config_key) {
    char *str = malloc(64);
    int result;
    PRINT_MSG("Getting bool config key '%s'\n", config_key);
    libinject_get_config(config_key, str, 64);
    result = value_to_bool(str);
    PRINT_MSG("Got bool config key '%s' with value %s (bool %d)\n", config_key, str, result);
    free(str);
    return result;
}

#ifndef GET_CONFIG_LIBRARY_ONLY
int main(int argc, char *argv[]) {
    char *buffer;
    int rv;
    require(argc == 2, "Usage: get_config <config_key>");
    buffer = malloc(BUFFER_SIZE);
    require(buffer != NULL, "Failed to allocate memory");
    rv = libinject_get_config(argv[1], buffer, BUFFER_SIZE);
    buffer[BUFFER_SIZE - 1] = 0;
    printf("%s", buffer);
    return !value_to_bool(buffer); // Return 0 for true values, 1 for false
}
#endif
