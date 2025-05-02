/*
 * 1. Guest runs `./send_syscall x y z`
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>

void require(bool condition, const char *s)
{
    if (!condition) {
        fprintf(stderr, "send_syscall: error: %s\n", s);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    require(argc > 1, "Need at least one arg");

    printf("send_syscall: received %d arguments\n", argc-1);

    unsigned long syscall_args[7] = {0}; // syscall number + up to 6 args

    // Convert arguments from hex to decimal
    for (int i = 0; i < argc - 1 && i < 7; i++) {
        // for tests the first argument can be a set of known syscalls from constants
        if (i == 0){
            if (strcmp(argv[i + 1], "write") == 0) {
                syscall_args[i] = SYS_write;
                continue;
            } else if (strcmp(argv[i + 1], "read") == 0) {
                syscall_args[i] = SYS_read;
                continue;
            } else if (strcmp(argv[i + 1], "clone") == 0) {
                syscall_args[i] = SYS_clone;
                continue;
            } else if (strcmp(argv[i + 1], "getpid") == 0) {
                syscall_args[i] = SYS_getpid;
                continue;
            }
        }
        // Try to convert from hex
        char *endptr;
        unsigned long value = strtoull(argv[i + 1], &endptr, 16);

        // Check if conversion was successful
        if (*endptr == '\0') {
            syscall_args[i] = value;
            printf("send_syscall: arg[%d] = %lu (converted from hex '%s')\n", i, value, argv[i + 1]);
        } else {
            // Not a valid hex number, use the pointer to the string (for char* args)
            syscall_args[i] = (unsigned long)argv[i + 1];
            printf("send_syscall: arg[%d] = '%s' (string)\n", i, argv[i + 1]);
        }
    }

    printf("send_syscall: calling syscall with up to 6 arguments\n");
    long ret = syscall(
        syscall_args[0],
        syscall_args[1],
        syscall_args[2],
        syscall_args[3],
        syscall_args[4],
        syscall_args[5],
        syscall_args[6]
    );
    printf("send_syscall: syscall returned %ld\n", ret);

    return (int)ret;
}
