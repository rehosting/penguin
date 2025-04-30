/*
 * 1. Guest runs `./send_syscall x y z`
 * 2. 
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
    
    void **syscall_args = calloc(argc, sizeof(void *));
    require(syscall_args, "Alloc failed");
    
    // Convert arguments from hex to decimal
    for (int i = 0; i < argc - 1; i++) {
        // Try to convert from hex
        char *endptr;
        long int value = strtol(argv[i + 1], &endptr, 16);
        
        // Check if conversion was successful
        if (*endptr == '\0') {
            // Successful conversion - allocate and store the decimal value
            long int *num_ptr = malloc(sizeof(long int));
            require(num_ptr, "Alloc failed for converted argument");
            *num_ptr = value;
            syscall_args[i] = num_ptr;
            printf("send_syscall: arg[%d] = %ld (converted from hex '%s')\n", i, value, argv[i + 1]);
        } else {
            // Not a valid hex number, use the original string
            syscall_args[i] = argv[i + 1];
            printf("send_syscall: arg[%d] = '%s' (string)\n", i, (char*)syscall_args[i]);
        }
    }
    
    char output[0x1000] = {0};
    syscall_args[argc - 1] = output;
    printf("send_syscall: calling syscall with %d arguments\n", argc);
    int ret = syscall((long)syscall_args[0], 
                     argc > 1 ? (long)syscall_args[1] : 0,
                     argc > 2 ? (long)syscall_args[2] : 0,
                     argc > 3 ? (long)syscall_args[3] : 0,
                     argc > 4 ? (long)syscall_args[4] : 0,
                     argc > 5 ? (long)syscall_args[5] : 0);
    printf("send_syscall: syscall returned %d\n", ret);
    
    fputs(output, stdout);
    
    // Free allocated memory
    for (int i = 0; i < argc - 1; i++) {
        // Only free if it's not the original argument string
        if (syscall_args[i] != argv[i + 1]) {
            free(syscall_args[i]);
        }
    }
    free(syscall_args);
    
    return ret;
}
