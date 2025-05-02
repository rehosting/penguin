/*
 * 1. Guest runs `./send_hypercall_raw 0x1234 0x5678 0x9abc 0xdef0`
 */

 #include <stdbool.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "hypercall.h"
 
 void require(bool condition, const char *s)
 {
     if (!condition) {
         fprintf(stderr, "send_hypercall: error: %s\n", s);
         exit(1);
     }
 }
 
 int main(int argc, char **argv)
 {
     // Parse up to 5 arguments from argv[1]..argv[5] as hex
     uint64_t args[5] = {0};
     int n = argc - 1;
     if (n > 5) n = 5;
     for (int i = 0; i < n; ++i) {
         char *endptr = NULL;
         args[i] = strtoull(argv[i + 1], &endptr, 16);
         require(endptr != argv[i + 1] && *endptr == '\0', "invalid hex argument");
         printf("arg[%d] = 0x%lx\n", i, args[i]);
     }
     unsigned long ret = igloo_hypercall4(args[0], args[1], args[2], args[3], args[4]);
     printf("do_hypercall returned: %lu\n", ret);
     return (int)ret;
 }
