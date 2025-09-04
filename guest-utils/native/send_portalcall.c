/*
 * 1. Guest runs `./send_portalcall 0x1234 0x5678 0x9abc 0xdef0`
 */

 #include <stdbool.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "portal_call.h"
 
 void require(bool condition, const char *s)
 {
     if (!condition) {
         fprintf(stderr, "send_portalcall: error: %s\n", s);
         exit(1);
     }
 }
 
 int main(int argc, char **argv)
 {
     // Parse up to 10 arguments from argv[1]..argv[10] as hex
     uint64_t args[10] = {0};
     int n = argc - 1;
     if (n > 10)
         n = 10;
     for (int i = 0; i < n; ++i)
     {
         char *endptr = NULL;
         args[i] = strtoull(argv[i + 1], &endptr, 16);
         if (endptr == argv[i + 1] || *endptr != '\0') {
             // Not a valid hex, pass as pointer
             args[i] = (uint64_t)(argv[i + 1]);
             printf("arg[%d] = pointer to '%s'\n", i, argv[i + 1]);
         } else {
             printf("arg[%d] = 0x%lx\n", i, args[i]);
         }
     }
     unsigned long ret = portal_callN(args[0], argc - 2,
                            args[1], args[2], args[3], args[4], args[5], args[6],
                            args[7], args[8], args[9]);
     printf("do_hypercall returned: %lu\n", ret);
     return (int)ret;
 }
