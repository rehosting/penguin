/*
 * uprobes_test: exercise a handful of libc functions with known arguments so
 * the uprobes_test plugin can verify entry/return uprobes on musl libc.
 *
 * This is built dynamically against /igloo/dylibs/ld-musl-<arch>.so.1 (see the
 * Makefile) so the probed calls route through the same musl libc.so the guest
 * maps under the ld-musl name -- which is where the plugin registers its
 * uprobes. (The old driver was a /igloo/utils/python3 ctypes script; once
 * python3 became a pristine glibc closure, ctypes-loading musl libc.so into a
 * glibc process crashed before the probed calls ran, so the libc probes never
 * fired. A native musl-linked binary, like test_executable.c, is stable.)
 *
 * The uprobes are registered with process_filter="uprobes_test.sh", which
 * matches the kernel task comm. Set comm to that name before the probed calls.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

int main(void) {
    /* PR_SET_NAME caps comm at 15 chars; "uprobes_test.sh" fits exactly. */
    prctl(PR_SET_NAME, "uprobes_test.sh", 0, 0, 0);

    /* Volatile sink so no optimization level can drop the unused results. */
    volatile long sink = 0;

    const char *msg = "Hello from uprobe_test\n";
    sink += strncmp(msg, msg, strlen(msg));

    printf("Hello from uprobe_test %d %d %d %d %d %d %d %d %d %d %d\n",
           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    FILE *fp = fopen("/proc/self/cmdline", "r");
    sink += (long)(fp != NULL);
    if (fp)
        fclose(fp);

    sink += (long)(getenv("PROJ_NAME") != NULL);

    /* atoi/atol are probed and unregistered after the first hit, so the second
     * call of each must not be recorded (count stays 1). */
    sink += atoi("10");
    sink += atoi("20");
    sink += atol("30");
    sink += atol("40");

    (void)sink;
    return 0;
}
