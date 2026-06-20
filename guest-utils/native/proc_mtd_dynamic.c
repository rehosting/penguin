/*
 * proc_mtd_dynamic: dlopen the guest injection library (lib_inject) and call
 * its exported libinject_strstr to scan /proc/mtd for a flash device. This
 * exercises that a dynamically-injected musl library loads and its symbols
 * resolve in the guest.
 *
 * Built as a native musl-dynamic binary (see the Makefile) rather than driven
 * by /igloo/utils/python3: python3 is now a pristine glibc closure, and
 * dlopening the musl lib_inject into a glibc process crashes on 32-bit guests
 * (mismatched libc). A native musl binary loads the musl lib_inject cleanly.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *options[] = {
        "lib_inject.so",
        "/igloo/lib_inject_default.so",
        "/igloo/lib_inject_ppc64.so",
    };

    void *lib_inject = NULL;
    for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        lib_inject = dlopen(options[i], RTLD_NOW);
        if (lib_inject)
            break;
        fprintf(stderr, "Error loading %s: %s\n", options[i], dlerror());
    }
    if (!lib_inject) {
        fprintf(stderr, "Error loading any of the lib_inject libraries.\n");
        return 1;
    }

    char *(*libinject_strstr)(const char *, const char *) =
        (char *(*)(const char *, const char *))dlsym(lib_inject, "libinject_strstr");
    if (!libinject_strstr) {
        fprintf(stderr, "libinject_strstr not found: %s\n", dlerror());
        return 1;
    }

    FILE *f = fopen("/proc/mtd", "r");
    if (!f) {
        perror("open /proc/mtd");
        return 1;
    }

    char line[256];
    char device_path[320] = {0};
    while (fgets(line, sizeof(line), f)) {
        if (libinject_strstr(line, "flash")) {
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                snprintf(device_path, sizeof(device_path), "/dev/%s", line);
            }
            break;
        }
    }
    fclose(f);

    printf("flash device path: %s\n", device_path[0] ? device_path : "(null)");
    return 0;
}
