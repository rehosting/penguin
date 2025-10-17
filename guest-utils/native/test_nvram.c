#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *) 0)
#endif

void print_usage(const char *progname) {
    printf("Usage: %s <command> [arguments]\n", progname);
    printf("\n");
    printf("Commands:\n");
    printf("  get <key>           Get value for the specified key\n");
    printf("  set <key> <value>   Set key to the specified value\n");
    printf("  show                Show all NVRAM variables (if supported)\n");
    printf("  help                Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s get wan_ip\n", progname);
    printf("  %s set lan_ip 192.168.1.1\n", progname);
    printf("\n");
}

int cmd_get(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Error: get command requires a key\n");
        return 1;
    }

    const char *key = argv[2];

    // Use dlsym instead of weak symbols
    char* (*real_nvram_get)(const char*) = dlsym(RTLD_DEFAULT, "nvram_get");
    if (!real_nvram_get) {
        fprintf(stderr, "Error: nvram_get not available: %s\n", dlerror());
        return 1;
    }

    char *value = real_nvram_get(key);
    if (value) {
        printf("%s\n", value);
        return 0;
    } else {
        // No output for missing keys (matches standard nvram behavior)
        return 1;
    }
}

int cmd_set(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Error: set command requires key and value\n");
        return 1;
    }

    const char *key = argv[2];
    const char *value = argv[3];

    // Use dlsym instead of weak symbols
    int (*real_nvram_set)(const char*, const char*) = dlsym(RTLD_DEFAULT, "nvram_set");
    if (!real_nvram_set) {
        fprintf(stderr, "Error: nvram_set not available: %s\n", dlerror());
        return 1;
    }

    int result = real_nvram_set(key, value);
    if (result) {
        printf("Set %s=%s\n", key, value);
        return 0;
    } else {
        fprintf(stderr, "Error: Failed to set %s\n", key);
        return 1;
    }
}

int cmd_show(int argc, char *argv[]) {
    printf("Show command not implemented (libnvram doesn't provide enumeration)\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "get") == 0) {
        return cmd_get(argc, argv);
    } else if (strcmp(command, "set") == 0) {
        return cmd_set(argc, argv);
    } else if (strcmp(command, "show") == 0) {
        return cmd_show(argc, argv);
    } else if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        return 1;
    }
}
