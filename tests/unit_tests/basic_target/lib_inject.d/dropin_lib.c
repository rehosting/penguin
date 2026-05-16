#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "dropin_lib_util.h"

const char *dropin_lib_marker = DROPIN_LIB_MARKER_STRING;

int dropin_lib_answer(void) {
    return 42;
}

static void __attribute__((constructor)) dropin_lib_init(void) {
    int fd = open("/igloo/shared/lib_inject_dropin_ran", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }
    const char *msg = DROPIN_LIB_MARKER_STRING "\n";
    write(fd, msg, strlen(msg));
    close(fd);
}
