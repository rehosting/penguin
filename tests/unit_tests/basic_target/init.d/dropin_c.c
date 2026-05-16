#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <dropin_c_util.h>

int main(void) {
    const char *message = dropin_c_message();
    int fd = open("/igloo/shared/dropin_c_ran", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return 1;
    }
    if (write(fd, message, strlen(message)) < 0) {
        close(fd);
        return 2;
    }
    close(fd);
    return 0;
}
