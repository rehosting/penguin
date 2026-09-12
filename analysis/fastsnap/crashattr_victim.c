/* A deliberately vulnerable parser, used as the crash oracle for the
 * input-attribution experiment. It is NOT part of any real target; it exists
 * so that an input-to-crash-to-reproducer path can be exercised end to end.
 *
 * Shape: read a request off a descriptor, then copy it into a small stack
 * buffer using a length taken from the request itself. That is the classic
 * unvalidated-length stack overflow. Reading from /dev/zero rather than a
 * socket is deliberate: the fuzz harness rewrites the buffer at the read()
 * return, so the descriptor is only a clock. It keeps the experiment free of
 * networking, which is not what is under test here.
 */
#include <fcntl.h>
#include <unistd.h>

#define REQ_MAX 256

/* noinline-ish: its own frame is what gets smashed. */
__attribute__((noinline)) static void handle(const unsigned char *req, int n) {
    volatile char small[16];
    int len = req[0];             /* attacker-controlled length, unvalidated */
    int i;
    if (len > n) len = n;
    for (i = 0; i < len; i++)     /* overflow whenever len > 16 */
        small[i] = (char)req[i];
    /* touch it so the copy cannot be optimised away */
    if (small[0] == 0x7f) write(1, (const void *)small, 1);
}

int main(void) {
    unsigned char req[REQ_MAX];
    int fd = open("/dev/zero", O_RDONLY);
    int i, n;
    if (fd < 0) return 1;
    for (i = 0; i < 64; i++) {
        n = read(fd, req, REQ_MAX);   /* harness rewrites req/retval here */
        if (n <= 0) break;
        handle(req, n);
    }
    close(fd);
    return 0;
}
