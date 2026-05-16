#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int fd = open("/dev/mmap_native", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    size_t size = 4096;
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    printf("Mapped address: %p\n", ptr);

    volatile unsigned int *m = (volatile unsigned int *)ptr;
    
    printf("Writing 0xDEADBEEF to mmap...\n");
    *m = 0xDEADBEEF;

    printf("Reading back from mmap...\n");
    unsigned int val = *m;
    printf("Value read: 0x%08X\n", val);

    if (val == 0xDEADBEEF) {
        printf("SUCCESS: mmap read/write worked!\n");
    } else {
        printf("FAILURE: value mismatch!\n");
    }

    munmap(ptr, size);
    close(fd);
    return 0;
}
