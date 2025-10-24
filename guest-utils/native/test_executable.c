#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int test_add(int x, int y) {
    return x + y;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <int1> <int2>\n", argv[0]);
        return 1;
    }

    int a = atoi(argv[1]);
    int b = atoi(argv[2]);
    int result = test_add(a, b);
    printf("Result of %d + %d = %d\n", a, b, result);
    return 0;
}
