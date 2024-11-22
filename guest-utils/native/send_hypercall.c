/*
 * 1. Guest runs `./send_hypercall x y z`
 * 2. Hypervisor receives hypercall `hc(MAGIC_VALUE, {"x", "y", "z", out}, 4)`
 * 3. Hypervisor writes output string to `out` and returns exit status.
 * 4. This program prints the string and exits with the status.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAGIC_VALUE 0xb335a535 // crc32("send_hypercall")
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
	require(argc > 1, "Need at least one arg");
	void **hypercall_args = calloc(argc, sizeof(void *));
	require(hypercall_args, "Alloc failed");
	for (int i = 0; i < argc - 1; i++) {
		hypercall_args[i] = argv[i + 1];
	}
	char output[0x1000] = {0};
	hypercall_args[argc - 1] = output;
	int ret = hc(MAGIC_VALUE, hypercall_args, argc);
	fputs(output, stdout);
	return ret;
}
