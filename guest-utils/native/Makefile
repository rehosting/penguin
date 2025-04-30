ARCHS = mipseb mips64eb mipsel mips64el armel aarch64 x86_64 powerpc powerpcle powerpc64 powerpc64le riscv32 riscv64 loongarch64

CC_mipseb = mipseb-linux-musl-gcc
CFLAGS_mipseb = -mips32r3 -s -static

CC_mips64eb = mips64eb-linux-musl-gcc
CFLAGS_mips64eb = -mips64r2 -s -static

CC_mipsel = mipsel-linux-musl-gcc
CFLAGS_mipsel = -mips32r3 -s -static

CC_mips64el = mips64el-linux-musl-gcc
CFLAGS_mips64el = -mips64r2 -s -static

CC_armel = arm-linux-musleabi-gcc
CFLAGS_armel = -s -static

CC_aarch64 = aarch64-linux-musl-gcc
CFLAGS_aarch64 = -s -static

CC_x86_64 = x86_64-linux-musl-gcc
CFLAGS_x86_64 = -s -static

CC_powerpc = powerpc-linux-musl-gcc
CFLAGS_powerpc = -s -static

CC_powerpcle = powerpcle-linux-musl-gcc
CFLAGS_powerpcle = -s -static

CC_powerpc64 = powerpc64-linux-musl-gcc
CFLAGS_powerpc64 = -s -static

CC_powerpc64le = powerpc64le-linux-musl-gcc
CFLAGS_powerpc64le = -s -static

CC_riscv32 = riscv32-linux-musl-gcc
CFLAGS_riscv32 = -s -static

CC_riscv64 = riscv64-linux-musl-gcc
CFLAGS_riscv64 = -s -static

CC_loongarch64 = loongarch64-unknown-linux-gnu-gcc
CFLAGS_loongarch64 = -s -static

.PHONY: all clean
all: $(foreach arch,$(ARCHS),out/$(arch)/send_hypercall) $(foreach arch,$(ARCHS),out/$(arch)/send_syscall)

hypercall.h:
	wget -q https://raw.githubusercontent.com/panda-re/libhc/main/hypercall.h

out/%/send_hypercall: send_hypercall.c hypercall.h
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/send_syscall: send_syscall.c
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

clean:
	rm -rf out/ hypercall.h