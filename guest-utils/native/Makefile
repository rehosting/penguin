ARCHS = mipseb mips64eb mipsel mips64el armel aarch64 x86_64 powerpc powerpcle powerpc64 powerpc64le riscv32 riscv64 loongarch64

CC_mipseb = mipseb-linux-musl-gcc
CFLAGS_mipseb = -mips32r3 -s -static
CFLAGS_DYNAMIC_mipseb = -mips32r3 -s

CC_mips64eb = mips64eb-linux-musl-gcc
CFLAGS_mips64eb = -mips64r2 -s -static
CFLAGS_DYNAMIC_mips64eb = -mips64r2 -s

CC_mipsel = mipsel-linux-musl-gcc
CFLAGS_mipsel = -mips32r3 -s -static
CFLAGS_DYNAMIC_mipsel = -mips32r3 -s

CC_mips64el = mips64el-linux-musl-gcc
CFLAGS_mips64el = -mips64r2 -s -static
CFLAGS_DYNAMIC_mips64el = -mips64r2 -s

CC_armel = arm-linux-musleabi-gcc
CFLAGS_armel = -s -static
CFLAGS_DYNAMIC_armel = -s

CC_aarch64 = aarch64-linux-musl-gcc
CFLAGS_aarch64 = -s -static
CFLAGS_DYNAMIC_aarch64 = -s

CC_x86_64 = x86_64-linux-musl-gcc
CFLAGS_x86_64 = -s -static
CFLAGS_DYNAMIC_x86_64 = -s

CC_powerpc = powerpc-linux-musl-gcc
CFLAGS_powerpc = -s -static
CFLAGS_DYNAMIC_powerpc = -s

CC_powerpcle = powerpcle-linux-musl-gcc
CFLAGS_powerpcle = -s -static
CFLAGS_DYNAMIC_powerpcle = -s

CC_powerpc64 = powerpc64-linux-musl-gcc
CFLAGS_powerpc64 = -s -static
CFLAGS_DYNAMIC_powerpc64 = -s

CC_powerpc64le = powerpc64le-linux-musl-gcc
CFLAGS_powerpc64le = -s -static
CFLAGS_DYNAMIC_powerpc64le = -s

CC_riscv32 = riscv32-linux-musl-gcc
CFLAGS_riscv32 = -s -static
CFLAGS_DYNAMIC_riscv32 = -s

CC_riscv64 = riscv64-linux-musl-gcc
CFLAGS_riscv64 = -s -static
CFLAGS_DYNAMIC_riscv64 = -s

CC_loongarch64 = loongarch64-unknown-linux-gnu-gcc
CFLAGS_loongarch64 = -s -static
CFLAGS_DYNAMIC_loongarch64 = -s

.PHONY: all clean
ALL_CS := $(basename $(notdir $(wildcard *.c)))
all: $(foreach arch,$(ARCHS),$(foreach bin,$(ALL_CS),out/$(arch)/$(bin)))

out/%/send_hypercall: send_hypercall.c hypercall.h
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/hyp_file_op: hyp_file_op.c hypercall.h
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/send_portalcall: send_portalcall.c hypercall.h
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/send_hypercall_raw: send_hypercall_raw.c hypercall.h
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/send_syscall: send_syscall.c
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/test_ioctl_interaction: test_ioctl_interaction.c
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/get_config: get_config.c
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_$*) $< -o $@

out/%/test_nvram: test_nvram.c
	@mkdir -p $(dir $@)
	$(CC_$*) $(CFLAGS_DYNAMIC_$*) -Wl,--dynamic-linker=/igloo/dylibs/ld-musl-$*.so.1 $< -o $@

out/%/test_executable: test_executable.c
	@mkdir -p $(dir $@)
	$(CC_$*) $(filter-out -s,$(CFLAGS_$*)) $< -o $@

clean:
	rm -rf out/ hypercall.h
