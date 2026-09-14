/*
 * Can a pagemap prefilter make the fork oracle cheap, and is it sound?
 *
 * The oracle costs 61 ms of a 173 s run's 35% wall share, and it is 98.7%
 * process_vm_readv + memcmp over 281 MB at 4.6 GB/s -- memory-bandwidth
 * bound, so the only lever on the per-call cost is to read less.
 *
 * THE ONE SOUND WAY TO READ LESS. Parent and child share physical frames
 * until COW breaks. Two mappings on the same PFN are byte-identical by
 * kernel guarantee, so a page whose PFN still matches needs no comparison at
 * all. A page whose PFN differs MIGHT still be equal, so it gets compared --
 * the filter can only ever do extra work, never miss a difference. That
 * conservative direction is the whole safety argument, and it does not depend
 * on fastsnap's own dirty bookkeeping, which is what the oracle exists to not
 * trust.
 *
 * This measures the two things that decide it, without a QEMU rebuild:
 *   1. are PFNs readable here at all (they need CAP_SYS_ADMIN; without it
 *      pagemap returns 0 and the filter must fall back and say so);
 *   2. how many pages actually diverge after a workload that writes a small
 *      fixed set -- which is what a snapshot loop re-executing the same span
 *      does.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>

#define PAGE 4096UL
#define CHUNK (1UL << 20)

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int pm_open(pid_t pid) {
    char p[64];
    if (pid == 0) snprintf(p, sizeof p, "/proc/self/pagemap");
    else snprintf(p, sizeof p, "/proc/%d/pagemap", (int)pid);
    return open(p, O_RDONLY);
}

/* Read pagemap entries for npages starting at addr. */
static int pm_read(int fd, void *addr, uint64_t *out, size_t npages) {
    off_t off = (off_t)(((uintptr_t)addr / PAGE) * 8);
    size_t want = npages * 8, done = 0;
    while (done < want) {
        ssize_t r = pread(fd, (char *)out + done, want - done, off + done);
        if (r <= 0) return -1;
        done += r;
    }
    return 0;
}

#define PM_PRESENT (1ULL << 63)
#define PM_SWAP    (1ULL << 62)
#define PM_PFN     ((1ULL << 55) - 1)

int main(int argc, char **argv) {
    size_t mb = argc > 1 ? strtoul(argv[1], NULL, 10) : 281;
    size_t dirty_pages = argc > 2 ? strtoul(argv[2], NULL, 10) : 24;
    size_t laps = argc > 3 ? strtoul(argv[3], NULL, 10) : 200;
    size_t len = mb * 1024 * 1024, npages = len / PAGE;
    uint8_t *mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }
    /* Populate: an unfaulted page has no PFN in either process and the
     * comparison below would be measuring the zero page, not the workload. */
    for (size_t i = 0; i < npages; i++) mem[i * PAGE] = (uint8_t)i;

    pid_t child = fork();
    if (child == 0) { pause(); _exit(0); }

    /* The workload: write the SAME small set every lap, which is what a
     * snapshot loop re-executing one span does. COW breaks once per page,
     * not once per lap, so the divergent set should saturate quickly. */
    for (size_t l = 0; l < laps; l++)
        for (size_t p = 0; p < dirty_pages; p++)
            mem[((p * 7919) % npages) * PAGE] = (uint8_t)(l + p);

    /* 1. the oracle as it stands */
    uint8_t *buf = malloc(CHUNK);
    double t0 = now_ms();
    uint64_t diffs = 0, checked = 0;
    for (size_t off = 0; off < len; off += CHUNK) {
        size_t clen = CHUNK < len - off ? CHUNK : len - off;
        struct iovec lo = { buf, clen }, re = { mem + off, clen };
        if (process_vm_readv(child, &lo, 1, &re, 1, 0) != (ssize_t)clen) {
            fprintf(stderr, "readv failed: %s\n", strerror(errno));
            kill(child, SIGKILL); return 1;
        }
        for (size_t p = 0; p < clen; p += PAGE) {
            checked++;
            if (memcmp(buf + p, mem + off + p, PAGE)) diffs++;
        }
    }
    double t_full = now_ms() - t0;

    /* 2. the pagemap prefilter */
    int fp = pm_open(0), fc = pm_open(child);
    if (fp < 0 || fc < 0) { perror("pagemap open"); kill(child, SIGKILL); return 1; }
    uint64_t *pp = malloc(npages * 8), *pc = malloc(npages * 8);
    t0 = now_ms();
    int ok = pm_read(fp, mem, pp, npages) == 0 && pm_read(fc, mem, pc, npages) == 0;
    double t_pm = now_ms() - t0;
    if (!ok) { fprintf(stderr, "pagemap read failed: %s\n", strerror(errno));
               kill(child, SIGKILL); return 1; }

    uint64_t shared = 0, nopfn = 0, candidates = 0;
    for (size_t i = 0; i < npages; i++) {
        uint64_t a = pp[i], b = pc[i];
        if (!(a & PM_PRESENT) || !(b & PM_PRESENT) ||
            (a & PM_SWAP) || (b & PM_SWAP) ||
            (a & PM_PFN) == 0 || (b & PM_PFN) == 0) { nopfn++; candidates++; continue; }
        if ((a & PM_PFN) == (b & PM_PFN)) shared++; else candidates++;
    }

    /* 3. compare only the candidates */
    t0 = now_ms();
    uint64_t diffs2 = 0;
    for (size_t i = 0; i < npages; i++) {
        uint64_t a = pp[i], b = pc[i];
        bool skip = (a & PM_PRESENT) && (b & PM_PRESENT) && !(a & PM_SWAP) &&
                    !(b & PM_SWAP) && (a & PM_PFN) && (b & PM_PFN) &&
                    (a & PM_PFN) == (b & PM_PFN);
        if (skip) continue;
        struct iovec lo = { buf, PAGE }, re = { mem + i * PAGE, PAGE };
        if (process_vm_readv(child, &lo, 1, &re, 1, 0) != (ssize_t)PAGE) continue;
        if (memcmp(buf, mem + i * PAGE, PAGE)) diffs2++;
    }
    double t_cand = now_ms() - t0;

    printf("RAM %zu MB (%zu pages), workload wrote %zu distinct pages over %zu laps\n",
           mb, npages, dirty_pages, laps);
    printf("  full oracle      %8.2f ms   diffs=%llu  checked=%llu pages\n",
           t_full, (unsigned long long)diffs, (unsigned long long)checked);
    printf("  pagemap read     %8.2f ms   (2 x %zu KB)\n", t_pm, npages * 8 / 1024);
    printf("  candidates       %8.2f ms   %llu pages (%.4f%%), shared=%llu, no-pfn=%llu\n",
           t_cand, (unsigned long long)candidates,
           100.0 * candidates / npages, (unsigned long long)shared,
           (unsigned long long)nopfn);
    printf("  filtered total   %8.2f ms   diffs=%llu  => %.1fx\n",
           t_pm + t_cand, (unsigned long long)diffs2,
           t_full / (t_pm + t_cand));
    printf("  AGREEMENT: %s\n", diffs == diffs2 ? "same answer" : "DIFFERENT ANSWER");
    kill(child, SIGKILL); waitpid(child, NULL, 0);
    return diffs == diffs2 ? 0 : 2;
}
