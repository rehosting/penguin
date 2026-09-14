/* bugbench: a victim with a KNOWN set of planted bugs, used as ground truth.
 *
 * Nothing here relates to any real device. Every bug below is deliberate, and
 * the point is that the set is CLOSED and KNOWN: we can say in advance exactly
 * which crashes a working fuzzer should find, at which program counters, from
 * which inputs. Without that, "the fuzzer found three crashes" is unfalsifiable
 * -- there is no denominator, and no way to tell a real miss from a weak
 * mutator.
 *
 * DESIGN RULES, each one there because its absence would make a result
 * unreadable:
 *
 *  1. Every bug reaches a DISTINCT faulting instruction. Two bugs sharing a PC
 *     cannot be told apart in crashes.yaml, so "found 2 of 7" would be
 *     unverifiable.
 *  2. Every bug is deterministic: the same input always faults, at the same
 *     place. A flaky bug makes a missing crash ambiguous between "not found"
 *     and "found but did not reproduce".
 *  3. Difficulty is graded and declared. B1-B3 are reachable by almost any
 *     input; B4-B5 need a specific byte; B6 needs a 4-byte magic; B7 needs two
 *     independent conditions. A fuzzer that finds only B1-B3 is doing something
 *     -- but not coverage-guided search, and the split says so.
 *  4. There is a NEGATIVE CONTROL: opcode 0x00 is an explicitly safe path that
 *     must never fault. If it ever appears in a crash report, the harness is
 *     manufacturing crashes and no positive result can be believed.
 *  5. There is a CANARY: B1 is trivially reachable by a random byte. If a run
 *     reports zero crashes INCLUDING B1, the plumbing is broken -- injection,
 *     detection or attribution -- and the correct conclusion is "harness
 *     broken", not "target is robust".
 *
 * The signals are deliberately mixed (SIGSEGV, SIGFPE, SIGBUS) because the
 * crash plugin watches a set of signals, and a victim that only ever raises
 * SIGSEGV cannot show whether the others are wired up.
 *
 * Request layout: req[0] = opcode, req[1..] = operands.
 */
#include <fcntl.h>
#include <unistd.h>

#define REQ_MAX 256

/* Kept out of line and non-static-inlinable so each bug owns a frame and a
 * recognisable address. volatile sinks stop the copies being optimised away. */
#define NOINL __attribute__((noinline))

static volatile unsigned int sink;
static volatile unsigned char bsink;

/* B1 (canary, trivial): unvalidated length copy into a 16-byte stack buffer.
 * Triggered by opcode 0x01 with req[1] > 16. */
NOINL static void bug1_stack_overflow(const unsigned char *req, int n)
{
    volatile char small[16];
    int len = req[1];
    int i;

    if (len > n) {
        len = n;
    }
    for (i = 0; i < len; i++) {
        small[i] = (char)req[i];
    }
    bsink = small[0];
}

/* B2 (trivial): NULL dereference. Opcode 0x02. */
NOINL static void bug2_null_deref(const unsigned char *req)
{
    volatile unsigned int *p = (volatile unsigned int *)0;

    if (req[1] != 0xff) {
        sink = *p;
    }
}

/* B3 (trivial): divide by zero -> SIGFPE on most arches. Opcode 0x03. */
NOINL static void bug3_div_zero(const unsigned char *req)
{
    int d = req[1];

    sink = (unsigned int)(1000 / d);   /* d == 0 faults */
}

/* B4 (easy): read far past a small table. Opcode 0x04, index in req[1]. */
NOINL static void bug4_oob_read(const unsigned char *req)
{
    static const unsigned char table[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    unsigned int idx = (unsigned int)req[1] * 0x00100000u;

    bsink = table[idx];
}

/* B5 (easy): wild write through an address built from the input.
 * Opcode 0x05; req[1] scales the target so it lands outside any mapping. */
NOINL static void bug5_wild_write(const unsigned char *req)
{
    volatile unsigned int *p =
        (volatile unsigned int *)((unsigned long)req[1] << 28);

    if (req[1] >= 0x40) {
        *p = 0xdeadbeef;
    }
}

/* B6 (hard for blind mutation): guarded by a 4-byte magic. Opcode 0x06 and
 * req[1..4] == "FUZZ". Random bytes hit this with probability 2^-32; a
 * coverage-guided fuzzer with the magic in its corpus or dictionary walks in. */
NOINL static void bug6_magic_guard(const unsigned char *req)
{
    if (req[1] == 'F' && req[2] == 'U' && req[3] == 'Z' && req[4] == 'Z') {
        volatile unsigned int *p = (volatile unsigned int *)0xa5a5a5a4ul;
        *p = 1;
    }
}

/* B7 (hardest): two independent conditions, each individually reachable, that
 * must both hold. Opcode 0x07, req[1] == 0x5a, and the sum of req[2..5] == 255.
 * Rewards a fuzzer that preserves partial progress; blind mutation stalls. */
NOINL static void bug7_two_condition(const unsigned char *req)
{
    unsigned int sum = (unsigned int)req[2] + req[3] + req[4] + req[5];

    if (req[1] == 0x5a && sum == 255) {
        /* misaligned access -> SIGBUS on strict-alignment targets, SIGSEGV
         * where unaligned access is permitted. Either is a distinct crash. */
        volatile unsigned int *p = (volatile unsigned int *)0x1u;
        *p = 2;
    }
}

/* NEGATIVE CONTROL. Opcode 0x00 must never fault, whatever follows it.
 * A crash attributed here means the harness is fabricating. */
NOINL static void safe_path(const unsigned char *req, int n)
{
    int i;
    unsigned int acc = 0;

    for (i = 1; i < n && i < 32; i++) {
        acc += req[i];
    }
    sink = acc;
}

NOINL static void dispatch(const unsigned char *req, int n)
{
    if (n < 8) {
        return;             /* every bug below indexes at least req[5] */
    }
    switch (req[0]) {
    case 0x00: safe_path(req, n);        break;
    case 0x01: bug1_stack_overflow(req, n); break;
    case 0x02: bug2_null_deref(req);     break;
    case 0x03: bug3_div_zero(req);       break;
    case 0x04: bug4_oob_read(req);       break;
    case 0x05: bug5_wild_write(req);     break;
    case 0x06: bug6_magic_guard(req);    break;
    case 0x07: bug7_two_condition(req);  break;
    default:   safe_path(req, n);        break;
    }
}

#ifdef BUGBENCH_STDIN
/*
 * Native validation mode. Reads ONE request from stdin and dispatches it, so
 * the ground-truth manifest can be checked on the host without a guest, a
 * rehost or an injector. The manifest is what every later score is graded
 * against; if a trigger listed there does not actually fault, every "bug not
 * found" verdict built on it is meaningless, and that has to be checkable
 * cheaply enough that it is actually checked.
 */
int main(void)
{
    unsigned char req[REQ_MAX];
    int n = (int)read(0, req, REQ_MAX);

    if (n <= 0) {
        return 1;
    }
    dispatch(req, n);
    return 0;
}
#elif defined(BUGBENCH_BENCH)
/*
 * Rate-measurement mode, used only by `usermode_bench.py` to price this victim
 * under qemu-user against the full-system snapshot loop. It lives here, behind
 * an ifdef, rather than in a file of its own: a second copy of the victim would
 * turn the comparison into a comparison of two programs. Nothing above this
 * line changes, so the ground-truth manifest is unaffected.
 *
 * argv[1] selects the shape:
 *   "persist"  every record dispatched in this process. No isolation between
 *              inputs -- the upper bound for a user-mode loop, and the
 *              counterpart of the loop's `bare` arm.
 *   "fork"     every record dispatched in a fresh child. AFL's forkserver
 *              shape: the ELF is loaded and the code translated once, in the
 *              parent, and each input runs against a copy-on-write clone.
 *
 * Records are fixed-size and read from stdin, which the harness points at a
 * regular file, so no driver process sits inside the measured loop.
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_REC 16

/* Report the record count on stderr without stdio, which the rest of this file
 * also avoids. A run that consumed nothing must not read as a fast one, so the
 * harness checks this against the number of records it wrote. */
static void write_count(long v)
{
    char digits[24];
    char out[26];
    int t = 0, k = 0;

    if (v == 0) {
        digits[t++] = '0';
    }
    while (v > 0) {
        digits[t++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (t > 0) {
        out[k++] = digits[--t];
    }
    out[k++] = '\n';
    if (write(2, out, (unsigned)k) < 0) {
        return;
    }
}

int main(int argc, char **argv)
{
    unsigned char req[BENCH_REC];
    int do_fork = (argc > 1 && strcmp(argv[1], "fork") == 0);
    long i;
    long touch_mb = (argc > 2) ? atol(argv[2]) : 0;
    /* argv[3]: extra syscalls per record. The comparison against the
     * full-system loop turns on cost PER SYSCALL, not per iteration, and the
     * user-mode side of that term was the one number still estimated. A
     * getpid() is the cheapest real syscall available -- glibc stopped caching
     * it in 2.25, so each call is a genuine trap. */
    long extra_calls = (argc > 3) ? atol(argv[3]) : 0;
    long done = 0;

    /* argv[2] is how many MB to allocate and TOUCH before the loop starts.
     * It is the whole point of the scaling experiment: fork must copy the page
     * tables of everything mapped, so its cost grows with the address space,
     * while a dirty-page snapshot reset pays for the pages an iteration wrote.
     * Touching matters -- an untouched mapping has no page table entries to
     * copy, and would show fork as free. */
    if (touch_mb > 0) {
        long bytes = touch_mb * 1024L * 1024L;
        char *blob = (char *)malloc((size_t)bytes);
        long i;

        if (blob == (char *)0) {
            return 3;
        }
        for (i = 0; i < bytes; i += 4096) {
            blob[i] = (char)(i & 0xff);
        }
    }

    for (;;) {
        int got = 0;

        /* A short read is not end of input on every fd the harness might pass,
         * so fill the record before deciding the stream ended. */
        while (got < BENCH_REC) {
            int r = (int)read(0, req + got, (unsigned)(BENCH_REC - got));
            if (r <= 0) {
                break;
            }
            got += r;
        }
        if (got < BENCH_REC) {
            break;
        }

        for (i = 0; i < extra_calls; i++) {
            sink += (unsigned int)getpid();
        }

        if (do_fork) {
            pid_t p = fork();

            if (p == 0) {
                dispatch(req, BENCH_REC);
                _exit(0);
            }
            if (p < 0) {
                return 2;
            }
            waitpid(p, (int *)0, 0);
        } else {
            dispatch(req, BENCH_REC);
        }
        done++;
    }

    write_count(done);
    return 0;
}
#else
int main(void)
{
    unsigned char req[REQ_MAX];
    int fd = open("/dev/zero", O_RDONLY);
    int i, n;

    if (fd < 0) {
        return 1;
    }
    /* The descriptor is only a clock: the harness rewrites the buffer and the
     * return value at the read() boundary. Reading /dev/zero rather than a
     * socket keeps networking out of an experiment that is not about it. */
    for (i = 0; i < 4096; i++) {
        n = read(fd, req, REQ_MAX);
        if (n <= 0) {
            break;
        }
        dispatch(req, n);
    }
    close(fd);
    return 0;
}
#endif /* BUGBENCH_STDIN / BUGBENCH_BENCH */
