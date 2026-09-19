"""Feed the victim from INSIDE the snapshot boundary, so a reset can rewind it.

WHY THIS EXISTS
---------------
`fastloop` resets the guest and replays a span. Three real targets were
measured replaying a span that was not the one they armed on:

    target A   forward     3.79 ms -> replayed 14,949 ms    3,945x SLOWER
    target B   forward   476.59 ms -> replayed      6.28 ms     76x FASTER
    target C   forward     1.64 ms -> replayed    160.02 ms     97x SLOWER

The oracle certified every one of those restores byte for byte -- 2.16 GB on
target B, ten times over -- so the divergence is not in the guest state. It is
in the world OUTSIDE it. The reset rewinds guest RAM and devices; it does not
rewind the host-side socket. When the armed span ends in a `read()` on a TCP
connection, replaying it means reading data that was already consumed and will
never be delivered again, so the guest waits on a timer (A and C); or reading
data that arrived DURING the forward traversal and is still queued, so the
guest never waits at all (B).

`fuzzdrive` does not fix this and was never meant to: it rewrites the buffer at
the read RETURN, so the read has already completed and the host-side data still
had to arrive. It is a mutator, not a feeder.

This plugin closes the loop by making the read never reach the host:

    on read ENTER for a connection fd
        write the payload into the guest's buffer
        syscall.retval      = len(payload)
        syscall.skip_syscall = True        <- the real read() never runs

Everything the guest consumes now comes from guest RAM, written by us, inside
the snapshot boundary. There is no host-side state left in the iteration for
the reset to fail to rewind.

WHICH READS
-----------
At the read RETURN you can tell an HTTP request by looking at the bytes, which
is what `fuzzdrive` does. At ENTER the buffer is empty and that is not
available, so the connection fds are learned from `accept`/`accept4` returns
instead. That is target-agnostic -- every TCP server accepts before it reads --
and it stays host-side, with nothing instrumented inside the guest.

The learned set lives in host Python and is NOT rewound by a reset. That is
correct rather than a bug: the guest's fd table IS rewound, so after a restore
the guest re-reads the same fd it held at the armed instant, and a set that is
a superset of the live fds still matches it.

CONTROLS
--------
A feeder that silently feeds nothing looks exactly like a fast loop, and that
failure has already happened once in this lane: 200,000 laps at 0.294 ms and
3,396 exec/s, for a guest nothing was being injected into. So:

  n_sent        every delivery, for `fastloop`'s arm_progress -- the idle axis
                refuses a draw where this does not advance.
  n_unmatched   reads on fds we never learned. If this is large and n_sent is
                zero, the accept hook never fired and the run is measuring an
                unfed guest. Reported, and warned about once.
  responses     status codes the victim wrote back. A feeder whose payloads are
                all rejected at byte one is reaching none of the parser, and a
                run that cannot tell that apart from "no crashes" is not a
                measurement.
"""

import json
import os
import random
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

SEEDS = [
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
    b"GET /cgi-bin/sysinfo.cgi HTTP/1.1\r\nHost: x\r\n"
    b"Authorization: Basic QUFBQUFBQUE=\r\n\r\n",
    b"POST /cgi-bin/login.cgi HTTP/1.1\r\nHost: x\r\n"
    b"Content-Length: 4\r\n\r\nAAAA",
    b"GET /../../etc/passwd HTTP/1.0\r\n\r\n",
]

HEADERS = [b"Host", b"Authorization", b"Connection", b"Content-Length",
           b"Range", b"If-Modified-Since", b"Cookie", b"Referer",
           b"Transfer-Encoding", b"Expect", b"User-Agent"]


class SnapFeed(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        # `x or default` is wrong for any arg whose meaningful value is 0 or
        # "": `mutate: 0` became `0 or 1` and mutation could not be switched
        # off at all. Caught by the host test before a boot was spent on a
        # "control" run that was still mutating.
        self.rng = random.Random(int(self._arg("seed", 1337)))
        # Off by default. A passthrough read is a read that goes to the host,
        # which is the single thing this plugin exists to remove -- in a loop
        # it reintroduces exactly the unrewindable state the reset cannot
        # handle. It stays available because a snapshot-free control run wants
        # it, and it is reported so a loop run cannot use it without saying so.
        self.passthrough = float(self._arg("passthrough", 0.0))
        self.mutate_on = bool(int(self._arg("mutate", 1)))

        # ---- the coverage-guided corpus ----------------------------------
        #
        # OFF BY DEFAULT, and that is a control rather than caution. Every
        # rate and every coverage figure this lane has published was measured
        # with mutation drawing from the five fixed SEEDS and nothing else, so
        # a run with this on is not comparable to them unless the pairing is
        # deliberate. It also makes the A/B possible at all: one run 0, one
        # run 1, same seed, same draw axis.
        #
        # WHAT IT DOES. fastloop announces each lap's new-edge count with the
        # lap boundary. A lap that reached somewhere new had its input fed by
        # this plugin, so that input goes into a corpus, and later mutations
        # draw their base from the corpus instead of always from a seed. That
        # is the only thing standing between "coverage is measured" and
        # "coverage is guiding", which is the honest limitation on every
        # number this lane reports.
        self.corpus_on = bool(int(self._arg("corpus", 0)))
        # Bounded on purpose. An unbounded corpus on a 12,000-lap run is a
        # slow memory leak whose symptom is a run that gets gradually worse,
        # and random replacement at the cap is both cheap and honest about
        # not being AFL's favoured-set logic.
        self.corpus_max = int(self._arg("corpus_max", 256))
        # How often a mutation starts from something discovered rather than
        # from a seed. Not 1.0: the seeds are the only inputs known to reach
        # the victim's normal paths, and a corpus that has drifted into
        # malformed requests would otherwise never find its way back.
        self.corpus_p = float(self._arg("corpus_p", 0.5))
        # THE BOUNDARY GUARD, and this run cannot have a corpus without it.
        #
        # This workload's laps are bimodal: a few per thousand replay a
        # connection boundary -- a guest fork+exec -- worth ~29,000 edges
        # against a typical lap's ~2,800. Those laps report enormous novelty
        # that the INPUT had nothing to do with, and they are exactly the laps
        # a corpus would rate highest. Unguarded, the corpus fills with
        # whatever request happened to be in flight when the guest forked, and
        # every one of those entries is credited for coverage it did not
        # cause.
        #
        # So a lap whose TOTAL edge count is more than this multiple of the
        # running median is not allowed to contribute, however new it looks.
        # Measured separation is ~4.8x (median 4,849, max 23,188), so 3.0 is
        # clear of both sides. Set 0 to disable the guard, which is only
        # sensible on a target whose laps are not bimodal.
        self.corpus_boundary_mult = float(self._arg("corpus_boundary_mult", 3.0))

        self.corpus = []             # payloads that reached somewhere new
        self._corpus_seen = set()    # exact-bytes dedup
        self._lap_fed = []           # (payload, provenance) fed this lap
        self._lap_edges = []         # recent per-lap totals, for the median
        self.n_corpus_add = 0
        self.n_corpus_dup = 0        # new coverage, payload already held
        self.n_corpus_evict = 0      # added at the cap, so something left
        self.n_corpus_reject_boundary = 0
        self.n_corpus_draw = 0       # mutations based on a corpus entry
        self.n_seed_draw = 0         # ...and on a seed
        # Laps that found new coverage, split by where their input came from.
        # THIS IS THE FIGURE THAT SAYS WHETHER THE CORPUS WORKS. Corpus size
        # does not: a corpus can grow steadily while contributing nothing,
        # because the seeds are still finding everything.
        self.n_new_from_corpus = 0
        self.n_new_from_seed = 0
        # The same split weighted by how MUCH was found, not just by how
        # often. Only credited when the lap fed exactly one payload, which is
        # almost all of them here -- measured at 1.012 feeds per lap on run
        # 116 -- because a lap that fed two cannot say which of them did it,
        # and splitting or double-counting would both invent a number.
        self.edges_from_corpus = 0
        self.edges_from_seed = 0
        self.n_multi_fed_laps = 0
        self._cov_absent_laps = 0    # laps that arrived with no coverage
        self._warned_cov_absent = False
        # OFF by default, and that default is a correction. It shipped as ON
        # because exclusive mode needs it -- a frozen peer never drains the
        # socket, so the victim wedges in writev the first time a send buffer
        # fills. But with a LIVE client, output drives input: swallowing the
        # response means the client never sends the next pipelined request and
        # waits out its timeout instead.
        #
        # Measured. Target B's rate comes from keep-alive batches of 20
        # pipelined requests. With responses swallowed its forward gaps went
        # from a ~183 ms median to ~1038 ms and the loop settled at 0.96
        # exec/s -- faithfully replaying a span that this plugin had made
        # slow. Turn it on with exclusive mode, where there is no client left
        # to starve, and leave it off otherwise.
        self.swallow_writes = bool(int(self._arg("swallow_writes", 0)))
        # iovec is two pointer-sized fields; 4 on every target in this lane.
        self.ptr_size = int(self._arg("ptr_size", 4))
        self.pin_filter = bool(int(self._arg("pin_filter", 0)))
        self.answer_select = bool(int(self._arg("answer_select", 1)))
        # The same problem as answer_select, one syscall over. A victim that
        # waits in epoll_wait() never reaches the read() this plugin feeds,
        # and the lap becomes the epoll timeout instead of the guest's work.
        # Measured on target A: every forward traversal 1048-1051 ms, laps
        # flat to 0.02% -- a timer, not a workload -- with n_select at exactly
        # 0 because this lighttpd uses epoll and nothing here answered it.
        # snapfeed's own comment already recorded the select version of this
        # at 1038 ms per lap. Same bug, different syscall.
        self.answer_epoll = bool(int(self._arg("answer_epoll", 1)))
        # struct epoll_event is PACKED ON x86_64 ONLY (see
        # include/uapi/linux/eventpoll.h: EPOLL_PACKED is empty elsewhere), so
        # it is {u32 events; u64 data;} = 12 bytes with data at 4 there, and
        # 16 bytes with data at 8 on every 32-bit target in this lane, where
        # the u64 takes its natural 8-byte alignment. Guessing wrong writes
        # the payload into the wrong half of the struct and the victim
        # dereferences garbage, so these are arguments rather than a constant.
        self.epoll_ev_size = int(self._arg("epoll_ev_size", 16))
        self.epoll_data_off = int(self._arg("epoll_data_off", 8))
        # fd -> the 8 data bytes the victim registered for it. epoll_wait must
        # hand BACK exactly what epoll_ctl was given: lighttpd stores a
        # pointer to its connection object there and dereferences it. A
        # synthesised event with the right fd and the wrong data is worse than
        # no event at all.
        self.epoll_reg = {}
        # One outstanding request per connection: feed a request, then say
        # nothing more until the victim has written its response.
        #
        # This was invisible while the victim blocked in epoll_wait, because
        # that wait WAS the throttle -- one request per ~1 s, and 7,224 feeds
        # produced 4,569 responses. Answering epoll removed the throttle and
        # the feeder turned out to have none of its own: 328,052 requests fed
        # against 85 responses written. snapfeed answers every read(), so
        # lighttpd never saw a would-block, never left its read loop, and
        # never reached the writev the loop detects.
        #
        # Request/response alternation is also just what an HTTP client does
        # on a keep-alive connection, and what a fuzzer wants: one input per
        # iteration, with the response as the iteration boundary -- which is
        # exactly what fastloop's writev detector keys on. Set 0 to restore
        # the unbounded feeder for a victim that genuinely pipelines.
        self.one_outstanding = bool(int(self._arg("one_outstanding", 1)))
        # KEEP THE CONNECTION ALIVE, because this feeder cannot replace one.
        #
        # snapfeed feeds ACCEPTED fds and cannot synthesise accept(), so the
        # connection it feeds is a resource only the guest can produce. Two of
        # the five seeds and several of the mutations ask the victim to end
        # it: SEEDS[4] is `GET /../../etc/passwd HTTP/1.0` with no Connection
        # header, which lighttpd answers and closes, and mutate() truncates
        # the request outright one op in five.
        #
        # That was survivable only because the guest driver opened a fresh
        # connection per request -- which is itself the 1.05 s wait this lane
        # spent a day chasing. With a driver that holds ONE connection open,
        # the first closing feed ends the run: observed directly on run 103,
        # `netstat` in the guest showing a single socket in CLOSE_WAIT and the
        # emulator at 2% CPU with nothing left to serve.
        #
        # Off by default: the closing requests are real inputs and a fuzzer
        # wants them. On when the loop depends on the connection outliving the
        # input. It REDUCES closes, it does not remove them -- a mangled
        # request can still draw a 400 and a close, which is why the guest
        # side must notice and reconnect regardless.
        self.keepalive = bool(int(self._arg("keepalive", 0)))
        self.n_keepalive_fixed = 0
        # KEEP THE REQUEST ANSWERABLE, which is a different demand from
        # keeping the connection open and fails a different way.
        #
        # `one_outstanding` withholds the next feed until the victim answers,
        # because the answer is the loop's iteration boundary. A request the
        # victim CANNOT answer therefore stops the loop rather than slowing
        # it: mutate() truncates one op in five, lighttpd waits for the rest
        # of the request, the withheld read returns EAGAIN, the epoll answer
        # excludes the pending fd, and nothing moves until lighttpd's
        # read-idle timeout tens of seconds later.
        #
        # Under a connection-per-request driver that cost one connection in
        # 1,537 and was invisible. Against a held-open connection it is the
        # whole run. Observed as a socket pair cycling CLOSE_WAIT/FIN_WAIT2
        # with the guest at 1.8% CPU.
        #
        # This does NOT make the request valid -- a 400 is an answer and a
        # perfectly good fuzzing outcome. It makes it COMPLETE, which is the
        # property the alternation actually depends on.
        self.complete_request = bool(int(self._arg("complete_request", 0)))
        self.n_completed = 0
        self.pending = set()     # fds fed a request that is not yet answered
        # WHY an epoll_wait was left alone, not just that it was. n_epoll came
        # back 0 against 2,391 passes and one counter could not say whether
        # the fds were unknown, unregistered, busy, or waiting on something
        # else entirely -- four different bugs behind one number, and a
        # control that cannot distinguish its own failure modes costs a run
        # per guess.
        # A plain dict, not a Counter: test_snapfeed loads this module through
        # an AST whitelist that admits `import json/os/random/time` and drops
        # every `from ... import ...`, so a collections import here is present
        # in the file and absent under test -- a NameError that only ever
        # appears in the harness.
        self._epass = {}
        # The events word is a u32 written into guest memory, so it has to go
        # out in the guest's byte order. Two of this lane's targets are
        # big-endian (mipseb, ppc), and a byte-swapped EPOLLIN is 0x01000000 --
        # not a flag the victim recognises, so it would see an event with no
        # readiness bits and loop, which looks exactly like this plugin doing
        # nothing rather than like a bug.
        self._little = getattr(getattr(self, "panda", None),
                               "endianness", "little") != "big"
        # The syscall census. OFF by default, and the default changed once the
        # per-syscall cost was actually measured -- see the census block below.
        self.census_on = bool(int(self._arg("census", 0)))
        # Requests fed per connection before returning EOF. 0 = unlimited
        # (right for keep-alive); 1 matches a connection-per-request victim.
        self.feeds_per_conn = int(self._arg("feeds_per_conn", 0))
        # fd_set is FD_SETSIZE bits. 1024 on every target here; read and
        # written as bytes so word size does not matter.
        self.fdset_bytes = int(self._arg("fdset_bytes", 128))
        self.census = {}         # which syscalls the victim actually makes
        self.fd_feeds = {}       # per-fd feed count, for the EOF rule
        self.n_lap_resets = 0    # laps that rewound the feed counts
        self.n_eof = 0           # connections ended by returning 0
        self.n_select = 0        # selects answered without reaching the host
        self.n_withheld = 0      # reads left alone: response still outstanding
        self.n_epoll = 0         # epoll_waits answered without reaching the host
        self.n_epoll_pass = 0    # ...and those left alone
        self.n_select_pass = 0   # ...and those left alone

        self.n_sent = 0          # deliveries -- fastloop's arm_progress
        self.n_pass = 0          # CONTROL: reads left to the host
        self.n_unmatched = 0     # CONTROL: reads on fds we never learned
        self.n_accept = 0        # connection fds learned
        self.n_writes = 0        # responses seen
        self.n_swallowed = 0     # responses that never reached the socket
        self.fds = set()
        self.responses = {}      # CONTROL: status codes written back
        self.t_first = None
        self.t_last = None
        self._warned_unmatched = False

        # `comm` alone would also feed a forked worker carrying the same
        # name, which is a different process than the loop armed in. pin_filter
        # confines every one of these to the pinned subtree once a pin exists,
        # and is inert before that.
        pf = self.pin_filter
        syscalls.syscall("on_sys_accept_return", comm_filter=self.comm,
                         pin_filter=pf)(self.on_accept)
        syscalls.syscall("on_sys_accept4_return", comm_filter=self.comm,
                         pin_filter=pf)(self.on_accept)
        syscalls.syscall("on_sys_read_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_read_enter)
        # recv()/recvfrom() as well as read(). Target C's vendor httpd accepted
        # 556 connections and issued EIGHT read() calls, none of them on a
        # learned fd -- it takes its sockets with recv(). snapfeed reported
        # FED NOTHING, correctly, and would have gone on reporting it forever
        # while the victim served happily through a syscall nobody hooked.
        # The import list said so from the start: `accept read recv select`.
        syscalls.syscall("on_sys_recv_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_recv_enter)
        syscalls.syscall("on_sys_recvfrom_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_recv_enter)
        syscalls.syscall("on_sys_writev_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_writev_enter)
        # write() as well as writev(). Target C's vendor httpd imports only
        # accept/read/recv/select and never calls writev, so a writev-only
        # hook tallied nothing and snapfeed reported "fed N inputs but the
        # victim wrote NO parseable response" -- a false alarm from the
        # control that exists to catch a wedged victim, on a victim that was
        # answering perfectly well through a different syscall.
        syscalls.syscall("on_sys_write_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_write_enter)
        # A CENSUS, not an intervention. Three hypotheses about where the
        # victim waits have now been wrong -- the detector, then select() --
        # and each cost a build and a run to disprove. These hooks only COUNT,
        # so the next run names the blocking syscall instead of testing
        # another guess.
        #
        # OFF BY DEFAULT, and this comment used to end "Cheap: one counter
        # increment per call, no memory access, no skip." That was wrong, and
        # wrong by about two orders of magnitude. The Python body IS one
        # increment -- 0.72 us, measured -- but the body is not what a hook
        # costs. Getting to it costs a guest hypercall trap, a portal
        # round trip and a dispatch, and `speedscheme.py` prices the whole
        # path at ~93 us against an UNHOOKED syscall's 1.16 us. Roughly 80x,
        # for a counter.
        #
        # Fifteen hooks on the syscalls a busy server makes constantly --
        # poll, futex, close, recvfrom -- is therefore not a rounding error on
        # a lap, it is potentially the largest single item in one. Nothing
        # here ever measured that, because "cheap" was asserted rather than
        # priced, and the census is a DIAGNOSTIC that has already returned its
        # answer: the blocking syscall was named, select() is handled, and
        # every lane target is running without it.
        #
        # It stays available for the next unknown victim, because it is the
        # right tool for that job -- it just is not free, so turning it on is
        # now a decision rather than a default. `census: 1` restores it.
        if self.census_on:
            for nm in ("epoll_wait", "epoll_pwait", "poll", "ppoll", "accept",
                       "accept4", "nanosleep", "clock_nanosleep", "futex",
                       "recvfrom", "recvmsg", "sendto", "sendmsg", "close",
                       "shutdown"):
                syscalls.syscall(f"on_sys_{nm}_enter", comm_filter=self.comm,
                                 pin_filter=pf)(self._census(nm))
        if self.answer_select:
            # A victim that waits in select() never reaches the read() this
            # plugin feeds. Target A gets to read() directly and won 28x;
            # target B blocks in select first and sat at 1038 ms per lap
            # feeding perfectly well into a victim that was not listening.
            # Both vendor httpds in this lane import exactly
            # `accept read recv select`, so this is the common shape, not the
            # exception.
            for nm in ("select", "_newselect", "pselect6"):
                syscalls.syscall(f"on_sys_{nm}_enter", comm_filter=self.comm,
                                 pin_filter=pf)(self.on_select_enter)
        if self.answer_epoll:
            # epoll_ctl is watched, not answered: it is how the data payload
            # for each fd is learned. Cheap -- a victim registers each
            # connection once and then waits on it many times.
            syscalls.syscall("on_sys_epoll_ctl_enter", comm_filter=self.comm,
                             pin_filter=pf)(self.on_epoll_ctl_enter)
            for nm in ("epoll_wait", "epoll_pwait"):
                syscalls.syscall(f"on_sys_{nm}_enter", comm_filter=self.comm,
                                 pin_filter=pf)(self.on_epoll_wait_enter)
        # Follow the loop's rewinds, when there is a loop. Optional on
        # purpose: snapfeed is useful without fastsnap, and a missing
        # subscription must degrade to "no per-lap reset", not to no feeder.
        try:
            plugins.subscribe(plugins.fastloop, "on_lap", self.on_lap)
            self.lap_subscribed = True
        except Exception as e:                              # noqa: BLE001
            self.lap_subscribed = False
            if self.feeds_per_conn:
                self.logger.warning(
                    f"snapfeed: feeds_per_conn is set but the lap event is "
                    f"not available ({e!r}), so the per-fd allowance is NOT "
                    f"rewound with the guest. A replayed span that was fed a "
                    f"request will get EOF instead, and the loop will read "
                    f"that as the guest changing behaviour.")
        self.logger.info(
            f"snapfeed: armed on comm={self.comm!r}, passthrough="
            f"{self.passthrough} (0.0 means nothing reaches the host), "
            f"mutate={self.mutate_on}, seeds={len(SEEDS)}")

    def _arg(self, name, default):
        v = self.get_arg(name)
        return default if v is None or v == "" else v

    # ---- learning the connection fds --------------------------------------

    def on_lap(self, lap=None, closed_by=None, new_edges=None,
               lap_edges=None, *a):
        """The loop rewound the guest; rewind what this plugin knows too, and
        bank the input if the lap it just closed reached somewhere new.

        THE PARAMETERS ARE THE PUBLISHED ARGS, NOT (plugin, event). This was
        written as `on_lap(self, plugin=None, event=None, *a)` and the names
        were wrong: plugin_manager's publish() calls `cb(*args)` with only the
        publisher's own arguments, so the first two have always been `lap` and
        `closed_by`. Nothing broke because nothing read them -- but the next
        parameter added would have been read, and would have been off by two.

        `fd_feeds` lives in host Python and the guest's fd state does not --
        the reset restores the guest to before the read, but the feed count
        stays where it was, so the replay of a span that was FED a request
        gets EOF instead. Same span, different answer, which is precisely the
        divergence the fidelity check exists to catch, manufactured by the
        feeder itself.

        The same trap as the driver pin's counters, from the other side:
        there, guest-side state was rewound when the reader assumed it was
        not; here, host-side state is NOT rewound when the guest assumes it
        is. Anything a replay depends on has to be rewound with it.

        THE CORPUS IS THE EXCEPTION, and deliberately so. It is campaign
        state, like the cumulative edge map in QEMU: it accumulates ACROSS
        laps because that is the whole point of it. `_lap_fed` is the per-lap
        half and is cleared here with everything else.
        """
        fed, self._lap_fed = self._lap_fed, []
        self.fd_feeds.clear()
        self.n_lap_resets += 1
        # The guest was rewound to before the request was fed, so the victim
        # is not waiting on a response it never received. Leaving these set
        # would withhold the replayed span's very first feed and stall the
        # lap -- the same class of bug as feeds_per_conn not being rewound.
        self.pending.clear()
        if self.corpus_on:
            self._corpus_lap(fed, new_edges, lap_edges)

    def _corpus_lap(self, fed, new_edges, lap_edges):
        """Decide whether the lap that just closed earned a corpus entry."""
        if new_edges is None:
            # Coverage is off, or this lap had none to summarise. An empty
            # corpus at the end of such a run means the loop never offered
            # anything, NOT that nothing was worth keeping -- and those two
            # look identical from the corpus itself, which is why this is
            # counted and shouted about rather than passed over.
            self._cov_absent_laps += 1
            if not self._warned_cov_absent and self._cov_absent_laps > 50:
                self._warned_cov_absent = True
                self.logger.warning(
                    "snapfeed: corpus is on but the loop is announcing laps "
                    "with no coverage. Set fastloop's `coverage: 1`, or turn "
                    "`corpus` off. As it stands the corpus can never grow and "
                    "the run will read as 'the corpus found nothing'.")
            return

        if lap_edges:
            self._lap_edges.append(lap_edges)
            if len(self._lap_edges) > 512:
                del self._lap_edges[0]

        if not new_edges or not fed:
            return

        # The boundary guard. Computed only on the laps that would otherwise
        # contribute -- about one in ten -- because a median over 512 samples
        # every lap would be real work inside the loop for an answer almost
        # never used.
        if self.corpus_boundary_mult and len(self._lap_edges) >= 64:
            ordered = sorted(self._lap_edges)
            median = ordered[len(ordered) // 2]
            if median and lap_edges > self.corpus_boundary_mult * median:
                self.n_corpus_reject_boundary += 1
                return

        if len(fed) > 1:
            self.n_multi_fed_laps += 1
        for payload, provenance in fed:
            if provenance == "corpus":
                self.n_new_from_corpus += 1
                if len(fed) == 1:
                    self.edges_from_corpus += new_edges
            else:
                self.n_new_from_seed += 1
                if len(fed) == 1:
                    self.edges_from_seed += new_edges
            if payload in self._corpus_seen:
                self.n_corpus_dup += 1
                continue
            self._corpus_seen.add(payload)
            if len(self.corpus) < self.corpus_max:
                self.corpus.append(payload)
            else:
                # Random replacement, not a favoured set. AFL ranks entries by
                # size and speed for the same slot pressure; doing that here
                # would be inventing a scheduler in a plugin whose job is to
                # feed bytes. What this must not do is silently REFUSE at the
                # cap, which freezes the corpus at whatever the first 256 laps
                # happened to find.
                i = self.rng.randrange(len(self.corpus))
                self._corpus_seen.discard(self.corpus[i])
                self.corpus[i] = payload
                self.n_corpus_evict += 1
            self.n_corpus_add += 1

    def _census(self, name):
        """One counting hook. Returns a generator function, because penguin's
        machinery drives every hook with `yield from`."""
        def hook(regs, proto, syscall, *a):
            self.census[name] = self.census.get(name, 0) + 1
            return
            yield
        hook.__name__ = f"census_{name}"
        return hook

    def on_accept(self, regs, proto, syscall, *a):
        fd = int(syscall.retval)
        if fd >= 0:
            self.fds.add(fd)
            # A new connection on this number, so a fresh allowance. This is
            # the only place the per-fd feed count is cleared -- the EOF path
            # must not, because the response is still to come on that fd.
            self.fd_feeds.pop(fd, None)
            self.n_accept += 1

    # ---- mutation ---------------------------------------------------------

    def _mutation_base(self):
        """Where this mutation starts: a discovered input, or a seed.

        Returns (payload, provenance). The provenance is carried all the way
        to the lap boundary so that "did the corpus find this" can be
        answered with a count instead of an argument.
        """
        if (self.corpus_on and self.corpus
                and self.rng.random() < self.corpus_p):
            self.n_corpus_draw += 1
            return self.rng.choice(self.corpus), "corpus"
        self.n_seed_draw += 1
        return self.rng.choice(SEEDS), "seed"

    def mutate(self, base, limit):
        if not self.mutate_on:
            return base[:limit]
        r = self.rng
        out = bytearray(base)
        for _ in range(r.randint(1, 3)):
            op = r.randrange(5)
            if op == 0 and out:
                out[r.randrange(len(out))] ^= 1 << r.randrange(8)
            elif op == 1:
                h = r.choice(HEADERS)
                out = out.replace(
                    b"\r\n\r\n",
                    b"\r\n" + h + b": " + bytes([r.randrange(33, 127)]) *
                    r.choice([64, 512, 3000]) + b"\r\n\r\n", 1)
            elif op == 2:
                h = r.choice(HEADERS)
                out = out.replace(b"\r\n\r\n",
                                  b"\r\n" + h + b": a,,b,,,c\r\n\r\n", 1)
            elif op == 3 and len(out) > 8:
                out = out[:r.randrange(4, len(out))]
            else:
                out = out.replace(b"\r\n\r\n",
                                  b"\r\nRange: bytes=0-,-1,0-0\r\n\r\n", 1)
        return bytes(out)[:limit]

    def _keep_alive(self, payload, limit):
        """Rewrite a fed request so it does not ask the victim to hang up.

        Applied AFTER mutate() on purpose: mutation is the thing most likely
        to produce a closing request, so normalising the seed first would
        protect nothing. Two rewrites, both minimal:

          HTTP/1.0 -> HTTP/1.1   1.0 without an explicit keep-alive closes by
                                 default, which is the whole of SEEDS[4].
          Connection: close      -> keep-alive.

        Deliberately does NOT repair a truncated or otherwise mangled request.
        Mutation's value is that it produces inputs the victim did not expect,
        and a feeder that tidied them would be feeding its own seeds back. The
        guest-side reconnect is what covers the remainder.
        """
        before = payload
        if b"HTTP/1.0" in payload:
            payload = payload.replace(b"HTTP/1.0", b"HTTP/1.1")
        # Case-insensitively, but without a regex: the header is generated by
        # this file or by mutate(), so the two spellings that actually occur
        # are enough, and a regex over attacker-shaped bytes is a cost paid on
        # every single feed.
        for close in (b"Connection: close", b"connection: close"):
            if close in payload:
                payload = payload.replace(close, b"Connection: keep-alive")
        if payload != before:
            self.n_keepalive_fixed += 1
        return payload[:limit]

    def _complete(self, payload, limit):
        """Make a request the victim can finish reading.

        Two ways a mutated request leaves the victim waiting, and both are
        repaired without touching what makes the request interesting:

          no header terminator  -- append CRLFCRLF, trimming the front of the
                                   payload first if `limit` has no room.
          Content-Length lying  -- rewrite the declared length to the body
                                   that is actually there. Padding the body
                                   instead would invent bytes the fuzzer did
                                   not choose; shortening the count keeps
                                   every byte the mutator produced.

        Header corruption, injected junk headers, oversized values and
        duplicated separators all survive untouched. So does a malformed
        request line -- lighttpd answers that with a 400, and a 400 is an
        answer.
        """
        end = payload.find(b"\r\n\r\n")
        if end < 0:
            term = b"\r\n\r\n"
            room = max(0, limit - len(term))
            payload = payload[:room] + term
            self.n_completed += 1
            return payload

        head, body = payload[:end + 4], payload[end + 4:]
        low = head.lower()
        at = low.find(b"content-length:")
        if at < 0:
            return payload
        eol = head.find(b"\r\n", at)
        if eol < 0:
            return payload
        try:
            declared = int(head[at + len(b"content-length:"):eol].strip())
        except ValueError:
            # Not a number any more -- the mutator got to it. lighttpd
            # answers that with a 400 rather than waiting, so it is already
            # answerable and there is nothing to repair.
            return payload
        if declared == len(body):
            return payload
        fixed = (head[:at] + b"Content-Length: " + str(len(body)).encode()
                 + head[eol:] + body)
        self.n_completed += 1
        return fixed[:limit]

    # ---- the feed ---------------------------------------------------------

    def on_read_enter(self, regs, proto, syscall, fd, buf, count):
        limit = int(count)
        if limit <= 0:
            return
        if int(fd) not in self.fds:
            self.n_unmatched += 1
            if self.n_unmatched == 2000 and not self.n_sent:
                self._warned_unmatched = True
                self.logger.warning(
                    f"snapfeed: {self.n_unmatched} reads by {self.comm!r} and "
                    f"NOT ONE on a learned connection fd -- {self.n_accept} "
                    f"accepts seen. Nothing is being fed, so any rate below is "
                    f"the rate of an unfed guest. Check that the victim accepts "
                    f"before it reads, and that comm= names the right process.")
            return

        if self.one_outstanding and int(fd) in self.pending:
            # Already fed; waiting on the response. Let the real read run: on
            # a non-blocking socket it returns EAGAIN, which is precisely the
            # signal that sends the victim off to write its reply.
            self.n_withheld += 1
            return

        if self.passthrough and self.rng.random() < self.passthrough:
            self.n_pass += 1
            return                      # goes to the host -- see __init__

        # EOF, eventually. A feeder that ALWAYS returns a full request never
        # lets the victim see the connection end -- so it never closes it and
        # never accepts another. Measured: 6 accepts against 1,561,776 feeds
        # on a connection-per-request server, after which the `accept`
        # detector had nothing left to fire on and the loop could not arm. A
        # feeder that cannot say "no more data" changes the victim's control
        # flow, not just its content.
        #
        # 0 keeps the unlimited behaviour, which is right for a keep-alive
        # victim driven by a real client.
        if self.feeds_per_conn:
            n = self.fd_feeds.get(int(fd), 0)
            if n >= self.feeds_per_conn:
                syscall.retval = 0            # EOF
                syscall.skip_syscall = True
                self.n_eof += 1
                # DO NOT forget the fd. Discarding it here broke two things at
                # once: the victim's response, written on that same fd moments
                # later, stopped being tallied (reported as "wrote NO
                # parseable response" on a victim answering perfectly well),
                # and after a reset the replayed read landed on a forgotten fd,
                # got no feed, and the injector's counter never advanced --
                # which the idle axis then refused, correctly.
                #
                # The allowance is reset by accept() instead, which is the
                # event that actually means "new connection".
                return
            self.fd_feeds[int(fd)] = n + 1

        base, provenance = self._mutation_base()
        payload = self.mutate(base, limit)
        if self.keepalive:
            payload = self._keep_alive(payload, limit)
        if self.complete_request:
            payload = self._complete(payload, limit)
        if not payload:
            return
        if self.corpus_on:
            # The FINAL bytes, after _keep_alive and _complete, because those
            # are what the victim actually read and therefore what the
            # coverage belongs to. Storing the pre-rewrite mutant would put
            # something in the corpus that was never executed.
            self._lap_fed.append((payload, provenance))
        yield from plugins.mem.write_bytes(buf, payload)
        syscall.retval = len(payload)
        # THE POINT. Without this the real read() still runs, the guest still
        # depends on host-side data, and the reset still cannot rewind it.
        syscall.skip_syscall = True

        self.n_sent += 1
        if self.one_outstanding:
            self.pending.add(int(fd))
        now = time.time()
        if self.t_first is None:
            self.t_first = now
        self.t_last = now

    def _tally(self, data):
        if not data.startswith(b"HTTP/"):
            return
        parts = data.split(b" ")
        code = (parts[1][:3].decode("latin-1", "replace")
                if len(parts) > 1 else "???")
        self.responses[code] = self.responses.get(code, 0) + 1

    def _answered(self, fd):
        """The victim wrote on this fd, so its request is answered.

        Called from both response paths. Clearing here rather than in the read
        hook is what makes the alternation follow the VICTIM's progress rather
        than this plugin's own bookkeeping.
        """
        if self.one_outstanding:
            self.pending.discard(int(fd))

    def on_writev_enter(self, regs, proto, syscall, fd, iov, iovcnt):
        """Swallow the response, and tally what it was.

        Two jobs, and the second is what makes exclusive mode survivable.

        With the other userspace tasks stopped, the peer on the far end of
        this socket is frozen and will never read again. Let the write through
        and the send buffer fills, the victim blocks in writev() forever, and
        the loop stalls -- exclusive mode would have deadlocked the thing it
        was meant to make deterministic. Skipping the syscall means the
        response never has to go anywhere and a frozen peer cannot matter.

        `iov` is an ARRAY OF IOVECS, not the payload: read the first entry's
        base through read_ptr and then read from THERE. Reading `iov`
        directly returns the struct's own bytes, which never start with
        "HTTP/" -- so the tally is silently always empty and the control that
        catches a wedged victim reads as "no responses" on a perfectly
        healthy one.
        """
        if int(iovcnt) <= 0 or int(fd) not in self.fds:
            return
        self._answered(fd)
        try:
            base = yield from plugins.mem.read_ptr(iov)
            data = yield from plugins.mem.read_bytes(base, size=16)
        except Exception:                                   # noqa: BLE001
            data = b""
        self._tally(data)
        self.n_writes += 1
        if self.swallow_writes:
            # Claim the whole write succeeded. A short count would send the
            # victim back for the remainder and cost a lap to a retry loop.
            total = yield from self._iov_total(iov, int(iovcnt))
            syscall.retval = total
            syscall.skip_syscall = True
            self.n_swallowed += 1

    def on_recv_enter(self, regs, proto, syscall, fd, buf, length, *rest):
        """recv(fd, buf, len, flags) -- the same feed as read().

        Separate entry point only because the argument list differs; the
        decision, the payload and the skip are identical. MSG_PEEK is the one
        flag that would matter (a peek must not consume) but this never
        consumes anything in the first place: it writes the buffer and skips
        the syscall, so a peek and a read see the same bytes, which is what a
        peek is entitled to expect.
        """
        return (yield from self.on_read_enter(regs, proto, syscall, fd, buf,
                                              length))

    def on_write_enter(self, regs, proto, syscall, fd, buf, count):
        """The same job as on_writev_enter, for a victim that uses write()."""
        n = int(count)
        if n <= 0 or int(fd) not in self.fds:
            return
        self._answered(fd)
        try:
            data = yield from plugins.mem.read_bytes(int(buf), size=16)
        except Exception:                                   # noqa: BLE001
            data = b""
        self._tally(data)
        self.n_writes += 1
        if self.swallow_writes:
            syscall.retval = n
            syscall.skip_syscall = True
            self.n_swallowed += 1

    # epoll_ctl ops, from include/uapi/linux/eventpoll.h.
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD = 1, 2, 3
    EPOLLIN = 0x001

    def on_epoll_ctl_enter(self, regs, proto, syscall, epfd, op, fd, event,
                           *rest):
        """Learn (or forget) the data payload a victim registers for an fd.

        Not an intervention -- the syscall runs untouched. This exists only so
        on_epoll_wait_enter can hand back the exact payload epoll_ctl was
        given, because lighttpd stores a pointer to its connection object
        there and dereferences whatever comes out.
        """
        fd = int(fd)
        op = int(op)
        if op == self.EPOLL_CTL_DEL:
            self.epoll_reg.pop(fd, None)
            return
        if op not in (self.EPOLL_CTL_ADD, self.EPOLL_CTL_MOD) or not event:
            return
        try:
            raw = yield from plugins.mem.read_bytes(int(event),
                                                    size=self.epoll_ev_size)
        except Exception:                                   # noqa: BLE001
            return
        if raw and len(raw) >= self.epoll_data_off + 8:
            # The MASK matters as much as the payload, and dropping it was a
            # real bug with a loud signature: 267,914 requests fed and 104
            # responses written. A server alternates interest -- EPOLLIN while
            # it wants a request, EPOLLOUT while it flushes the reply -- and
            # re-arms through EPOLL_CTL_MOD each time (134,044 of them in that
            # run). Answering EPOLLIN unconditionally told lighttpd "there is
            # more to read" every time it tried to switch to writing, so it
            # went back to read() forever and never produced the writev the
            # loop detects. Feeding a victim faster is not the goal; letting
            # it finish an iteration is.
            want = int.from_bytes(raw[0:4], "little" if self._little else "big")
            self.epoll_reg[fd] = (
                want,
                bytes(raw[self.epoll_data_off:self.epoll_data_off + 8]))

    def on_epoll_wait_enter(self, regs, proto, syscall, epfd, events,
                            maxevents, *rest):
        """Answer epoll_wait for the fds this plugin is feeding.

        The same claim the read hook already makes, moved one syscall earlier:
        every read on a learned fd is answered from guest RAM, so those fds are
        readable by construction and saying so is not a lie.

        Left alone when nothing is known about the fds being waited on -- the
        victim may be waiting on a timer, a pipe or a listening socket this
        plugin knows nothing about, and claiming readiness there would corrupt
        its logic rather than accelerate it. That is the same rule
        on_select_enter follows, and it is why n_epoll_pass is counted
        separately: a run where it dominates is a run where this is doing
        nothing, which should be visible rather than inferred.
        """
        if not events or not self.fds or not self.epoll_reg:
            self.n_epoll_pass += 1
            self._epass["no_state"] = self._epass.get("no_state", 0) + 1
            return
        cap = min(int(maxevents), len(self.fds)) if maxevents else 0
        if cap <= 0:
            self.n_epoll_pass += 1
            self._epass["no_cap"] = self._epass.get("no_cap", 0) + 1
            return
        # Only fds that are BOTH being fed and registered with this epoll.
        # Only fds whose CURRENT registered interest includes EPOLLIN. One
        # that has switched to EPOLLOUT is waiting to write, and its
        # writability is real -- the host can answer that correctly and this
        # plugin has nothing to add.
        ready = [fd for fd in self.fds
                 if fd in self.epoll_reg
                 and (self.epoll_reg[fd][0] & self.EPOLLIN)
                 and not (self.one_outstanding and fd in self.pending)][:cap]
        if not ready:
            self.n_epoll_pass += 1
            both = set(self.fds) & set(self.epoll_reg)
            if not both:
                # The fds being waited on are not the fds being fed. On a
                # connection-per-request victim this is the LISTENING socket:
                # it waits for the next connection, which this plugin cannot
                # supply -- it feeds ACCEPTED fds and cannot synthesise an
                # accept().
                self._epass["disjoint"] = self._epass.get("disjoint", 0) + 1
            elif all(fd in self.pending for fd in both):
                self._epass["outstanding"] = self._epass.get("outstanding", 0) + 1
            else:
                self._epass["no_epollin"] = self._epass.get("no_epollin", 0) + 1
            return
        buf = bytearray()
        for fd in ready:
            ev = bytearray(self.epoll_ev_size)
            ev[0:4] = int(self.EPOLLIN).to_bytes(
                4, "little" if self._little else "big")
            ev[self.epoll_data_off:self.epoll_data_off + 8] = \
                self.epoll_reg[fd][1]
            buf += ev
        try:
            yield from plugins.mem.write_bytes(int(events), bytes(buf))
        except Exception:                                   # noqa: BLE001
            self.n_epoll_pass += 1
            self._epass["write_failed"] = self._epass.get("write_failed", 0) + 1
            return
        syscall.skip_syscall = True
        syscall.retval = len(ready)
        self.n_epoll += 1

    def on_select_enter(self, regs, proto, syscall, nfds, rfds, wfds, efds,
                        *rest):
        """Answer select() for the fds this plugin is feeding.

        A victim that blocks here never reaches the read() being fed, and the
        lap becomes the select timeout rather than the guest's work. Since
        every read on a learned fd is answered from guest RAM, those fds are
        ALWAYS readable by construction -- so saying so is not a lie, it is
        the same claim the read hook already makes, moved one syscall earlier.

        Only the read set is answered, and only if a learned fd is in it. A
        select that is waiting on something else entirely is left alone: the
        victim may be waiting on a timer or a pipe this plugin knows nothing
        about, and claiming readiness there would corrupt its logic rather
        than accelerate it.
        """
        if not rfds or not self.fds:
            self.n_select_pass += 1
            return
        n = min(max(int(nfds), 0), self.fdset_bytes * 8)
        if n <= 0:
            self.n_select_pass += 1
            return
        try:
            cur = yield from plugins.mem.read_bytes(int(rfds),
                                                    size=self.fdset_bytes)
        except Exception:                                   # noqa: BLE001
            self.n_select_pass += 1
            return
        ready = [fd for fd in self.fds
                 if fd < n and (cur[fd >> 3] >> (fd & 7)) & 1]
        if not ready:
            self.n_select_pass += 1
            return                      # waiting on something else; leave it
        out = bytearray(self.fdset_bytes)
        for fd in ready:
            out[fd >> 3] |= 1 << (fd & 7)
        yield from plugins.mem.write_bytes(int(rfds), bytes(out))
        # The write and exception sets must be CLEARED, not left as the guest
        # passed them in: select's contract is that every set comes back
        # holding only ready descriptors, and a victim that trusts a stale
        # write set will write to an fd this plugin never said was writable.
        for other in (wfds, efds):
            if other:
                try:
                    yield from plugins.mem.write_bytes(
                        int(other), bytes(self.fdset_bytes))
                except Exception:                           # noqa: BLE001
                    pass
        syscall.retval = len(ready)
        syscall.skip_syscall = True
        self.n_select += 1

    def _iov_total(self, iov, iovcnt):
        """Sum iov_len across the array, so the faked return is the length the
        guest actually asked to write rather than a guess."""
        total = 0
        ptr = int(self.ptr_size)
        for i in range(min(iovcnt, 64)):
            try:
                ln = yield from plugins.mem.read_ptr(int(iov) + i * 2 * ptr + ptr)
            except Exception:                               # noqa: BLE001
                break
            total += int(ln)
        return total

    # ---- report -----------------------------------------------------------

    def uninit(self) -> None:
        dur = ((self.t_last - self.t_first)
               if (self.t_first and self.t_last) else None)
        out = {
            "comm": self.comm,
            "n_sent": self.n_sent,
            "n_pass": self.n_pass,
            "n_unmatched": self.n_unmatched,
            "n_accept": self.n_accept,
            "fds_learned": sorted(self.fds),
            "responses": self.responses,
            "n_writes": self.n_writes,
            # What the victim ACTUALLY calls. `select` reading 0 here while
            # the lap sits 96% idle is the evidence that sent the search
            # elsewhere, and it cost nothing to have.
            "census": dict(sorted(self.census.items(), key=lambda kv: -kv[1])),
            # Pairs with identical counts are almost certainly the SAME
            # syscall reached under two names -- accept/accept4 came back
            # 542/542 and 544/544 on two runs, which is not coincidence. Left
            # in rather than merged, because which name the guest actually
            # uses is itself information, but flagged so nobody adds them up.
            # WITHIN 1%, not exactly equal. accept/accept4 came back 542/542,
            # 544/544, 1331/1331 and 1397/1397 -- and then 734/738, which an
            # equality test misses entirely while it is just as certainly the
            # same call under two names, a few increments apart because the
            # run ended between them.
            "census_aliases": [
                [a, b] for i, (a, na) in enumerate(sorted(self.census.items()))
                for b, nb in sorted(self.census.items())[i + 1:]
                if na > 0 and nb > 0 and abs(na - nb) <= 0.01 * max(na, nb)],
            # A name being PRESENT is not a mechanism; its magnitude is.
            # recvfrom appeared 6 times in a five-minute run and was read as
            # "this is how it reads sockets", when 675 of 681 feeds had come
            # through read(). The dominant call is the one that matters.
            "census_top": (max(self.census.items(), key=lambda kv: kv[1])[0]
                           if self.census else None),
            "n_eof": self.n_eof,
            "n_lap_resets": self.n_lap_resets,
            "lap_subscribed": getattr(self, "lap_subscribed", False),
            "feeds_per_conn": self.feeds_per_conn,
            "n_select": self.n_select,
            "n_select_pass": self.n_select_pass,
            "answer_select": self.answer_select,
            "answer_epoll": self.answer_epoll,
            "n_epoll": self.n_epoll,
            "n_epoll_pass": self.n_epoll_pass,
            "epoll_pass_why": dict(self._epass),
            "one_outstanding": self.one_outstanding,
            "keepalive": self.keepalive,
            "n_keepalive_fixed": self.n_keepalive_fixed,
            "complete_request": self.complete_request,
            "n_completed": self.n_completed,
            "n_withheld": self.n_withheld,
            "epoll_registered": len(self.epoll_reg),
            "census_on": self.census_on,
            "n_swallowed": self.n_swallowed,
            "swallow_writes": self.swallow_writes,
            "passthrough": self.passthrough,
            "mutate": self.mutate_on,
            "corpus_on": self.corpus_on,
            "corpus_size": len(self.corpus),
            "corpus_max": self.corpus_max,
            "corpus_p": self.corpus_p,
            "corpus_boundary_mult": self.corpus_boundary_mult,
            "n_corpus_add": self.n_corpus_add,
            "n_corpus_dup": self.n_corpus_dup,
            "n_corpus_evict": self.n_corpus_evict,
            "n_corpus_reject_boundary": self.n_corpus_reject_boundary,
            "n_corpus_draw": self.n_corpus_draw,
            "n_seed_draw": self.n_seed_draw,
            # The figure that says whether the corpus is doing anything.
            # Corpus SIZE does not: it can grow steadily while every
            # discovery still comes from a seed.
            "n_new_from_corpus": self.n_new_from_corpus,
            "n_new_from_seed": self.n_new_from_seed,
            "edges_from_corpus": self.edges_from_corpus,
            "edges_from_seed": self.edges_from_seed,
            "n_multi_fed_laps": self.n_multi_fed_laps,
            # THE PRIMARY RESULT, and it is an IN-RUN one.
            #
            # Cross-run coverage comparisons on this target are confounded by
            # the draw -- two runs of the same config replay different spans,
            # and that difference has swamped real effects before. This ratio
            # does not have that problem: both numerator and denominator are
            # measured in the same run, on the same snapshot, from the same
            # draw. It is new edges per corpus-derived input divided by new
            # edges per seed-derived input. Above 1, the corpus is finding
            # things the seeds were not.
            "corpus_lift": (
                round((self.edges_from_corpus / self.n_corpus_draw) /
                      (self.edges_from_seed / self.n_seed_draw), 3)
                if (self.n_corpus_draw and self.n_seed_draw
                    and self.edges_from_seed) else None),
            "cov_absent_laps": self._cov_absent_laps,
            "feed_wall_s": round(dur, 4) if dur else None,
            "sent_per_s": (round(self.n_sent / dur, 2)
                           if dur and dur > 0 else None),
        }
        # The corpus has its own way of reading as healthy while inert, and
        # it is the reverse of the usual one: an empty corpus looks like a
        # clean negative result ("guidance did not help here") when it is
        # usually a wiring fault. Both are named.
        if self.corpus_on and self._cov_absent_laps > 50 and not self.corpus:
            out["corpus_verdict"] = (
                f"CORPUS NEVER OFFERED ANYTHING: {self._cov_absent_laps} laps "
                f"arrived with no coverage attached, so nothing could ever be "
                f"banked. This is fastloop `coverage: 0`, not a corpus that "
                f"found nothing. Any claim about guidance from this run is "
                f"unsupported.")
        elif self.corpus_on and not self.corpus and self.n_lap_resets > 500:
            out["corpus_verdict"] = (
                f"CORPUS STAYED EMPTY over {self.n_lap_resets} laps with "
                f"coverage attached. Either no input reached anywhere new, or "
                f"the boundary guard rejected everything "
                f"({self.n_corpus_reject_boundary} rejected).")
        elif self.corpus_on and self.corpus and not self.n_corpus_draw:
            out["corpus_verdict"] = (
                f"CORPUS HELD {len(self.corpus)} ENTRIES AND WAS NEVER DRAWN "
                f"FROM. corpus_p={self.corpus_p} -- at 0 the corpus is "
                f"collected and ignored, which measures nothing.")

        # The one thing this file must never do quietly.
        if not self.n_sent:
            out["verdict"] = (
                f"FED NOTHING: {self.n_unmatched} reads by {self.comm!r} on "
                f"unlearned fds, {self.n_accept} accepts. Any loop rate "
                f"measured alongside this is the rate of an unfed guest.")
        elif (self.n_accept and self.n_sent > 1000 * max(1, self.n_accept)
              and not self.feeds_per_conn):
            out["verdict"] = (
                f"RUNAWAY: {self.n_sent} inputs fed across only "
                f"{self.n_accept} connections. Nothing ever returned EOF, so "
                f"the victim never closed a connection and never accepted "
                f"another -- a loop whose detector is `accept` cannot arm. "
                f"Set feeds_per_conn.")
        elif not self.responses:
            out["verdict"] = (
                f"FED {self.n_sent} inputs but the victim wrote NO parseable "
                f"response. It may be wedged; a clean crash count here means "
                f"nothing.")
        else:
            out["verdict"] = (
                f"fed {self.n_sent} inputs to {self.comm!r} from inside the "
                f"snapshot boundary ({self.n_pass} passed through to the host)"
                f", responses {self.responses}")
        self.logger.info(f"snapfeed: {out['verdict']}")
        if self.outdir:
            with open(os.path.join(self.outdir, "snapfeed.json"), "w") as fh:
                json.dump(out, fh, indent=2)
