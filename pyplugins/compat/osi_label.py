"""
Rung labels for OS-introspection answers
========================================

Every OSI answer can say how it was obtained and how far it can be trusted,
so a result can cite it.  The rung is the capability ladder's:

- ``L0``: QEMU read the kernel's structures from outside (apis/hostosi.py);
  no guest code ran.
- ``L1``: the task made system calls for us (Syscalls.inject).
- ``L2``: igloo.ko answered from inside the guest kernel (apis/osi.py).

The consistency is one of:

- ``safe-point``: read where nothing it depends on can be changing: the task
  stopped at its system call boundary (L0, the current task), or the kernel's
  own code walking it as /proc does (L2).
- ``possibly-torn``: read from outside while the subject may be mid-update:
  another task, which may have been preempted inside the kernel, the process
  list, or (with more than one vCPU) state the task shares with threads that
  keep running.
- ``unavailable``: no answer (None).

And ``offsets``, where an L0 answer's kernel offsets came from: ``isf`` (the
ISF, trusted as its provenance says), or the other sources it also rests on,
``+``-joined: ``invariant`` (a field trusted as a layout prior from builds)
and ``l1-graded`` (a field trusted only by an L1 grade), compat/isf_trust.py.

A plugin's last answer's label, on the same thread::

    args = yield from plugins.HostOSI.get_args()
    label = plugins.HostOSI.last_label        # Label(rung, consistency, why)

or both at once::

    args, label = yield from labeled(plugins.HostOSI, plugins.HostOSI.get_args())
"""
import functools
import threading
from typing import Any, Callable, Generator, NamedTuple, Tuple

SAFE, TORN, UNAVAILABLE = "safe-point", "possibly-torn", "unavailable"


class Label(NamedTuple):
    rung: str
    consistency: str
    why: str
    offsets: str = "isf"


def answer(judge: Callable[[Any, Any], Label]):
    """an OSI call's decorator: its answer's label from @judge(self, value),
    kept as the instance's last_label for this thread"""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            tl = _local(self)
            tl.via = None
            value = yield from fn(self, *args, **kwargs)
            # a nested call's other rung (get_cwd's get_fd_name) is ours too
            tl.label = tl.via or judge(self, value)
            return value
        return wrapper
    return deco


def _local(obj) -> threading.local:
    tl = obj.__dict__.get("_osi_labels")
    if tl is None:
        tl = obj.__dict__.setdefault("_osi_labels", threading.local())
    return tl


def answered_by(obj, label: Label) -> None:
    """the call @obj is running took its answer from another rung: @label"""
    _local(obj).via = label


def last_label(obj) -> Label:
    """@obj's last answer's label on this thread"""
    return getattr(_local(obj), "label", None) or Label("", UNAVAILABLE, "nothing asked yet")


def labeled(obj, gen: Generator) -> Generator[Any, Any, Tuple[Any, Label]]:
    """run one of @obj's OSI calls: (its answer, its label)"""
    value = yield from gen
    return value, last_label(obj)
