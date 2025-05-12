from cffi import FFI
from penguin.defaults import DEFAULT_KERNEL
from glob import glob

ffi = FFI()
ffi.cdef("typedef uint64_t __le64;")
ffi.cdef("#define PAGE_SIZE 0x1000")


def cdef_file(filename):
    with open(filename) as f:
        return ffi.cdef(f.read())


for f in glob(f"/igloo_static/kernels/{DEFAULT_KERNEL}/includes/*.h"):
    cdef_file(f)

c = ffi.dlopen('c')

for i in dir(c):
    globals()[i] = getattr(c, i)
