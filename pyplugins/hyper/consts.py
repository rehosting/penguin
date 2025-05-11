from cffi import FFI
from penguin.defaults import DEFAULT_KERNEL

ffi =FFI()
ffi.cdef("typedef uint64_t __le64;")
ffi.cdef("#define PAGE_SIZE 0x1000")

def cdef_file(filename):
    with open(filename) as f:
        return ffi.cdef(f.read())

cdef_file(f"/igloo_static/kernels/{DEFAULT_KERNEL}/portal_types.h")
cdef_file(f"/igloo_static/kernels/{DEFAULT_KERNEL}/igloo_hypercall_consts.h")

c = ffi.dlopen('c')

for i in dir(c):
    globals()[i] = getattr(c, i)
