from wrappers.generic import Wrapper, ArrayWrapper

VM_READ = 0x00000001
VM_WRITE = 0x00000002
VM_EXEC = 0x00000004
VM_MAYSHARE = 0x00000080

class MappingWrapper(Wrapper):
    @property
    def exec(self):
        """Check if the mapping is executable."""
        return self.flags & VM_EXEC != 0

    @property
    def read(self):
        """Check if the mapping is readable."""
        return self.flags & VM_READ != 0

    @property
    def write(self):
        """Check if the mapping is writable."""
        return self.flags & VM_WRITE != 0

    @property
    def share(self):
        """Check if the mapping is shareable."""
        return self.flags & VM_MAYSHARE != 0

    @property
    def perms(self):
        """Return the permissions of the mapping."""
        r = 'r' if self.read else '-'
        w = 'w' if self.write else '-'
        x = 'x' if self.exec else '-'
        s = 's' if self.share else 'p'
        return f"{r}{w}{x}{s}"

    @property
    def start(self):
        """Return the start address of the mapping."""
        return self.base

    @property
    def end(self):
        """Return the end address of the mapping."""
        return self.base + self.size

    @property
    def dev_major(self):
        """Return the major number of the mapping.
        In Linux, the major number is in the high 12 bits of dev."""
        return (self.dev >> 20) & 0xFFF

    @property
    def dev_minor(self):
        """Return the minor number of the mapping.
        In Linux, the minor number is in the low 20 bits of dev."""
        return self.dev & 0xFFFFF

    def get_addr_offset(self, addr):
        """Return the offset of the address within the mapping."""
        if self.start <= addr < self.end:
            return addr - self.start

    def __str__(self):
        """Return a string representation of the wrapped object."""
        a = self
        return f"{a.start:x}-{a.end:x} {a.perms} {a.pgoff:x} {a.dev_major:02x}:{a.dev_minor:02x} {a.inode} {a.name}"


class MappingsWrapper(ArrayWrapper):
    def get_mapping_by_addr(self, addr):
        """Find the mapping for a given address."""
        for mapping in self._data:
            if mapping.start <= addr < mapping.end:
                return mapping

    def get_mappings_by_name(self, name):
        """Find the mapping for a given address."""
        mappings = []
        for mapping in self._data:
            if name in mapping.name:
                mappings.append(mapping)
        return mappings

    def __str__(self):
        """Return a string representation of all mappings."""
        return "\n".join(str(mapping) for mapping in self._data)
