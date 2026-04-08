#!/usr/bin/env python3
from penguin import Plugin, plugins

mem = plugins.mem
static_fs = plugins.static_fs


class StaticFsTest(Plugin):
    '''
    This test verifies that the static_fs plugin can properly resolve
    symlinks, correctly encode/decode inline string contents, and handle
    various edge cases like symlink loops and broken links.
    '''
    def test_static_fs_api(self):
        expected_content = b"static_fs test string"

        # 1. Test basic existence
        assert static_fs.exists("/igloo/test_target_file.txt"), "Target static file should exist"
        assert static_fs.exists("/igloo/test_symlink.txt"), "Symlink should exist"

        # 2. Test multi-hop symlink
        assert static_fs.exists("/igloo/multi_link_1.txt"), "Multi-hop symlink should exist"
        size = static_fs.get_size("/igloo/multi_link_1.txt")
        assert size == len(expected_content), f"Expected size {len(expected_content)}, got {size}"

        content = static_fs.read("/igloo/multi_link_1.txt", size=100)
        assert content == expected_content, f"Expected {expected_content}, got {content}"

        # 3. Test broken symlink
        assert not static_fs.exists("/igloo/broken_link.txt"), "Broken symlink should NOT exist"
        assert static_fs.get_size("/igloo/broken_link.txt") is None, "Broken symlink should have no size"
        assert static_fs.read("/igloo/broken_link.txt", size=100) is None, "Broken symlink read should return None"

        # 4. Test symlink loop (should safely abort after max_depth)
        assert not static_fs.exists("/igloo/loop_1.txt"), "Symlink loop should return False for exists()"
        assert static_fs.get_size("/igloo/loop_1.txt") is None, "Symlink loop should return None for size"

        # 5. Test open and reading via BytesIO
        f = static_fs.open("/igloo/test_symlink.txt")
        assert f is not None, "Failed to open valid symlink"
        content_from_open = f.read()
        assert content_from_open == expected_content, f"Expected {expected_content}, got {content_from_open}"

        # 6. Test directory listing
        dir_list = static_fs.list("/igloo/fake_dir")
        assert dir_list is not None, "Directory listing failed"
        assert "file1.txt" in dir_list and "file2.txt" in dir_list, f"Expected file1.txt and file2.txt in listing, got {dir_list}"

        # 7. Test directory mode listing
        modes = static_fs.list_mode("/igloo/fake_dir")
        assert modes is not None, "Directory modes listing failed"
        assert modes.get("file1.txt") == 0o755, f"Expected mode 0o755, got {oct(modes.get('file1.txt', 0))}"
        assert modes.get("file2.txt") == 0o644, f"Expected mode 0o644, got {oct(modes.get('file2.txt', 0))}"

        self.logger.info("static_fs python API comprehensive tests passed!")

    @plugins.syscalls.syscall("on_sys_ioctl_return", arg_filters=[None, 0x89f5])
    def ioctl_val(self, regs, proto, syscall, fd, op, arg):
        # check our arguments
        assert fd == 0, f"Expected fd 0, got {fd:#x}"
        assert op == 0x89f5, f"Expected op 0x89f5, got {op:#x}"

        val = yield from mem.read_str(arg)
        assert val == "stringval", f"Expected 'stringval', got {val}"
        # Run the static_fs api checks on the host side
        self.test_static_fs_api()

        # Return unique value checked by the shell script
        syscall.retval = 14
